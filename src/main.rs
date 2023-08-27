use std::{env, fs, io, net, process};

use anyhow::{anyhow, Result};
use chrono::{Days, Utc};
use cidr_utils::cidr::IpCidr;
use serde::Serialize;

#[derive(Serialize)]
struct Metadata {
    counts: usize,
    generated: i64,
    valid: i64,
}

#[derive(Serialize)]
struct ROA {
    prefix: String,
    #[serde(rename = "maxLength")]
    max_length: u8,
    asn: String,
}

#[derive(Serialize)]
struct Routes {
    metadata: Metadata,
    roas: Vec<ROA>,
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} registry route.json", args[0]);
        process::exit(1);
    }

    let mut filters = vec![];

    let filter = format!("{}/data/filter.txt", args[1]);
    process_filter(&filter, &mut filters)?;

    let filter = format!("{}/data/filter6.txt", args[1]);
    process_filter(&filter, &mut filters)?;

    let mut roas = vec![];

    let path = format!("{}/data/route", args[1]);
    process_directory(&path, &mut roas, &filters)?;

    let path = format!("{}/data/route6", args[1]);
    process_directory(&path, &mut roas, &filters)?;

    let now = Utc::now();
    let expire = now
        .checked_add_days(Days::new(7))
        .ok_or(anyhow!("invalid date"))?;

    let metadata = Metadata {
        counts: roas.len(),
        generated: now.timestamp(),
        valid: expire.timestamp(),
    };

    let routes = Routes {
        metadata,
        roas,
    };

    let output = serde_json::to_string(&routes)?;
    fs::write(&args[2], output)?;

    Ok(())
}

fn process_filter(
    path: &str,
    filters: &mut Vec<(IpCidr, bool, u8, u8)>
) -> Result<()> {
    let filter = fs::read_to_string(path)?;

    let lines: Vec<_> = filter.split("\n").collect();
    for line in lines {
        let first = match line.chars().nth(0) {
            Some(c) => c,
            None => continue,
        };

        if first < '0' || first > '9' {
            continue;
        }

        let line: Vec<_> = line.split_whitespace().collect();
        if line.len() < 6 {
            continue;
        }

        let allow = match line[1] {
            "deny" => false,
            "permit" => true,
            _ => continue,
        };

        let cidr = match IpCidr::from_str(line[2]) {
            Ok(cidr) => cidr,
            Err(_) => continue,
        };


        let min: u8 = match line[3].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let max: u8 = match line[4].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        filters.push((cidr.to_owned(), allow, min, max));
    }

    Ok(())
}

fn process_directory(
    path: &str,
    roas: &mut Vec<ROA>,
    filters: &Vec<(IpCidr, bool, u8, u8)>
) -> Result<()> {
    let files = fs::read_dir(path)?;

    for file in files {
        let roa = match process_entry(file, &filters) {
            Ok(roa) => roa,
            Err(e) => {
                eprintln!("Failed to process: {e}. ");
                continue;
            },
        };

        roas.extend(roa);
    }

    Ok(())
}

fn process_entry(
    file: Result<fs::DirEntry, io::Error>,
    filters: &Vec<(IpCidr, bool, u8, u8)>
) -> Result<Vec<ROA>> {
    let file = file?.path();
    let file = fs::read_to_string(file)?;

    let mut prefix: Option<String> = None;
    let mut asn = vec![];
    let mut max_length: Option<u8> = None;

    let lines: Vec<_> = file.split("\n").collect();
    for line in lines {
        match line.chars().nth(0) {
            Some(c) => {
                if c.is_whitespace() {
                    continue;
                }
            },
            None => continue,
        };

        let line = line.to_ascii_lowercase();
        let line: Vec<_> = line.split_whitespace().collect();

        if line.len() < 2 {
            continue;
        }

        if line[0] == "route:" || line[0] == "route6:" {
            prefix = Some(line[1].to_owned());
        } else if line[0] == "origin:" {
            asn.push(line[1].to_ascii_uppercase());
        } else if line[0] == "max-length:" {
            max_length = Some(line[1].parse()?);
        } else {
            continue;
        }
    }

    let prefix = prefix.ok_or(anyhow!("no route specified"))?;

    let prefix_parts: Vec<_> = prefix.split("/").collect();
    if prefix_parts.len() != 2 {
        return Err(anyhow!("invalid CIDR: {}", prefix));
    }

    let addr: net::IpAddr = prefix_parts[0].parse()?;
    let netmask: u8 = prefix_parts[1].parse()?;

    let mut filter: Option<(u8, u8)> = None;

    for f in filters {
        if f.0.contains(addr) {
            if !f.1 {
                return Ok(vec![]);
            }

            filter = Some((f.2, f.3));
            break;
        }
    }

    let filter = match filter {
        Some(f) => f,
        None => return Err(anyhow!("IP {addr} is in an invalid range")),
    };

    let max_length = match max_length {
        Some(max_length) => {
            if max_length > filter.1 {
                filter.1
            } else if max_length < filter.0 {
                filter.0
            } else {
                max_length
            }
        },
        None => filter.1,
    };

    if netmask > max_length {
        return Ok(vec![]);
    }

    let roas = asn
        .iter()
        .map(|asn| {
            ROA {
                prefix: prefix.clone(),
                max_length,
                asn: asn.to_owned(),
            }
        })
        .collect();

    Ok(roas)
}
