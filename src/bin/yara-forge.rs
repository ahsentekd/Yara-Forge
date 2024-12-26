use std::process::exit;
use yara_forge::{RuleBuilder, ValidationOptions};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [options]", args[0]);
        eprintln!("Commands:");
        eprintln!("  validate <rule_file>    - Validate a YARA rule file");
        eprintln!("  scan <rule> <target>    - Scan a file or directory with a YARA rule");
        exit(1);
    }

    match args[1].as_str() {
        "validate" => {
            if args.len() < 3 {
                eprintln!("Usage: {} validate <rule_file>", args[0]);
                exit(1);
            }
            let rule_file = &args[2];
            match std::fs::read_to_string(rule_file) {
                Ok(content) => {
                    let options = ValidationOptions::default();
                    match yara_forge::validation::validate_rule(&content, &options) {
                        Ok(_) => println!("Rule validation successful!"),
                        Err(e) => {
                            eprintln!("Rule validation failed: {}", e);
                            exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read rule file: {}", e);
                    exit(1);
                }
            }
        }
        "scan" => {
            if args.len() < 4 {
                eprintln!("Usage: {} scan <rule_file> <target>", args[0]);
                exit(1);
            }
            let rule_file = &args[2];
            let target = &args[3];
            let options = ValidationOptions::default();

            match yara_forge::validation::scan_with_rule(rule_file, target, &options) {
                Ok(matches) => {
                    if matches.is_empty() {
                        println!("No matches found");
                    } else {
                        println!("Matches found:");
                        for m in matches {
                            println!("  {}", m);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Scan failed: {}", e);
                    exit(1);
                }
            }
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            exit(1);
        }
    }
}
