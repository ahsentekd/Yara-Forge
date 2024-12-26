/// Example of validating and testing YARA rules
/// 
/// Shows how to:
/// - Create and validate rules
/// - Scan files with rules
/// - Use parallel scanning for better performance
/// - Handle validation errors properly
use std::path::PathBuf;
use yara_forge::{
    RuleBuilder, ValidationOptions,
    patterns::{FILE_HEADERS, PROCESS_INJECTION},
    validation::{validate_rule, scan_with_rule, parallel_scan},
    utils::save_rule_to_file,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build a rule to detect potential malware
    let rule = RuleBuilder::new("detect_malware")
        .with_tag("malware")
        .with_metadata("author", "YARA Forge")
        .with_metadata("description", "Detects potential malware characteristics")
        
        // Check if it's a Windows executable
        .with_string("$mz_header", FILE_HEADERS.get("exe").unwrap())?
        
        // Look for process injection behavior
        .with_string("$virtual_alloc", "VirtualAllocEx")?      // Memory allocation
        .with_string("$write_mem", "WriteProcessMemory")?      // Memory writing
        .with_string("$create_thread", "CreateRemoteThread")?  // Thread creation
        
        // Combine indicators with size constraints
        .with_condition(r#"
            // Must be a PE file
            $mz_header at 0 and
            // Look for process injection patterns
            2 of ($virtual_alloc, $write_mem, $create_thread) and
            // Size constraints to avoid false positives
            filesize > 1KB and filesize < 10MB
        "#)
        .build()?;

    // Save for later use
    let rule_path = PathBuf::from("detect_malware.yar");
    save_rule_to_file(&rule, &rule_path)?;
    println!("Rule saved to: {}", rule_path.display());

    // Make sure it's valid
    println!("\nValidating rule syntax...");
    let options = ValidationOptions {
        syntax_only: false,
        test_against_samples: true,
        max_file_size: 10 * 1024 * 1024, // 10MB
        timeout: 60,
    };
    match validate_rule(&rule.to_string(), &options) {
        Ok(_) => println!("Rule validation passed"),
        Err(e) => println!("Rule validation failed: {}", e),
    }

    // Test against a single file
    println!("\nScanning a single file...");
    let test_file = PathBuf::from("samples/test.exe");
    if let Ok(matches) = scan_with_rule(&rule_path, &test_file, &options) {
        if matches.is_empty() {
            println!("No matches found");
        } else {
            println!("Matches found:");
            for m in matches {
                println!("  - {}", m);
            }
        }
    }

    // Scan a directory in parallel
    println!("\nScanning directory in parallel...");
    let test_dir = PathBuf::from("samples/");
    match parallel_scan(&rule_path, &test_dir, &options) {
        Ok(matches) => {
            println!("Found {} matches:", matches.len());
            for m in matches {
                println!("  - {}", m);
            }
        }
        Err(e) => println!("Scanning error: {}", e),
    }

    Ok(())
}