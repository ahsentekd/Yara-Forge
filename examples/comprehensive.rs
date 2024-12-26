/// Complete example showing all major YARA Forge features
/// 
/// This example covers:
/// - Using built-in templates and pattern libraries
/// - Rule validation and error handling
/// - File operations (save/export)
/// - Complex pattern matching with multiple indicators
use yara_forge::{
    ValidationOptions,
    templates::ransomware_template,
    patterns::{ENCRYPTION_APIS, RANSOMWARE_EXTENSIONS, PROCESS_INJECTION},
    validation::validate_rule,
    utils::{generate_unique_rule_name, export_rule_to_json, save_rule_to_file},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start with a template and customize it
    let rule_name = generate_unique_rule_name("ransomware_detector");
    let mut rule = ransomware_template(&rule_name);
    
    // Add our detection info
    rule = rule
        .with_metadata("description", "Advanced ransomware detection rule with multiple indicators")
        .with_metadata("author", "YARA Forge")
        .with_metadata("severity", "high");
    
    // Add known encryption API patterns
    for (i, pattern) in ENCRYPTION_APIS.iter().enumerate() {
        rule = rule.with_string(&format!("$encrypt_api_{}", i), pattern)?;
    }

    // Look for ransomware file extensions
    for (i, pattern) in RANSOMWARE_EXTENSIONS.iter().enumerate() {
        rule = rule.with_string(&format!("$ransom_ext_{}", i), pattern)?;
    }

    // Check for process injection attempts
    for (i, pattern) in PROCESS_INJECTION.iter().enumerate() {
        rule = rule.with_string(&format!("$injection_{}", i), pattern)?;
    }

    // Add a pattern to detect high entropy (common in encrypted files)
    rule = rule.with_string("$high_entropy", "{ ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }")?;

    // Build complex condition logic
    let rule = rule.with_condition(r#"
        // Match encryption APIs
        (
            any of ($encrypt_api_*)
        ) and
        // Match ransomware extensions or high entropy
        (
            any of ($ransom_ext_*) or
            $high_entropy
        ) and
        // Match process injection indicators
        (
            any of ($injection_*)
        ) and
        // File size constraints
        filesize > 1KB and filesize < 10MB and
        // Ensure high entropy in larger blocks
        math.entropy(0, filesize) > 7.8
    "#).build()?;

    // Make sure it's valid
    println!("Validating rule...");
    let options = ValidationOptions {
        syntax_only: true,
        test_against_samples: false,
        max_file_size: 10 * 1024 * 1024, // 10MB
        timeout: 30,
    };

    match validate_rule(&rule.to_string(), &options) {
        Ok(_) => println!("Rule validation passed"),
        Err(e) => println!("Rule validation failed: {}", e),
    }

    // Export as JSON for integration with other tools
    println!("\nExporting rule to JSON...");
    let json = export_rule_to_json(&rule);
    println!("{}", serde_json::to_string_pretty(&json)?);

    // Save for later use
    println!("\nSaving rule to file...");
    save_rule_to_file(&rule, &format!("{}.yar", rule_name))?;

    Ok(())
}
