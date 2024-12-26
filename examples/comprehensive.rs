/// Complete example showing all major YARA Forge features
///
/// This example covers:
/// - Using built-in templates and pattern libraries
/// - Rule validation and error handling
/// - File operations (save/export)
/// - Complex pattern matching with multiple indicators
use yara_forge::{
    patterns::{ENCRYPTION_APIS, PROCESS_INJECTION, RANSOMWARE_EXTENSIONS},
    templates::ransomware_template,
    utils::{export_rule_to_json, generate_unique_rule_name, save_rule_to_file},
    validation::validate_rule,
    ValidationOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start with a template and customize it
    let rule_name = generate_unique_rule_name("ransomware_detector");
    let mut rule = ransomware_template(&rule_name);

    // Add our detection info
    rule = rule
        .with_metadata(
            "description",
            "Advanced ransomware detection rule with multiple indicators",
        )
        .with_metadata("author", "YARA Forge")
        .with_metadata("severity", "high");

    // Add known encryption API patterns
    for (i, pattern) in ENCRYPTION_APIS.iter().enumerate() {
        rule = rule.with_string(&format!("$encrypt_api_{}", i), pattern)?;
    }

    // Add ransomware extension patterns
    for (i, ext) in RANSOMWARE_EXTENSIONS.iter().enumerate() {
        rule = rule.with_string(&format!("$ransom_ext_{}", i), ext)?;
    }

    // Add process injection indicators
    for (i, pattern) in PROCESS_INJECTION.iter().enumerate() {
        rule = rule.with_string(&format!("$injection_{}", i), pattern)?;
    }

    // Add a pattern to detect high entropy (common in encrypted files)
    rule = rule.with_string(
        "$high_entropy",
        "{ ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }",
    )?;

    // Build complex condition logic
    let rule = rule
        .with_condition(
            r#"
        // Match encryption APIs
        (
            any of ($encrypt_api_*)
            or any of ($ransom_ext_*)
            or any of ($injection_*)
        )
        and
        // Size constraints to avoid false positives
        filesize > 1KB and filesize < 10MB and
        // Ensure high entropy in larger blocks
        math.entropy(0, filesize) > 7.8
    "#,
        )
        .build()?;

    // Make sure it's valid
    println!("Validating rule...");
    let options = ValidationOptions::default();
    validate_rule(&rule.to_string(), &options)?;

    // Save for later use
    println!("Saving rule...");
    save_rule_to_file(&rule, "ransomware_detector.yar")?;

    // Export as JSON for integration with other tools
    println!("Exporting as JSON...");
    let json = export_rule_to_json(&rule);
    println!("JSON output:\n{}", serde_json::to_string_pretty(&json)?);

    Ok(())
}
