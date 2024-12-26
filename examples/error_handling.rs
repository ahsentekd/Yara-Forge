/// Examples of handling common YARA rule errors
///
/// Shows how to:
/// - Handle invalid rule names and identifiers
/// - Deal with validation errors
/// - Manage file operation errors
/// - Use proper error handling patterns
use yara_forge::{
    utils::{load_rule_from_file, save_rule_to_file},
    validation::{validate_rule, ValidationError},
    RuleBuilder, ValidationOptions, YaraError,
};

/// Attempt to create an invalid rule
fn create_invalid_rule() -> Result<(), Box<dyn std::error::Error>> {
    println!("Attempting to create an invalid rule...");

    // Try using invalid characters in rule name
    let result = RuleBuilder::new("invalid-name!@#")
        .with_metadata("author", "YARA Forge")
        .with_string("$test", "test")?
        .with_condition("$test")
        .build();

    match result {
        Ok(_) => println!("Rule was created successfully (unexpected)"),
        Err(e) => println!("Got expected error: {}", e),
    }

    Ok(())
}

/// Attempt to validate an invalid rule
fn validate_invalid_rule() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nAttempting to validate an invalid rule...");

    // Create a rule with invalid condition
    let rule = RuleBuilder::new("test_rule")
        .with_string("$test", "test")?
        .with_condition("invalid_condition")
        .build()?;

    let result = validate_rule(&rule.to_string(), &ValidationOptions::default());
    match result {
        Ok(_) => println!("Rule validation passed (unexpected)"),
        Err(e) => println!("Got expected error: {}", e),
    }

    Ok(())
}

/// Demonstrate file operation error handling
fn handle_file_operations() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nTesting file operations...");

    // Try to load a non-existent file
    match load_rule_from_file("nonexistent.yar") {
        Ok(_) => println!("File loaded successfully (unexpected)"),
        Err(e) => println!("Got expected error: {}", e),
    }

    // Create and save a valid rule
    let rule = RuleBuilder::new("test_rule")
        .with_string("$test", "test")?
        .with_condition("$test")
        .build()?;

    // Save to an invalid path
    match save_rule_to_file(&rule, "/invalid/path/test.yar") {
        Ok(_) => println!("File saved successfully (unexpected)"),
        Err(e) => println!("Got expected error: {}", e),
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    create_invalid_rule()?;
    validate_invalid_rule()?;
    handle_file_operations()?;
    Ok(())
}
