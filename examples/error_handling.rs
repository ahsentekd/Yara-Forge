/// Examples of handling common YARA rule errors
/// 
/// Shows how to:
/// - Handle invalid rule names and identifiers
/// - Deal with validation errors
/// - Manage file operation errors
/// - Use proper error handling patterns
use yara_forge::{
    RuleBuilder, ValidationOptions, YaraError,
    validation::{validate_rule, ValidationError},
    utils::{save_rule_to_file, load_rule_from_file},
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
        Ok(_) => println!("Rule created successfully (shouldn't happen)"),
        Err(YaraError::InvalidRuleName(name)) => {
            println!("Got expected error: Invalid rule name '{}'", name);
        }
        Err(e) => println!("Unexpected error type: {}", e),
    }

    // Try using invalid string identifier
    let result = RuleBuilder::new("test_rule")
        .with_string("invalid@id", "test")?
        .with_condition("true")
        .build();

    match result {
        Ok(_) => println!("Rule created successfully (shouldn't happen)"),
        Err(YaraError::InvalidIdentifier(id)) => {
            println!("Got expected error: Invalid identifier '{}'", id);
        }
        Err(e) => println!("Unexpected error type: {}", e),
    }

    Ok(())
}

/// Validate invalid rules
fn validate_invalid_rules() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nValidating invalid rules...");

    // Try validating a rule with syntax errors
    let invalid_rule = r#"
        rule invalid_syntax {
            strings:
                $a = "test
            condition:
                $a
        }
    "#;

    let options = ValidationOptions {
        syntax_only: true,
        ..Default::default()
    };

    match validate_rule(invalid_rule, &options) {
        Ok(_) => println!("Validation passed (shouldn't happen)"),
        Err(e) => println!("Got expected error: {}", e),
    }

    // Try validating a non-existent file
    match validate_rule("nonexistent.yar", &options) {
        Ok(_) => println!("Validation passed (shouldn't happen)"),
        Err(e) => println!("Error detected as expected: {}", e),
    }

    Ok(())
}

/// Test file operations
fn test_file_operations() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nTesting file operations...");

    // Create a valid rule for testing
    let rule = RuleBuilder::new("test_rule")
        .with_metadata("author", "YARA Forge")
        .with_string("$test", "test")?
        .with_condition("$test")
        .build()?;

    // Try saving to an invalid path
    match save_rule_to_file(&rule, "/invalid/path/rule.yar") {
        Ok(_) => println!("Save succeeded (shouldn't happen)"),
        Err(e) => println!("Got expected save error: {}", e),
    }

    // Try loading a non-existent file
    match load_rule_from_file("nonexistent.yar") {
        Ok(_) => println!("Load succeeded (shouldn't happen)"),
        Err(e) => println!("Got expected load error: {}", e),
    }

    Ok(())
}

/// Main function
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Run through different error scenarios
    create_invalid_rule()?;
    validate_invalid_rules()?;
    test_file_operations()?;

    Ok(())
}
