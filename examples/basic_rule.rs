/// Shows how to create a simple YARA rule with basic string matching
///
/// This example demonstrates:
/// - Creating a rule with a descriptive name
/// - Adding metadata and tags
/// - Using string patterns
/// - Building and validating the rule
use yara_forge::{validation::validate_rule, RuleBuilder, ValidationOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a simple rule to detect a specific string pattern
    let rule = RuleBuilder::new("detect_pattern")
        .with_tag("example")
        .with_metadata("author", "YARA Forge")
        .with_metadata("description", "Example rule for basic string matching")
        .with_string("$pattern", "suspicious_string")?
        .with_condition("$pattern")
        .build()?;

    // Validate the rule
    println!("Rule content:\n{}", rule);
    println!("\nValidating rule...");
    match validate_rule(&rule.to_string(), &ValidationOptions::default()) {
        Ok(_) => println!("Rule validation passed"),
        Err(e) => println!("Rule validation failed: {}", e),
    }

    Ok(())
}
