/// Shows how to create a simple YARA rule with basic string matching
/// 
/// This example demonstrates:
/// - Creating a rule with a descriptive name
/// - Adding metadata and tags
/// - Basic string pattern matching
/// - Simple condition logic
use yara_forge::RuleBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Quick example showing a basic malware detection rule
    let rule = RuleBuilder::new("detect_suspicious_pattern")
        .with_tag("malware")
        .with_metadata("author", "YARA Forge")
        .with_metadata("description", "Detects a suspicious pattern in files")
        .with_string("$suspicious_str", "malicious_content")?  // Look for this exact string
        .with_string("$hex_pattern", "90 90 90 90")?          // Match a sequence of NOPs
        .with_condition("$suspicious_str or $hex_pattern")     // Alert if we find either pattern
        .build()?;

    // Show what we built
    println!("Generated YARA Rule:\n{}", rule.to_string());

    Ok(())
}
