/// Advanced example showing ransomware detection techniques
///
/// Demonstrates more complex YARA rule features:
/// - Multiple string patterns and wildcards
/// - Structured conditions with logical operators
/// - Rich metadata for better rule management
/// - Multiple tags for classification
use yara_forge::RuleBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build a ransomware detection rule with multiple indicators
    let rule = RuleBuilder::new("detect_ransomware")
        // Help classify and organize rules
        .with_tag("malware")
        .with_tag("ransomware")
        .with_tag("threat_hunting")
        // Track rule info and severity
        .with_metadata("author", "YARA Forge")
        .with_metadata("date", "2024-12-26")
        .with_metadata("description", "Detects potential ransomware behavior patterns")
        .with_metadata("severity", "high")
        // Look for typical ransomware behavior patterns
        .with_string("$encrypt_api1", "CryptoAPI")?           // Common encryption APIs
        .with_string("$encrypt_api2", "CryptEncrypt")?
        .with_string("$ransom_note", "Your files have been encrypted")?  // Ransom message
        .with_string("$file_ext", ".encrypted")?              // Modified file extension
        .with_string("$suspicious_bytes", 
            "68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04")?  // Suspicious code pattern with wildcards
        // Complex condition combining multiple indicators
        .with_condition(r#"
            // Need to see encryption API usage
            any of ($encrypt_api*) and
            // Plus either a ransom note or encrypted files
            (
                $ransom_note or
                $file_ext
            ) and
            // And some suspicious code
            $suspicious_bytes
        "#)
        .build()?;

    // Show the complete rule
    println!("Generated YARA Rule:\n{}", rule.to_string());

    Ok(())
}
