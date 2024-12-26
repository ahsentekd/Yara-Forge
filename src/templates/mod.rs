//! Pre-defined templates for common YARA rule patterns
//! This module provides ready-to-use templates for various types of malware detection

use crate::RuleBuilder;
use chrono::Utc;

/// Template for creating a ransomware detection rule
pub fn ransomware_template(name: &str) -> RuleBuilder {
    RuleBuilder::new(name)
        .with_tag("malware")
        .with_tag("ransomware")
        .with_metadata("type", "ransomware")
        .with_metadata("created", &Utc::now().format("%Y-%m-%d").to_string())
}

/// Template for creating a cryptominer detection rule
pub fn cryptominer_template(name: &str) -> RuleBuilder {
    RuleBuilder::new(name)
        .with_tag("malware")
        .with_tag("cryptominer")
        .with_metadata("type", "cryptominer")
        .with_metadata("created", &Utc::now().format("%Y-%m-%d").to_string())
}

/// Template for creating a backdoor detection rule
pub fn backdoor_template(name: &str) -> RuleBuilder {
    RuleBuilder::new(name)
        .with_tag("malware")
        .with_tag("backdoor")
        .with_metadata("type", "backdoor")
        .with_metadata("created", &Utc::now().format("%Y-%m-%d").to_string())
}

/// Template for creating a generic malware detection rule
pub fn malware_template(name: &str, malware_type: &str) -> RuleBuilder {
    RuleBuilder::new(name)
        .with_tag("malware")
        .with_tag(malware_type)
        .with_metadata("type", malware_type)
        .with_metadata("created", &Utc::now().format("%Y-%m-%d").to_string())
}

/// Template for creating a filetype detection rule
pub fn filetype_template(name: &str, file_type: &str) -> RuleBuilder {
    RuleBuilder::new(name)
        .with_tag("filetype")
        .with_tag(file_type)
        .with_metadata("file_type", file_type)
        .with_metadata("created", &Utc::now().format("%Y-%m-%d").to_string())
}
