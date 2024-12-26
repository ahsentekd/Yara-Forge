//! YARA Rule Generator
//!
//! A comprehensive Rust library for generating YARA rules.
//! This library provides a simple and intuitive API to create,
//! validate, and manage YARA rules programmatically.

pub mod patterns;
pub mod templates;
pub mod utils;
pub mod validation;

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum YaraError {
    #[error("Invalid rule name: {0}")]
    InvalidRuleName(String),
    #[error("Invalid string identifier: {0}")]
    InvalidIdentifier(String),
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// A YARA rule string definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringDefinition {
    pub identifier: String,
    pub pattern: String,
    pub is_hex: bool,
    pub modifiers: Vec<String>,
}

/// A complete YARA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub strings: Vec<StringDefinition>,
    pub condition: String,
}

/// Builder for creating YARA rules
#[derive(Default)]
pub struct RuleBuilder {
    name: Option<String>,
    tags: Vec<String>,
    metadata: HashMap<String, String>,
    strings: Vec<StringDefinition>,
    condition: Option<String>,
}

impl RuleBuilder {
    /// Create a new RuleBuilder with a given name
    pub fn new(name: &str) -> Self {
        RuleBuilder {
            name: Some(name.to_string()),
            ..Default::default()
        }
    }

    /// Add a tag to the rule
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }

    /// Add metadata to the rule
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Add a string pattern to the rule
    pub fn with_string(mut self, identifier: &str, pattern: &str) -> Result<Self, YaraError> {
        if !is_valid_identifier(identifier) {
            return Err(YaraError::InvalidIdentifier(identifier.to_string()));
        }

        self.strings.push(StringDefinition {
            identifier: identifier.to_string(),
            pattern: pattern.to_string(),
            is_hex: false,
            modifiers: Vec::new(),
        });

        Ok(self)
    }

    /// Add a hex pattern to the rule
    pub fn with_hex(mut self, identifier: &str, hex: &str) -> Result<Self, YaraError> {
        if !is_valid_identifier(identifier) {
            return Err(YaraError::InvalidIdentifier(identifier.to_string()));
        }

        self.strings.push(StringDefinition {
            identifier: identifier.to_string(),
            pattern: hex.to_string(),
            is_hex: true,
            modifiers: Vec::new(),
        });

        Ok(self)
    }

    /// Set the condition for the rule
    pub fn with_condition(mut self, condition: &str) -> Self {
        self.condition = Some(condition.to_string());
        self
    }

    /// Build the YARA rule
    pub fn build(self) -> Result<Rule, YaraError> {
        let name = self
            .name
            .ok_or_else(|| YaraError::MissingField("rule name".to_string()))?;
        let condition = self
            .condition
            .ok_or_else(|| YaraError::MissingField("condition".to_string()))?;

        if !is_valid_identifier(&name) {
            return Err(YaraError::InvalidRuleName(name));
        }

        Ok(Rule {
            name,
            tags: self.tags,
            metadata: self.metadata,
            strings: self.strings,
            condition,
        })
    }
}

impl std::fmt::Display for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut output = String::new();

        // Rule name and tags
        output.push_str(&format!("rule {} {{\n", self.name));

        // Tags section
        if !self.tags.is_empty() {
            output.push_str("    tags:\n");
            for tag in &self.tags {
                output.push_str(&format!("        {}\n", tag));
            }
        }

        // Metadata section
        if !self.metadata.is_empty() {
            output.push_str("    metadata:\n");
            for (key, value) in &self.metadata {
                output.push_str(&format!("        {} = \"{}\"\n", key, value));
            }
        }

        // Strings section
        if !self.strings.is_empty() {
            output.push_str("    strings:\n");
            for string in &self.strings {
                let mut modifiers = String::new();
                if !string.modifiers.is_empty() {
                    modifiers = format!(" {}", string.modifiers.join(" "));
                }

                if string.is_hex {
                    output.push_str(&format!(
                        "        {} = {{ {} }}{}\n",
                        string.identifier, string.pattern, modifiers
                    ));
                } else {
                    output.push_str(&format!(
                        "        {} = \"{}\"{}\n",
                        string.identifier, string.pattern, modifiers
                    ));
                }
            }
        }

        // Condition section
        output.push_str("    condition:\n");
        output.push_str(&format!("        {}\n", self.condition));
        output.push('}');

        write!(f, "{}", output)
    }
}

/// Check if a string is a valid YARA identifier
fn is_valid_identifier(s: &str) -> bool {
    lazy_static::lazy_static! {
        static ref RE: Regex = Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$").unwrap();
    }
    RE.is_match(s)
}

// Re-export commonly used items
pub use patterns::{
    C2_PATTERNS, ENCRYPTION_APIS, FILE_HEADERS, OBFUSCATION_PATTERNS, RANSOMWARE_EXTENSIONS,
};
pub use templates::{
    backdoor_template, cryptominer_template, filetype_template, malware_template,
    ransomware_template,
};
pub use utils::{
    export_rule_to_json, import_rule_from_json, load_rule_from_file, save_rule_to_file,
};
pub use validation::{scan_with_rule, validate_against_samples, validate_rule, ValidationOptions};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_rule() {
        let rule = RuleBuilder::new("test_rule")
            .with_tag("malware")
            .with_metadata("author", "Test Author")
            .with_string("$suspicious_str", "malicious")
            .unwrap()
            .with_condition("$suspicious_str")
            .build()
            .unwrap();

        assert_eq!(rule.name, "test_rule");
        assert_eq!(rule.tags, vec!["malware"]);
        assert_eq!(
            rule.metadata.get("author"),
            Some(&"Test Author".to_string())
        );
    }

    #[test]
    fn test_invalid_rule_name() {
        let result = RuleBuilder::new("invalid-name")
            .with_condition("true")
            .build();
        assert!(matches!(result, Err(YaraError::InvalidRuleName(_))));
    }

    #[test]
    fn test_rule_to_string() {
        let rule = RuleBuilder::new("test_rule")
            .with_tag("malware")
            .with_metadata("author", "Test Author")
            .with_string("$suspicious_str", "malicious")
            .unwrap()
            .with_condition("$suspicious_str")
            .build()
            .unwrap();

        let rule_str = format!("{}", rule);
        assert!(rule_str.contains("rule test_rule"));
        assert!(rule_str.contains("tags:\n        malware"));
        assert!(rule_str.contains("author = \"Test Author\""));
    }
}
