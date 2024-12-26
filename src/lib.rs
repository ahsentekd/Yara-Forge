//! YARA Rule Generator
//! 
//! A comprehensive Rust library for generating YARA rules.
//! This library provides a simple and intuitive API to create,
//! validate, and manage YARA rules programmatically.

pub mod templates;
pub mod patterns;
pub mod validation;
pub mod utils;

use std::collections::HashMap;
use thiserror::Error;
use serde::{Serialize, Deserialize};
use regex::Regex;

#[derive(Debug, Error)]
pub enum YaraError {
    #[error("Invalid rule name: {0}")]
    InvalidRuleName(String),
    #[error("Invalid string identifier: {0}")]
    InvalidStringIdentifier(String),
    #[error("Invalid condition: {0}")]
    InvalidCondition(String),
    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// Represents a YARA rule string definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringDefinition {
    identifier: String,
    pattern: String,
    is_hex: bool,
    modifiers: Vec<String>,
}

impl StringDefinition {
    /// Create a new string definition
    pub fn new(identifier: &str, pattern: &str) -> Result<Self, YaraError> {
        if !is_valid_identifier(identifier) {
            return Err(YaraError::InvalidStringIdentifier(identifier.to_string()));
        }

        Ok(Self {
            identifier: identifier.to_string(),
            pattern: pattern.to_string(),
            is_hex: false,
            modifiers: Vec::new(),
        })
    }

    /// Add a modifier to the string definition
    pub fn with_modifier(mut self, modifier: &str) -> Self {
        self.modifiers.push(modifier.to_string());
        self
    }

    /// Set the pattern as hexadecimal
    pub fn as_hex(mut self) -> Self {
        self.is_hex = true;
        self
    }
}

/// Represents a complete YARA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    name: String,
    tags: Vec<String>,
    metadata: HashMap<String, String>,
    strings: Vec<StringDefinition>,
    condition: String,
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
    /// Create a new RuleBuilder instance
    pub fn new(name: &str) -> Self {
        let mut builder = RuleBuilder::default();
        builder.name = Some(name.to_string());
        builder
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

    /// Add a string definition to the rule
    pub fn with_string(mut self, identifier: &str, pattern: &str) -> Result<Self, YaraError> {
        let string_def = StringDefinition::new(identifier, pattern)?;
        self.strings.push(string_def);
        Ok(self)
    }

    /// Set the condition for the rule
    pub fn with_condition(mut self, condition: &str) -> Self {
        self.condition = Some(condition.to_string());
        self
    }

    /// Build the YARA rule
    pub fn build(self) -> Result<Rule, YaraError> {
        let name = self.name.ok_or_else(|| YaraError::MissingField("rule name".to_string()))?;
        let condition = self.condition.ok_or_else(|| YaraError::MissingField("condition".to_string()))?;

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

impl Rule {
    /// Convert the rule to its string representation
    pub fn to_string(&self) -> String {
        let mut output = String::new();

        // Add rule name and tags
        output.push_str(&format!("rule {} {{\n", self.name));

        // Add metadata section if present
        if !self.metadata.is_empty() {
            output.push_str("    metadata:\n");
            for (key, value) in &self.metadata {
                output.push_str(&format!("        {} = \"{}\"\n", key, value));
            }
        }

        // Add strings section if present
        if !self.strings.is_empty() {
            output.push_str("    strings:\n");
            for string in &self.strings {
                let pattern = if string.is_hex {
                    format!("{{ {} }}", string.pattern)
                } else {
                    format!("\"{}\"", string.pattern)
                };
                
                let modifiers = if string.modifiers.is_empty() {
                    String::new()
                } else {
                    format!(" {}", string.modifiers.join(" "))
                };
                
                output.push_str(&format!("        {} = {}{}\n", 
                    string.identifier, pattern, modifiers));
            }
        }

        // Add condition section
        output.push_str("    condition:\n");
        output.push_str(&format!("        {}\n", self.condition));
        output.push_str("}\n");

        output
    }
}

/// Check if a string is a valid YARA identifier
fn is_valid_identifier(s: &str) -> bool {
    // YARA identifiers can start with $ for string identifiers
    let identifier_regex = Regex::new(r"^[$]?[a-zA-Z_][a-zA-Z0-9_]*$").unwrap();
    identifier_regex.is_match(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_builder() {
        let rule = RuleBuilder::new("test_rule")
            .with_tag("malware")
            .with_metadata("author", "Test Author")
            .with_string("$suspicious_str", "malicious").unwrap()
            .with_condition("$suspicious_str")
            .build()
            .unwrap();

        assert_eq!(rule.name, "test_rule");
        assert_eq!(rule.tags, vec!["malware"]);
        assert_eq!(rule.metadata.get("author").unwrap(), "Test Author");
        assert_eq!(rule.strings.len(), 1);
        assert_eq!(rule.condition, "$suspicious_str");
    }

    #[test]
    fn test_invalid_rule_name() {
        let result = RuleBuilder::new("invalid-name")
            .with_condition("true")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_rule_to_string() {
        let rule = RuleBuilder::new("test_rule")
            .with_tag("malware")
            .with_metadata("author", "Test Author")
            .with_string("$suspicious_str", "malicious").unwrap()
            .with_condition("$suspicious_str")
            .build()
            .unwrap();

        let rule_str = rule.to_string();
        assert!(rule_str.contains("rule test_rule {"));
        assert!(rule_str.contains("metadata:"));
        assert!(rule_str.contains("author = \"Test Author\""));
        assert!(rule_str.contains("strings:"));
        assert!(rule_str.contains("$suspicious_str = \"malicious\""));
        assert!(rule_str.contains("condition:"));
        assert!(rule_str.contains("$suspicious_str"));
    }
}

// Re-export commonly used items
pub use templates::{ransomware_template, cryptominer_template, backdoor_template, malware_template, filetype_template};
pub use patterns::{FILE_HEADERS, ENCRYPTION_APIS, RANSOMWARE_EXTENSIONS, C2_PATTERNS, OBFUSCATION_PATTERNS};
pub use validation::{validate_rule, validate_against_samples, scan_with_rule, ValidationOptions};
pub use utils::{export_rule_to_json, import_rule_from_json, save_rule_to_file, load_rule_from_file};
