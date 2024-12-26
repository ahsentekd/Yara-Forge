//! Utility functions for YARA rule generation
//! Provides helper functions for common tasks

use std::fs;
use std::path::Path;
use std::io::{self, Read, Write};
use serde_json::{json, Value};

/// Export a rule to JSON format
pub fn export_rule_to_json(rule: &crate::Rule) -> Value {
    json!({
        "name": rule.name,
        "tags": rule.tags,
        "metadata": rule.metadata,
        "strings": rule.strings.iter().map(|s| {
            json!({
                "identifier": s.identifier,
                "pattern": s.pattern,
                "is_hex": s.is_hex,
                "modifiers": s.modifiers,
            })
        }).collect::<Vec<_>>(),
        "condition": rule.condition,
    })
}

/// Import a rule from JSON format
pub fn import_rule_from_json(json: Value) -> Result<crate::Rule, crate::YaraError> {
    let name = json["name"].as_str()
        .ok_or_else(|| crate::YaraError::MissingField("name".to_string()))?
        .to_string();

    let tags = json["tags"].as_array()
        .map(|arr| arr.iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_string())
            .collect())
        .unwrap_or_default();

    let metadata = json["metadata"].as_object()
        .map(|obj| obj.iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect())
        .unwrap_or_default();

    let strings = json["strings"].as_array()
        .ok_or_else(|| crate::YaraError::MissingField("strings".to_string()))?
        .iter()
        .map(|s| crate::StringDefinition {
            identifier: s["identifier"].as_str().unwrap_or("").to_string(),
            pattern: s["pattern"].as_str().unwrap_or("").to_string(),
            is_hex: s["is_hex"].as_bool().unwrap_or(false),
            modifiers: s["modifiers"].as_array()
                .map(|arr| arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect())
                .unwrap_or_default(),
        })
        .collect();

    let condition = json["condition"].as_str()
        .ok_or_else(|| crate::YaraError::MissingField("condition".to_string()))?
        .to_string();

    Ok(crate::Rule {
        name,
        tags,
        metadata,
        strings,
        condition,
    })
}

/// Save a rule to a file
pub fn save_rule_to_file<P: AsRef<Path>>(rule: &crate::Rule, path: P) -> io::Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(rule.to_string().as_bytes())?;
    Ok(())
}

/// Load a rule from a file
pub fn load_rule_from_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

/// Generate a unique rule name
pub fn generate_unique_rule_name(prefix: &str) -> String {
    use chrono::Utc;
    format!("{}_{}", prefix, Utc::now().timestamp())
}

/// Escape special characters in strings
pub fn escape_string(s: &str) -> String {
    s.replace('\\', "\\\\")
     .replace('"', "\\\"")
     .replace('\n', "\\n")
     .replace('\r', "\\r")
     .replace('\t', "\\t")
}

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let hex = hex.replace(" ", "");
    hex::decode(hex)
}

/// Calculate entropy of data
pub fn calculate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    
    let len = data.len() as f64;
    let mut entropy = 0.0;
    
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    
    entropy
}
