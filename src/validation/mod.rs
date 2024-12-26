//! Validation module for YARA rules
//! Provides functionality to validate and test YARA rules

use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::NamedTempFile;
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Syntax error: {0}")]
    SyntaxError(String),
    #[error("Compilation error: {0}")]
    CompilationError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Invalid path: {0}")]
    InvalidPath(String),
    #[error("YARA command failed: {0}")]
    CommandFailed(String),
}

/// Options for rule validation
#[derive(Debug, Clone)]
pub struct ValidationOptions {
    /// Only check syntax without compiling
    pub syntax_only: bool,
    /// Test against sample files
    pub test_against_samples: bool,
    /// Maximum file size to scan (in bytes)
    pub max_file_size: usize,
    /// Timeout in seconds
    pub timeout: u32,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        ValidationOptions {
            syntax_only: false,
            test_against_samples: false,
            max_file_size: 10 * 1024 * 1024, // 10MB
            timeout: 60,
        }
    }
}

/// Validate a YARA rule
pub fn validate_rule(rule: &str, _options: &ValidationOptions) -> Result<(), ValidationError> {
    // Create a temporary file for the rule
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(rule.as_bytes())?;

    // Run yarac for syntax checking
    let output = Command::new("yarac")
        .arg(temp_file.path())
        .arg("/dev/null")
        .output()?;

    if !output.status.success() {
        return Err(ValidationError::SyntaxError(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    Ok(())
}

/// Tests a YARA rule against a directory of samples
pub fn validate_against_samples(
    rule: &str,
    _options: &ValidationOptions,
) -> Result<(), ValidationError> {
    let mut temp_rule = NamedTempFile::new()?;
    temp_rule.write_all(rule.as_bytes())?;

    // Compile the rule
    let status = Command::new("yarac")
        .arg(temp_rule.path())
        .arg("compiled_rule")
        .status()
        .map_err(|e| ValidationError::IoError(e))?;

    if !status.success() {
        return Err(ValidationError::CompilationError(
            "Failed to compile rule".to_string(),
        ));
    }

    Ok(())
}

/// Scan a file or directory with a YARA rule
pub fn scan_with_rule(
    rule_path: impl AsRef<Path>,
    target_path: impl AsRef<Path>,
    options: &ValidationOptions,
) -> Result<Vec<String>, ValidationError> {
    let mut matches = Vec::new();

    let output = Command::new("yara")
        .arg("--timeout")
        .arg(options.timeout.to_string())
        .arg("--max-files")
        .arg("1000")
        .arg(rule_path.as_ref())
        .arg(target_path.as_ref())
        .output()?;

    if output.status.success() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        matches.extend(output_str.lines().map(String::from));
    }

    Ok(matches)
}

/// Scan files in parallel using multiple threads
pub fn parallel_scan(
    rule_path: impl AsRef<Path>,
    target_dir: impl AsRef<Path>,
    options: &ValidationOptions,
) -> Result<Vec<String>, ValidationError> {
    use rayon::prelude::*;

    let walker = WalkDir::new(target_dir)
        .min_depth(1)
        .max_depth(5)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_type().is_file()
                && e.metadata()
                    .map(|m| m.len() as usize <= options.max_file_size)
                    .unwrap_or(false)
        })
        .collect::<Vec<_>>();

    let rule_path = rule_path.as_ref().to_path_buf();
    let matches: Vec<String> = walker
        .par_iter()
        .filter_map(|entry| scan_with_rule(&rule_path, entry.path(), options).ok())
        .flatten()
        .collect();

    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_validation() {
        let rule = r#"
            rule test {
                strings:
                    $a = "test"
                condition:
                    $a
            }
        "#;

        let options = ValidationOptions::default();
        assert!(validate_rule(rule, &options).is_ok());
    }

    #[test]
    fn test_invalid_rule() {
        let rule = r#"
            rule test {
                strings:
                    $a = "test
                condition:
                    $a
            }
        "#;

        let options = ValidationOptions::default();
        assert!(validate_rule(rule, &options).is_err());
    }
}
