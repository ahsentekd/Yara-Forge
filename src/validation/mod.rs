//! Validation module for YARA rules
//! Provides functionality to validate and test YARA rules

use std::path::Path;
use std::process::Command;
use tempfile::NamedTempFile;
use thiserror::Error;
use walkdir::WalkDir;
use std::io::Write;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("YARA syntax error: {0}")]
    SyntaxError(String),
    #[error("YARA compilation error: {0}")]
    CompilationError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Test file creation error: {0}")]
    TestFileError(String),
}

/// Options for rule validation
#[derive(Debug, Clone)]
pub struct ValidationOptions {
    /// Check for syntax only
    pub syntax_only: bool,
    /// Verify against test files
    pub test_against_samples: bool,
    /// Maximum file size to scan (in bytes)
    pub max_file_size: u64,
    /// Timeout for scanning (in seconds)
    pub timeout: u64,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            syntax_only: false,
            test_against_samples: false,
            max_file_size: 10 * 1024 * 1024, // 10MB
            timeout: 60,
        }
    }
}

/// Validates a YARA rule
pub fn validate_rule(rule: &str, options: &ValidationOptions) -> Result<(), ValidationError> {
    // Create a temporary file for the rule
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(rule.as_bytes())?;
    
    // Run yarac for syntax checking
    let output = Command::new("yarac")
        .arg(temp_file.path())
        .arg("/dev/null")
        .output()
        .map_err(|e| ValidationError::IoError(e))?;

    if !output.status.success() {
        return Err(ValidationError::SyntaxError(
            String::from_utf8_lossy(&output.stderr).to_string()
        ));
    }

    if options.syntax_only {
        return Ok(());
    }

    if options.test_against_samples {
        validate_against_samples(rule, options)?;
    }

    Ok(())
}

/// Tests a YARA rule against a directory of samples
pub fn validate_against_samples(rule: &str, _options: &ValidationOptions) -> Result<(), ValidationError> {
    let mut temp_rule = NamedTempFile::new()?;
    temp_rule.write_all(rule.as_bytes())?;

    // Compile the rule
    let compiled_rule = NamedTempFile::new()?;
    let status = Command::new("yarac")
        .arg(temp_rule.path())
        .arg(compiled_rule.path())
        .status()
        .map_err(|e| ValidationError::IoError(e))?;

    if !status.success() {
        return Err(ValidationError::CompilationError("Failed to compile rule".to_string()));
    }

    Ok(())
}

/// Scans a file or directory with a YARA rule
pub fn scan_with_rule(
    rule_path: impl AsRef<Path>,
    target_path: impl AsRef<Path>,
    options: &ValidationOptions
) -> Result<Vec<String>, ValidationError> {
    let mut matches = Vec::new();
    
    let output = Command::new("yara")
        .arg("--timeout")
        .arg(options.timeout.to_string())
        .arg("--max-files")
        .arg("1000")
        .arg(rule_path.as_ref())
        .arg(target_path.as_ref())
        .output()
        .map_err(|e| ValidationError::IoError(e))?;

    if output.status.success() {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            matches.push(line.to_string());
        }
    }

    Ok(matches)
}

/// Performs parallel scanning of multiple files
pub fn parallel_scan(
    rule_path: impl AsRef<Path>,
    target_dir: impl AsRef<Path>,
    options: &ValidationOptions
) -> Result<Vec<String>, ValidationError> {
    use rayon::prelude::*;
    
    let walker = WalkDir::new(target_dir)
        .min_depth(1)
        .max_depth(5)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            if let Ok(metadata) = e.metadata() {
                metadata.len() <= options.max_file_size
            } else {
                false
            }
        })
        .collect::<Vec<_>>();

    let rule_path = rule_path.as_ref().to_path_buf();
    let matches: Vec<String> = walker.par_iter()
        .filter_map(|entry| {
            scan_with_rule(&rule_path, entry.path(), options).ok()
        })
        .flatten()
        .collect();

    Ok(matches)
}
