# YARA Forge 🛠️

A powerful Rust library for crafting, validating, and managing YARA rules. YARA Forge provides a comprehensive set of tools for creating sophisticated malware detection rules with an intuitive builder pattern interface.

[![Crates.io](https://img.shields.io/crates/v/yara-forge.svg)](https://crates.io/crates/yara-forge)
[![Documentation](https://docs.rs/yara-forge/badge.svg)](https://docs.rs/yara-forge)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/username/yara-forge/workflows/CI/badge.svg)](https://github.com/username/yara-forge/actions)

## Features

- 🏗️ **Rule Builder Pattern**: Intuitive interface for creating YARA rules
- 📚 **Pre-built Templates**: Common templates for malware detection
- 🔍 **Pattern Library**: Extensive collection of malware detection patterns
- ✅ **Validation**: Built-in rule validation and testing
- 🚀 **Performance**: Parallel scanning capabilities
- 🔄 **Import/Export**: Support for JSON and other formats
- 📋 **Documentation**: Comprehensive documentation and examples

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
yara-forge = "0.1.0"
```

## Quick Start

```rust
use yara_forge::{RuleBuilder, ValidationOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a simple rule
    let rule = RuleBuilder::new("detect_suspicious")
        .with_metadata("author", "YARA Forge")
        .with_string("$suspicious_api", "CreateRemoteThread")
        .with_condition("$suspicious_api")
        .build()?;

    // Validate the rule
    let options = ValidationOptions {
        syntax_only: true,
        test_against_samples: false,
        max_file_size: 10 * 1024 * 1024,
        timeout: 30,
    };

    // Save the rule
    rule.save("detect_suspicious.yar")?;

    Ok(())
}
```

## Advanced Usage

### Using Templates

```rust
use yara_forge::templates::ransomware_template;

let rule = ransomware_template("detect_ransomware")
    .with_metadata("severity", "high")
    .build()?;
```

### Pattern Matching

```rust
use yara_forge::patterns::{ENCRYPTION_APIS, PROCESS_INJECTION};

let rule = RuleBuilder::new("detect_malware")
    .with_patterns(ENCRYPTION_APIS)
    .with_patterns(PROCESS_INJECTION)
    .with_condition("2 of them")
    .build()?;
```

### Parallel Scanning

```rust
use yara_forge::validation::parallel_scan;

let matches = parallel_scan("rules/malware.yar", "samples/", &options)?;
```

## Development

```bash
# Run tests
cargo test

# Run benchmarks
cargo bench

# Build documentation
cargo doc --no-deps --open

# Format code
cargo fmt

# Run lints
cargo clippy
```

## Docker Support

Build the Docker image:

```bash
docker build -t yara-forge .
```

Run with Docker Compose:

```bash
docker-compose up
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- YARA Project: https://virustotal.github.io/yara/
- Rust Community
- All Contributors

## Security

For security issues, please open issue on GitHub.
