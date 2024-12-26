//! Common YARA pattern libraries
//! Provides pre-defined patterns for various detection scenarios

/// File header patterns for common file types
pub const FILE_HEADERS: &[&str] = &[
    "4D 5A",       // MZ (Windows executable)
    "7F 45 4C 46", // ELF (Linux executable)
    "50 4B 03 04", // ZIP archive
    "FF D8 FF",    // JPEG
    "89 50 4E 47", // PNG
];

/// Common encryption API patterns
pub const ENCRYPTION_APIS: &[&str] = &[
    "CryptoAPI",
    "OpenSSL",
    "BCrypt",
    "AES_encrypt",
    "RC4_encrypt",
];

/// Common ransomware file extensions
pub const RANSOMWARE_EXTENSIONS: &[&str] =
    &[".encrypted", ".locked", ".crypted", ".crypt", ".WNCRY"];

/// Command and control (C2) patterns
pub const C2_PATTERNS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "nc.exe",
    "netcat",
    "reverse_tcp",
];

/// Code obfuscation patterns
pub const OBFUSCATION_PATTERNS: &[&str] = &[
    "eval(",
    "base64_decode(",
    "chr(",
    "fromCharCode",
    "unescape(",
];

/// Common process injection patterns
pub const PROCESS_INJECTION: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
];

/// Common registry persistence keys
pub const PERSISTENCE_REGISTRY_KEYS: &[&str] = &[
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
];

/// Common sandbox evasion techniques
pub const SANDBOX_EVASION: &[&str] = &[
    "GetTickCount",
    "QueryPerformanceCounter",
    "GetSystemTime",
    "GetComputerNameA",
    "GetProcessHeap",
];

/// Generate hex pattern with wildcards
pub fn generate_hex_pattern(pattern: &[u8], mask: &[bool]) -> String {
    assert_eq!(
        pattern.len(),
        mask.len(),
        "Pattern and mask must have the same length"
    );

    pattern
        .iter()
        .zip(mask.iter())
        .map(|(byte, &is_fixed)| {
            if is_fixed {
                format!("{:02X}", byte)
            } else {
                "??".to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Generate base64 pattern
pub fn generate_base64_pattern(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(data)
}

/// Generate SHA256 pattern
pub fn generate_sha256_pattern(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_pattern() {
        let pattern = &[0x48, 0x45, 0x4C, 0x4C, 0x4F];
        let mask = &[true, true, false, true, true];
        let result = generate_hex_pattern(pattern, mask);
        assert_eq!(result, "48 45 ?? 4C 4F");
    }

    #[test]
    fn test_base64_pattern() {
        let data = b"Hello World!";
        let result = generate_base64_pattern(data);
        assert_eq!(result, "SGVsbG8gV29ybGQh");
    }

    #[test]
    fn test_sha256_pattern() {
        let data = b"test data";
        let result = generate_sha256_pattern(data);
        assert_eq!(
            result,
            "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }
}
