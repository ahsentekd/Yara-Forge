//! Common patterns for malware detection
//! This module provides pre-defined patterns for various types of malicious behavior

use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    /// Common file headers for various file types
    pub static ref FILE_HEADERS: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("pdf", "25 50 44 46");  // %PDF
        m.insert("exe", "4D 5A");        // MZ
        m.insert("elf", "7F 45 4C 46");  // .ELF
        m.insert("zip", "50 4B 03 04");  // PK..
        m.insert("jpg", "FF D8 FF");     // JPEG SOI marker
        m.insert("png", "89 50 4E 47");  // .PNG
        m.insert("office", "D0 CF 11 E0 A1 B1 1A E1"); // MS Office
        m
    };

    /// Common encryption API patterns
    pub static ref ENCRYPTION_APIS: Vec<&'static str> = vec![
        "CryptoAPI",
        "CryptEncrypt",
        "CryptDecrypt",
        "EVP_EncryptInit",
        "EVP_DecryptInit",
        "CreateDecryptor",
        "RijndaelManaged",
        "AesCryptoServiceProvider",
    ];

    /// Common ransomware extensions
    pub static ref RANSOMWARE_EXTENSIONS: Vec<&'static str> = vec![
        ".encrypted",
        ".locked",
        ".crypto",
        ".crypt",
        ".crypted",
        ".encode",
        ".krypt",
        ".locked",
        ".ransom",
    ];

    /// Common command and control patterns
    pub static ref C2_PATTERNS: Vec<&'static str> = vec![
        "User-Agent: Mozilla",
        "POST /gate.php",
        "/admin/get.php",
        "/panel/gate.php",
        "/config/settings",
    ];

    /// Common obfuscation patterns
    pub static ref OBFUSCATION_PATTERNS: Vec<&'static str> = vec![
        "eval(",
        "base64_decode(",
        "gzinflate(",
        "str_rot13(",
        "document.write(unescape",
        "String.fromCharCode(",
    ];
}

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
    assert_eq!(pattern.len(), mask.len(), "Pattern and mask must have the same length");
    
    pattern.iter()
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
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.encode(data)
}

/// Generate SHA256 pattern
pub fn generate_sha256_pattern(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}
