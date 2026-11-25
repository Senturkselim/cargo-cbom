//! Core vocabulary shared by rules, analysis and reports.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Verdict for a finding or an algorithm.
///
/// Variants are declared from worst to best, so `Ord` sorts the most
/// urgent findings first and `min()` gives the worst status of a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Broken even without a quantum computer (MD5, SHA-1, DES, RC4, ...).
    ClassicallyBroken,
    /// The resolved version is affected by a published advisory.
    KnownVulnerable,
    /// Public-key cryptography broken by Shor's algorithm (RSA, ECC, DH).
    QuantumVulnerable,
    /// Post-quantum, but a pre-standard variant (Kyber, Dilithium, SPHINCS+, ...).
    PreStandardPq,
    /// The outcome depends on how the crate is used or configured.
    Depends,
    /// Symmetric primitive; not affected by Shor's algorithm.
    Symmetric,
    /// Post-quantum/traditional hybrid (e.g. X25519MLKEM768).
    Hybrid,
    /// A NIST post-quantum standard (ML-KEM, ML-DSA, SLH-DSA).
    PostQuantum,
}

impl Status {
    pub const ALL: [Status; 8] = [
        Status::ClassicallyBroken,
        Status::KnownVulnerable,
        Status::QuantumVulnerable,
        Status::PreStandardPq,
        Status::Depends,
        Status::Symmetric,
        Status::Hybrid,
        Status::PostQuantum,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Status::ClassicallyBroken => "classically-broken",
            Status::KnownVulnerable => "known-vulnerable",
            Status::QuantumVulnerable => "quantum-vulnerable",
            Status::PreStandardPq => "pre-standard-pq",
            Status::Depends => "depends",
            Status::Symmetric => "symmetric",
            Status::Hybrid => "hybrid",
            Status::PostQuantum => "post-quantum",
        }
    }

    /// Section heading used in the text report.
    pub fn heading(self) -> &'static str {
        match self {
            Status::ClassicallyBroken => "CLASSICALLY BROKEN",
            Status::KnownVulnerable => "KNOWN VULNERABILITY",
            Status::QuantumVulnerable => "QUANTUM-VULNERABLE",
            Status::PreStandardPq => "PRE-STANDARD POST-QUANTUM",
            Status::Depends => "DEPENDS ON USAGE OR CONFIGURATION",
            Status::Symmetric => "SYMMETRIC (NOT AFFECTED BY SHOR'S ALGORITHM)",
            Status::Hybrid => "HYBRID POST-QUANTUM",
            Status::PostQuantum => "POST-QUANTUM",
        }
    }

    pub fn symbol(self) -> &'static str {
        match self {
            Status::ClassicallyBroken | Status::KnownVulnerable | Status::QuantumVulnerable => "✗",
            Status::PreStandardPq | Status::Depends => "!",
            Status::Symmetric | Status::Hybrid | Status::PostQuantum => "✓",
        }
    }

    /// `true` for statuses that should be fixed (red in the report).
    pub fn is_problem(self) -> bool {
        matches!(
            self,
            Status::ClassicallyBroken | Status::KnownVulnerable | Status::QuantumVulnerable
        )
    }

    /// `true` for statuses that need a human decision (yellow in the report).
    pub fn is_warning(self) -> bool {
        matches!(self, Status::PreStandardPq | Status::Depends)
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Cryptographic primitive, using the CycloneDX 1.6 vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Primitive {
    Drbg,
    Mac,
    BlockCipher,
    StreamCipher,
    Signature,
    Hash,
    Pke,
    Xof,
    Kdf,
    KeyAgree,
    Kem,
    Ae,
    Combiner,
    Other,
    Unknown,
}

impl Primitive {
    pub fn as_str(self) -> &'static str {
        match self {
            Primitive::Drbg => "drbg",
            Primitive::Mac => "mac",
            Primitive::BlockCipher => "block-cipher",
            Primitive::StreamCipher => "stream-cipher",
            Primitive::Signature => "signature",
            Primitive::Hash => "hash",
            Primitive::Pke => "pke",
            Primitive::Xof => "xof",
            Primitive::Kdf => "kdf",
            Primitive::KeyAgree => "key-agree",
            Primitive::Kem => "kem",
            Primitive::Ae => "ae",
            Primitive::Combiner => "combiner",
            Primitive::Other => "other",
            Primitive::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Primitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Cryptographic function, using the CycloneDX 1.6 vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoFunction {
    Generate,
    Keygen,
    Encrypt,
    Decrypt,
    Digest,
    Tag,
    Keyderive,
    Sign,
    Verify,
    Encapsulate,
    Decapsulate,
    Other,
    Unknown,
}

/// Optional topic of a rule, used to build the report headline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// TLS key exchange: the most common way a Rust binary uses public-key
    /// cryptography, and the first thing to make post-quantum.
    Tls,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Tls => "TLS key exchange",
        }
    }
}

/// Which part of the build pulls a package in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    /// Shipped in the final artifact (normal dependency chain).
    Normal,
    /// Only reachable through a workspace member's dev-dependencies.
    Dev,
    /// Only used at compile time (build scripts and proc-macros).
    Build,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Normal => "normal",
            Scope::Dev => "dev",
            Scope::Build => "build",
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
