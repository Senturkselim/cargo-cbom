//! `cargo-cbom` checks which cryptography a Rust project compiles in, whether
//! it is ready for post-quantum cryptography, and emits a CycloneDX 1.6
//! Cryptography Bill of Materials (CBOM).
//!
//! The binary is the main interface (`cargo cbom`); the library is exposed so
//! the analysis can be embedded or tested against saved `cargo metadata`
//! output.

pub mod analyze;
pub mod cbom;
pub mod graph;
pub mod model;
pub mod report;
pub mod rules;

pub use analyze::{Finding, PackageRef, Report, analyze};
pub use graph::ScopeOptions;
pub use model::{Scope, Status};
pub use rules::RuleSet;
