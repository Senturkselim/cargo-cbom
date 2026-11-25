# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-24

### Added

- `cargo cbom` subcommand that walks the resolved dependency graph from
  `cargo metadata` (host target by default; `--target`, `--all-targets`), with
  dev-dependencies and build-time code as opt-in scopes.
- Feature- and version-aware rules (85 rules, 70 crates), including rustls provider
  and `prefer-post-quantum` detection, ureq, BoringSSL, vendored and system OpenSSL,
  JWT/JOSE crates, and NIST post-quantum crates.
- Text report with a "TLS key exchange" headline, dependency paths and fixes.
- Findings JSON and deterministic CycloneDX 1.6 CBOM output.
- `--fail-on` policy gate with exit codes 0, 1 and 2.
- `--rules` to add or override rules, `--list-rules`, `--metadata` for saved
  `cargo metadata` output.
