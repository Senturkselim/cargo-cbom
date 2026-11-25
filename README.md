# cargo-cbom

[![CI](https://github.com/Senturkselim/cargo-cbom/actions/workflows/ci.yml/badge.svg)](https://github.com/Senturkselim/cargo-cbom/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/cargo-cbom.svg)](https://crates.io/crates/cargo-cbom)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Is your Rust binary's TLS post-quantum? `cargo cbom` tells you in seconds, explains why, and shows the fix.**
It also writes a [CycloneDX 1.6](https://cyclonedx.org/capabilities/cbom/) Cryptography Bill of Materials (CBOM).

[Türkçe README](README.tr.md)

```text
$ cargo cbom
cargo-cbom 0.1.0 · post-quantum readiness of my-api 0.1.0
128 packages scanned (normal dependencies, target x86_64-unknown-linux-gnu) · 85 rules

TLS key exchange
  ! depends            rustls 0.23.46  aws-lc-rs provider, post-quantum not preferred

! DEPENDS ON USAGE OR CONFIGURATION (4)
  rustls 0.23.46 · TLS key exchange: aws-lc-rs provider, post-quantum not preferred
    algorithms: X25519MLKEM768 (kem), X25519 (key-agree)
    X25519MLKEM768 is supported but offered last. As a TLS client, rustls starts with a
    classical X25519 key share, so the hybrid group is used only if the server asks for it
    (HelloRetryRequest). As a server, rustls follows the client's preference.
    fix: Enable rustls' `prefer-post-quantum` feature in your own Cargo.toml, ...
    why: version 0.23.46 matches `>=0.23.22`; enabled features: aws_lc_rs; not enabled: prefer-post-quantum
    via: my-api 0.1.0 → reqwest 0.13.5 → rustls 0.23.46
  jsonwebtoken 12.0.0 · JSON Web Tokens (jsonwebtoken)
    ...
```

## Why

Harvest-now-decrypt-later attacks make key exchange the first thing to migrate, and
in Rust that usually means rustls. rustls 0.23.27 and later prefer the hybrid
`X25519MLKEM768` group by default, but only when two conditions hold: the **aws-lc-rs**
provider is used and the **`prefer-post-quantum`** feature is on. Most projects do not
depend on rustls directly, and the crates in between often turn rustls' default
features off.

Checked with cargo-cbom 0.1.0 on 2026-11-24 (each crate with its default features):

| Your dependency | rustls provider | `prefer-post-quantum` | Verdict |
|---|---|---|---|
| `rustls` 0.23.46 | aws-lc-rs | on | ✓ hybrid, X25519MLKEM768 offered first |
| `reqwest` 0.13.5 | aws-lc-rs | off | ! client starts with classical X25519 |
| `hyper-rustls` 0.27.10 | aws-lc-rs | off | ! client starts with classical X25519 |
| `tokio-rustls` 0.26.6 | aws-lc-rs | off | ! client starts with classical X25519 |
| `ureq` 3.5.2 | ring | n/a | ✗ no post-quantum key exchange |
| `reqwest` 0.12.28 with `rustls-tls` | ring | n/a | ✗ no post-quantum key exchange |

`Cargo.lock` does not record enabled features, so a tool that matches crate names in
the lock file cannot tell these cases apart. cargo-cbom reads the **resolved dependency
graph and the features Cargo actually enabled** (`cargo metadata`), so it can.

For the reqwest case the fix is one line in your own `Cargo.toml`; Cargo's feature
unification applies it to the rustls that reqwest uses:

```toml
rustls = { version = "0.23.27", default-features = false, features = ["prefer-post-quantum"] }
```

```text
$ cargo cbom
TLS key exchange
  ✓ hybrid             rustls 0.23.46  aws-lc-rs provider, post-quantum preferred
```

For `ureq` 3, also install the aws-lc-rs provider at startup, because ureq picks ring
unless a provider is installed:

```rust
rustls::crypto::aws_lc_rs::default_provider().install_default().unwrap();
```

To see what a running client actually negotiates, fetch
`https://www.cloudflare.com/cdn-cgi/trace` with it and look at the `kex=` line.

## Install

```sh
cargo install cargo-cbom --locked
```

Requires Rust 1.86 or later.

## Usage

```sh
cargo cbom                                   # text report for the current project
cargo cbom --manifest-path path/to/Cargo.toml
cargo cbom --format cbom --output cbom.json  # CycloneDX 1.6 CBOM
cargo cbom --format json                     # findings as JSON
cargo cbom --fail-on vulnerable              # exit 1 on quantum-vulnerable or known-vulnerable
cargo cbom --include-dev --include-build     # also scan dev/build-dependencies and proc-macros
cargo cbom --all-targets                     # every platform, not only the host
cargo cbom --target aarch64-unknown-linux-gnu
cargo cbom --features tls,metrics            # passed to cargo metadata
cargo cbom --rules my-rules.toml             # add or override rules
cargo cbom --list-rules
cargo metadata --format-version 1 > m.json && cargo cbom --metadata m.json
```

Exit codes: `0` ok, `1` a finding matched `--fail-on`, `2` error.

### Statuses

| Status | Meaning |
|---|---|
| `classically-broken` | broken without a quantum computer (MD5, SHA-1, DES, RC4) |
| `known-vulnerable` | the resolved version is affected by a published advisory |
| `quantum-vulnerable` | RSA, ECC or DH only: broken by Shor's algorithm |
| `pre-standard-pq` | post-quantum, but a pre-standard variant (Kyber, Dilithium, SPHINCS+, Falcon, HQC) |
| `depends` | the outcome depends on how the crate is used or configured |
| `symmetric` | symmetric primitive, not affected by Shor's algorithm |
| `hybrid` | post-quantum/traditional hybrid such as X25519MLKEM768 or X-Wing |
| `post-quantum` | a NIST standard: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) |

`--fail-on` takes a comma-separated list of these (except the three green ones);
`vulnerable` is short for `quantum-vulnerable,known-vulnerable`.

### In CI

```yaml
- run: cargo install cargo-cbom --locked
- run: cargo cbom --fail-on vulnerable
- run: cargo cbom --format cbom --output cbom.json
- uses: actions/upload-artifact@v4
  with:
    name: cbom
    path: cbom.json
```

The CBOM is deterministic (no timestamp or serial number, sorted arrays), so you can
also commit it and review changes in pull requests.

## How it works

1. Runs `cargo metadata` (for the host target unless `--all-targets` or `--target` is
   given) and walks the resolved graph from your workspace members. Normal dependencies
   are scanned by default; dev-dependencies, build-dependencies and proc-macros are
   opt-in. Each finding shows the shortest path that pulls the crate in.
2. Matches every package against [rules](rules/rules.toml) by name, version range and
   enabled features. Rules in the same group are tried in order and the first match
   wins, which is how the rustls verdict is decided:

   | rustls | Verdict |
   |---|---|
   | 0.24 preview | depends (not modeled yet) |
   | < 0.23 | quantum-vulnerable |
   | `custom-provider` feature | depends |
   | `aws_lc_rs` and `ring` both enabled | depends: the installed provider decides |
   | `ring` only | quantum-vulnerable |
   | `aws_lc_rs`, < 0.23.22 | quantum-vulnerable |
   | `aws_lc_rs` + `prefer-post-quantum` | hybrid |
   | `aws_lc_rs` without `prefer-post-quantum` | depends |
   | no built-in provider | depends |

3. Prints a report, findings JSON or a CycloneDX 1.6 CBOM in which each crate
   `provides` its algorithm assets. Quantum-vulnerable algorithms get
   `nistQuantumSecurityLevel: 0`.

85 rules cover 70 crates: rustls, ureq, BoringSSL, OpenSSL (vendored and
system), native-tls, aws-lc-rs, ring, libsodium, RustCrypto public-key, symmetric
and post-quantum crates, JWT/JOSE libraries, rcgen, HPKE, X-Wing, liboqs, pqcrypto
and libcrux. Run `cargo cbom --list-rules` for the full list. Version-specific claims
were checked against the published crate sources, and the note says which version.

## Limitations

- It reports what is **compiled in**, not which functions your code calls. A crate
  such as ring or aws-lc-rs shows up as `depends` because it offers both classical and
  post-quantum algorithms.
- Features come from `cargo metadata`, which reports one feature set per package.
- When both rustls providers are compiled in, the provider is chosen at runtime
  (`install_default`, or a library's own choice); cargo-cbom says so instead of guessing.
- It is not a vulnerability database. Keep using `cargo audit` or `cargo deny`; the
  single advisory rule (ml-dsa, CVE-2026-24850) is there because it affects a
  post-quantum primitive.
- Rules can go stale as crates change. Each rule links its reference; please open an
  issue or a pull request when something is out of date.

## Contributing

New rules are the easiest way to help; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

- Source-level confirmation of algorithm use (with `syn`) to separate "compiled in" from "called"
- SARIF output for GitHub code scanning, and a ready-made GitHub Action
- rustls 0.24 provider crates
- Optional RustSec advisory lookup for crypto crates

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
