# Contributing

Thanks for helping. The most useful contributions are new or corrected **rules**.

## Adding or fixing a rule

Rules live in [`rules/rules.toml`](rules/rules.toml) and are compiled into the binary.
A minimal rule:

```toml
[[rule]]
id = "my-crate"                # unique, a-z 0-9 and -
crate = "my-crate"             # exact crates.io name
title = "What the crate is"
reference = "https://docs.rs/my-crate"
algorithms = [
  { name = "X25519", primitive = "key-agree", status = "quantum-vulnerable" },
]
```

Optional fields:

| Field | Use |
|---|---|
| `versions` | `">=1.2.0, <2.0.0"`: comparisons with full versions only |
| `features_all` / `features_any` / `features_none` | match on the Cargo features enabled for the crate |
| `group` | rules in one group are tried in file order, first match wins (all must target the same crate) |
| `status` | the verdict for the project; defaults to the worst algorithm status |
| `category = "tls"` | shows the finding in the "TLS key exchange" headline |
| `note`, `fix` | one or two sentences each |
| `advisory` | `{ id = "CVE-...", url = "https://..." }` |

Algorithm fields: `name`, `primitive` (CycloneDX 1.6 values such as `signature`, `kem`,
`key-agree`, `ae`, `hash`, `mac`, `kdf`), `status`, and optionally `functions`,
`parameter_set` and `nist_level` (0-6).

Please:

1. **Check the claim in the crate's published source**, not only its docs, and name the
   version you checked in the note ("checked in 1.2.3"). Version-specific behavior is
   what makes this tool useful, and also what goes stale.
2. Keep notes short and factual.
3. Add a test when the rule depends on versions or features (see below).

You can try a rule without rebuilding: `cargo cbom --rules my-rules.toml`.

## Tests

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

Integration tests run the binary on saved `cargo metadata` output in
`tests/fixtures/`, so they need no network. To add a fixture, create a small probe
project, then:

```sh
cargo metadata --format-version 1 --manifest-path probe/Cargo.toml > metadata.json
python3 tests/fixtures/make_fixture.py metadata.json > tests/fixtures/NAME.json
```

The script keeps only the fields cargo-cbom reads and removes local paths.
`tests/schema/` holds the official CycloneDX 1.6 JSON schemas used to validate
every generated CBOM.

## Code

- Rust 1.86 or later (the MSRV is checked in CI).
- New dependencies need a good reason; the tool should stay quick to install.
- By contributing you agree that your work is dual-licensed under MIT and Apache-2.0.
