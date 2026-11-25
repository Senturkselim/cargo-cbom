//! End-to-end tests: run the binary on saved `cargo metadata` fixtures.
//!
//! Fixtures were produced with `cargo metadata --format-version 1` on small
//! probe projects and shrunk with `tests/fixtures/make_fixture.py`.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.json"))
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cargo-cbom"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run cargo-cbom")
}

fn run_on(name: &str, extra: &[&str]) -> Output {
    let path = fixture(name);
    let mut args = vec!["--metadata", path.to_str().unwrap()];
    args.extend_from_slice(extra);
    run(&args)
}

fn json_on(name: &str, extra: &[&str]) -> Value {
    let mut args = vec!["--format", "json"];
    args.extend_from_slice(extra);
    let out = run_on(name, &args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("valid JSON")
}

/// (rule id, status) of findings for one crate.
fn verdicts(report: &Value, crate_name: &str) -> Vec<(String, String)> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["package"]["name"] == crate_name)
        .map(|f| {
            (
                f["rule"].as_str().unwrap().to_string(),
                f["status"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn pair(rule: &str, status: &str) -> (String, String) {
    (rule.to_string(), status.to_string())
}

#[test]
fn rustls_default_features_prefer_post_quantum() {
    let r = json_on("rustls_default", &[]);
    assert_eq!(
        verdicts(&r, "rustls"),
        [pair("rustls-pq-preferred", "hybrid")]
    );
}

#[test]
fn rustls_ring_provider_is_quantum_vulnerable() {
    let r = json_on("rustls_ring", &[]);
    assert_eq!(
        verdicts(&r, "rustls"),
        [pair("rustls-ring", "quantum-vulnerable")]
    );
}

#[test]
fn rustls_aws_lc_rs_without_preference_depends() {
    let r = json_on("rustls_awslc_nopq", &[]);
    assert_eq!(
        verdicts(&r, "rustls"),
        [pair("rustls-pq-not-preferred", "depends")]
    );
}

#[test]
fn rustls_with_both_providers_depends() {
    let r = json_on("rustls_both", &[]);
    assert_eq!(
        verdicts(&r, "rustls"),
        [pair("rustls-two-providers", "depends")]
    );
}

#[test]
fn rustls_before_0_23_22_has_no_pq_group() {
    let r = json_on("rustls_old", &[]);
    assert_eq!(
        verdicts(&r, "rustls"),
        [pair("rustls-aws-lc-rs-before-pq", "quantum-vulnerable")]
    );
}

#[test]
fn reqwest_0_13_defaults_do_not_prefer_post_quantum() {
    let r = json_on("reqwest013", &[]);
    assert_eq!(
        verdicts(&r, "rustls"),
        [pair("rustls-pq-not-preferred", "depends")]
    );
    // The saved metadata covers all targets, and reqwest only pulls rustls
    // in for non-wasm targets.
    let rustls = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["package"]["name"] == "rustls")
        .unwrap();
    assert!(!rustls["targets"].as_array().unwrap().is_empty());
}

#[test]
fn ureq_text_report_explains_ring_and_fix() {
    let out = run_on("ureq3", &[]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("TLS key exchange"), "{text}");
    assert!(
        text.contains("ring provider, no post-quantum groups"),
        "{text}"
    );
    assert!(
        text.contains("ureq selects ring unless a provider is installed"),
        "{text}"
    );
    assert!(text.contains("fix: "), "{text}");
    assert!(
        text.contains("via: p_ureq3 0.1.0 → ureq 3.5.2 → rustls 0.23.46"),
        "{text}"
    );
    assert!(
        !text.contains('\u{1b}'),
        "NO_COLOR output must not contain ANSI escapes"
    );
}

#[test]
fn fail_on_sets_the_exit_code() {
    let bad = run_on("ureq3", &["--fail-on", "vulnerable", "--format", "json"]);
    assert_eq!(bad.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("matched --fail-on"));

    let good = run_on(
        "rustls_default",
        &["--fail-on", "vulnerable", "--format", "json"],
    );
    assert_eq!(good.status.code(), Some(0));

    let depends = run_on(
        "rustls_default",
        &["--fail-on", "depends", "--format", "json"],
    );
    assert_eq!(
        depends.status.code(),
        Some(1),
        "aws-lc-rs and ring are `depends`"
    );
}

#[test]
fn known_vulnerable_ml_dsa_version_is_flagged() {
    let r = json_on("mldsa_old", &[]);
    assert_eq!(
        verdicts(&r, "ml-dsa"),
        [pair("ml-dsa-cve-2026-24850", "known-vulnerable")]
    );
    let f = &r["findings"][0];
    assert_eq!(f["advisory"]["id"], "CVE-2026-24850");
}

#[test]
fn mixed_project_covers_many_rules() {
    let r = json_on("mixed", &[]);
    assert_eq!(
        verdicts(&r, "openssl-src"),
        [pair("openssl-src-pq", "hybrid")]
    );
    assert_eq!(
        verdicts(&r, "jwt-simple"),
        [pair("jwt-simple-classical", "depends")]
    );
    assert_eq!(
        verdicts(&r, "jsonwebtoken"),
        [pair("jsonwebtoken", "depends")]
    );
    assert_eq!(
        verdicts(&r, "pqcrypto-kyber"),
        [pair("pqcrypto-kyber", "pre-standard-pq")]
    );
    assert_eq!(verdicts(&r, "md-5"), [pair("md-5", "classically-broken")]);
    assert_eq!(verdicts(&r, "rsa"), [pair("rsa", "quantum-vulnerable")]);
}

#[test]
fn dev_and_build_dependencies_are_opt_in() {
    let normal = json_on("scopes", &[]);
    assert!(
        verdicts(&normal, "rsa").is_empty(),
        "rsa is a dev-dependency"
    );
    assert!(
        verdicts(&normal, "md-5").is_empty(),
        "md-5 is a build-dependency"
    );
    assert_eq!(verdicts(&normal, "sha2"), [pair("sha2", "symmetric")]);

    let all = json_on("scopes", &["--include-dev", "--include-build"]);
    let scope_of = |name: &str| -> String {
        all["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["package"]["name"] == name)
            .map(|f| f["scope"].as_str().unwrap().to_string())
            .unwrap()
    };
    assert_eq!(scope_of("rsa"), "dev");
    assert_eq!(scope_of("md-5"), "build");
    assert_eq!(scope_of("sha2"), "normal");
}

#[test]
fn extra_rules_override_builtin_ones() {
    let dir = std::env::temp_dir().join(format!("cargo-cbom-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let rules = dir.join("extra.toml");
    std::fs::write(
        &rules,
        r#"
schema = 1
[[rule]]
id = "sha2"
crate = "sha2"
title = "SHA-2 (company policy)"
status = "depends"
note = "Overridden for the test."
reference = "https://example.org/policy"
"#,
    )
    .unwrap();
    let r = json_on("scopes", &["--rules", rules.to_str().unwrap()]);
    assert_eq!(verdicts(&r, "sha2"), [pair("sha2", "depends")]);
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn list_rules_prints_every_rule() {
    let out = run(&["--list-rules"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.lines().next().unwrap().ends_with(" rules"));
    assert!(text.contains("rustls-pq-not-preferred"));
}

#[test]
fn invoked_as_cargo_subcommand() {
    // `cargo cbom --list-rules` runs `cargo-cbom cbom --list-rules`.
    let out = run(&["cbom", "--list-rules"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn errors_exit_with_code_2() {
    let out = run(&["--metadata", "/definitely/not/here.json"]);
    assert_eq!(out.status.code(), Some(2));
}

fn schema_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/schema")
}

fn load_schema(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(schema_dir().join(name)).unwrap()).unwrap()
}

/// Serves the schemas that bom-1.6.schema.json references from tests/schema
/// (the official copies from github.com/CycloneDX/specification), so the
/// test never touches the network.
struct LocalSchemas;

impl jsonschema::Retrieve for LocalSchemas {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let name = match uri.as_str() {
            "http://cyclonedx.org/schema/spdx.schema.json" => "spdx.schema.json",
            "http://cyclonedx.org/schema/jsf-0.82.schema.json" => "jsf-0.82.schema.json",
            other => return Err(format!("unexpected schema reference {other}").into()),
        };
        Ok(load_schema(name))
    }
}

fn cbom_validator() -> jsonschema::Validator {
    jsonschema::options()
        .with_retriever(LocalSchemas)
        .build(&load_schema("bom-1.6.schema.json"))
        .expect("CycloneDX schema compiles")
}

#[test]
fn cbom_output_is_valid_cyclonedx_1_6() {
    let validator = cbom_validator();
    for name in [
        "rustls_default",
        "rustls_ring",
        "ureq3",
        "mldsa_old",
        "mixed",
        "reqwest013",
        "scopes",
    ] {
        let out = run_on(
            name,
            &["--format", "cbom", "--include-dev", "--include-build"],
        );
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let bom: Value = serde_json::from_slice(&out.stdout).unwrap();
        let errors: Vec<String> = validator
            .iter_errors(&bom)
            .map(|e| format!("{} at {}", e, e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{name}: {errors:#?}");

        // Every `provides` target is a crypto asset in the document.
        let refs: Vec<&str> = bom["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["bom-ref"].as_str().unwrap())
            .collect();
        for dep in bom["dependencies"].as_array().unwrap() {
            assert!(refs.contains(&dep["ref"].as_str().unwrap()));
            for p in dep["provides"].as_array().unwrap() {
                assert!(refs.contains(&p.as_str().unwrap()), "{name}: dangling {p}");
            }
        }
    }
}

#[test]
fn schema_check_is_not_vacuous() {
    let out = run_on("rustls_ring", &["--format", "cbom"]);
    let mut bom: Value = serde_json::from_slice(&out.stdout).unwrap();
    let asset = bom["components"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|c| c["type"] == "cryptographic-asset")
        .unwrap();
    asset["cryptoProperties"]["algorithmProperties"]["primitive"] = "not-a-primitive".into();
    assert!(!cbom_validator().is_valid(&bom));
}

#[test]
fn cbom_marks_quantum_vulnerable_algorithms_with_level_zero() {
    let out = run_on("rustls_ring", &["--format", "cbom"]);
    let bom: Value = serde_json::from_slice(&out.stdout).unwrap();
    let x25519 = bom["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "X25519")
        .expect("X25519 asset");
    assert_eq!(
        x25519["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"],
        0
    );
}

#[test]
fn cbom_output_is_deterministic() {
    for (name, extra) in [
        ("reqwest013", &[][..]),
        ("mixed", &["--include-dev", "--include-build"][..]),
        ("scopes", &["--include-dev", "--include-build"][..]),
    ] {
        let mut args = vec!["--format", "cbom"];
        args.extend_from_slice(extra);
        let first = run_on(name, &args).stdout;
        for _ in 0..5 {
            assert_eq!(run_on(name, &args).stdout, first, "{name}");
        }
    }
}
