//! CycloneDX 1.6 Cryptography Bill of Materials.
//!
//! Output is deterministic (no serial number or timestamp, sorted arrays) so
//! a committed `cbom.json` gives clean diffs.

use crate::analyze::{PackageRef, Report};
use crate::model::Status;
use crate::rules::Algorithm;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

const PROPERTY_PREFIX: &str = "cargo-cbom";

fn bom_ref_for_package(p: &PackageRef) -> String {
    if let Some(purl) = &p.purl {
        return purl.clone();
    }
    // Local path packages (e.g. workspace members): do not leak the
    // absolute path of the machine that produced the CBOM.
    if p.id.starts_with("path+") {
        return format!("cargo:path/{}@{}", p.name, p.version);
    }
    format!("cargo:{}", p.id)
}

fn slug(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

fn bom_ref_for_algorithm(a: &Algorithm) -> String {
    let mut r = format!("crypto/algorithm/{}/{}", slug(&a.name), a.primitive);
    if let Some(p) = &a.parameter_set {
        r.push('/');
        r.push_str(&slug(p));
    }
    r
}

fn property(name: &str, value: impl Into<String>) -> Value {
    json!({ "name": format!("{PROPERTY_PREFIX}:{name}"), "value": value.into() })
}

fn package_component(p: &PackageRef, kind: &str) -> Map<String, Value> {
    let mut c = Map::new();
    c.insert("type".into(), json!(kind));
    c.insert("bom-ref".into(), json!(bom_ref_for_package(p)));
    c.insert("name".into(), json!(p.name));
    c.insert("version".into(), json!(p.version));
    if let Some(purl) = &p.purl {
        c.insert("purl".into(), json!(purl));
    }
    c
}

fn algorithm_component(a: &Algorithm, status: Status) -> Value {
    let mut props = Map::new();
    props.insert("primitive".into(), json!(a.primitive));
    if let Some(p) = &a.parameter_set {
        props.insert("parameterSetIdentifier".into(), json!(p));
    }
    props.insert("executionEnvironment".into(), json!("software-plain-ram"));
    props.insert("implementationPlatform".into(), json!("generic"));
    if !a.functions.is_empty() {
        props.insert("cryptoFunctions".into(), json!(a.functions));
    }
    let level = a.nist_level.or(match status {
        Status::QuantumVulnerable | Status::ClassicallyBroken => Some(0),
        _ => None,
    });
    if let Some(level) = level {
        props.insert("nistQuantumSecurityLevel".into(), json!(level));
    }
    json!({
        "type": "cryptographic-asset",
        "bom-ref": bom_ref_for_algorithm(a),
        "name": a.name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": Value::Object(props),
        },
        "properties": [property("quantum-status", status.as_str())],
    })
}

/// Builds the CycloneDX document.
pub fn to_cyclonedx(report: &Report) -> Value {
    // Root component: the single workspace member, or the workspace itself.
    let root = match report.roots.as_slice() {
        [one] => Value::Object(package_component(one, one.kind)),
        _ => json!({
            "type": "application",
            "bom-ref": format!("cargo-workspace:{}", report.workspace),
            "name": report.workspace,
        }),
    };

    // Libraries that matched a rule, keyed by bom-ref.
    let mut libraries: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut lib_props: BTreeMap<String, BTreeSet<(String, String)>> = BTreeMap::new();
    // Algorithm assets, deduplicated across crates; keep the worst status.
    let mut assets: BTreeMap<String, (Algorithm, Status)> = BTreeMap::new();
    let mut provides: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for f in &report.findings {
        let lib_ref = bom_ref_for_package(&f.package);
        libraries
            .entry(lib_ref.clone())
            .or_insert_with(|| package_component(&f.package, "library"));
        let props = lib_props.entry(lib_ref.clone()).or_default();
        props.insert(("rule".into(), f.rule.clone()));
        props.insert(("verdict".into(), format!("{}: {}", f.rule, f.status)));
        props.insert(("scope".into(), f.scope.to_string()));
        props.insert(("path".into(), f.path.join(" -> ")));

        for a in &f.algorithms {
            let asset_ref = bom_ref_for_algorithm(a);
            assets
                .entry(asset_ref.clone())
                .and_modify(|(_, s)| *s = (*s).min(a.status))
                .or_insert_with(|| (a.clone(), a.status));
            provides
                .entry(lib_ref.clone())
                .or_default()
                .insert(asset_ref);
        }
    }

    let mut components: Vec<Value> = libraries
        .into_iter()
        .map(|(lib_ref, mut c)| {
            let props: Vec<Value> = lib_props
                .remove(&lib_ref)
                .unwrap_or_default()
                .into_iter()
                .map(|(k, v)| property(&k, v))
                .collect();
            c.insert("properties".into(), Value::Array(props));
            Value::Object(c)
        })
        .collect();
    components.extend(assets.values().map(|(a, s)| algorithm_component(a, *s)));

    let dependencies: Vec<Value> = provides
        .into_iter()
        .map(|(lib_ref, assets)| json!({ "ref": lib_ref, "provides": assets }))
        .collect();

    json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [{
                    "type": "application",
                    "name": report.tool.name,
                    "version": report.tool.version,
                }]
            },
            "component": root,
            "properties": [
                property("scopes", report.scopes.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")),
                property("packages-scanned", report.packages_scanned.to_string()),
            ],
        },
        "components": components,
        "dependencies": dependencies,
    })
}

#[cfg(test)]
mod tests {
    use super::slug;

    #[test]
    fn slugs_are_stable() {
        assert_eq!(slug("ECDSA (P-256)"), "ecdsa-p-256");
        assert_eq!(slug("X25519MLKEM768"), "x25519mlkem768");
        assert_eq!(slug("  RSA  "), "rsa");
    }
}
