//! Rule model, loading and matching.
//!
//! Rules are plain TOML (see `rules/rules.toml`). Each rule targets one crate
//! and can be narrowed by version range and by the features Cargo actually
//! enabled for that crate. Rules that share a `group` are evaluated in file
//! order and only the first match in a group applies, which keeps mutually
//! exclusive verdicts (for example the rustls provider rules) simple to write.

use crate::model::{Category, CryptoFunction, Primitive, Status};
use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};

/// The rules shipped with the binary.
pub const BUILTIN_RULES: &str = include_str!("../rules/rules.toml");

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    schema: u32,
    #[serde(default, rename = "rule")]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    #[serde(rename = "crate")]
    crate_name: String,
    title: String,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    category: Option<Category>,
    #[serde(default)]
    versions: Option<String>,
    #[serde(default)]
    features_all: Vec<String>,
    #[serde(default)]
    features_any: Vec<String>,
    #[serde(default)]
    features_none: Vec<String>,
    #[serde(default)]
    status: Option<Status>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    fix: Option<String>,
    #[serde(default)]
    advisory: Option<Advisory>,
    reference: String,
    #[serde(default)]
    algorithms: Vec<Algorithm>,
}

/// An algorithm a crate provides. `status` describes the algorithm itself;
/// the rule's status describes the situation in the project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Algorithm {
    pub name: String,
    pub primitive: Primitive,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<CryptoFunction>,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter_set: Option<String>,
    /// NIST post-quantum security category (0-6). Quantum-vulnerable
    /// algorithms default to 0 in the CBOM when this is not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nist_level: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advisory {
    pub id: String,
    pub url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
}

/// A comma-separated list of comparisons such as `>=0.23.22, <0.24.0-0`.
///
/// Unlike `semver::VersionReq`, pre-release versions are compared with the
/// normal semver precedence, so `0.1.0-rc.3` satisfies `<0.1.0-rc.4` and
/// `0.14.0-rc.1` satisfies `>=0.13.0`. Build metadata is ignored.
#[derive(Debug, Clone)]
pub struct VersionConstraint {
    raw: String,
    bounds: Vec<(Op, Version)>,
}

impl VersionConstraint {
    pub fn parse(raw: &str) -> Result<Self> {
        let mut bounds = Vec::new();
        for part in raw.split(',') {
            let part = part.trim();
            ensure!(
                !part.is_empty(),
                "empty comparison in version range `{raw}`"
            );
            let (op, rest) = if let Some(r) = part.strip_prefix(">=") {
                (Op::Ge, r)
            } else if let Some(r) = part.strip_prefix("<=") {
                (Op::Le, r)
            } else if let Some(r) = part.strip_prefix('>') {
                (Op::Gt, r)
            } else if let Some(r) = part.strip_prefix('<') {
                (Op::Lt, r)
            } else if let Some(r) = part.strip_prefix('=') {
                (Op::Eq, r)
            } else {
                bail!(
                    "`{part}` in version range `{raw}` must start with one of >=, <=, >, <, = \
                     and use a full version such as 0.23.22"
                );
            };
            let version = Version::parse(rest.trim())
                .with_context(|| format!("invalid version `{}` in range `{raw}`", rest.trim()))?;
            bounds.push((op, version));
        }
        Ok(Self {
            raw: raw.to_string(),
            bounds,
        })
    }

    pub fn matches(&self, version: &Version) -> bool {
        self.bounds.iter().all(|(op, bound)| {
            let ord = precedence(version, bound);
            match op {
                Op::Lt => ord == Ordering::Less,
                Op::Le => ord != Ordering::Greater,
                Op::Gt => ord == Ordering::Greater,
                Op::Ge => ord != Ordering::Less,
                Op::Eq => ord == Ordering::Equal,
            }
        })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

/// Semver precedence: compares major, minor, patch and pre-release, ignoring
/// build metadata (so `300.5.0+3.5.0` equals `300.5.0`).
fn precedence(a: &Version, b: &Version) -> Ordering {
    (a.major, a.minor, a.patch)
        .cmp(&(b.major, b.minor, b.patch))
        .then_with(|| match (a.pre.is_empty(), b.pre.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => a.pre.cmp(&b.pre),
        })
}

/// A validated rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub crate_name: String,
    pub title: String,
    pub group: Option<String>,
    pub category: Option<Category>,
    pub versions: Option<VersionConstraint>,
    pub features_all: Vec<String>,
    pub features_any: Vec<String>,
    pub features_none: Vec<String>,
    /// Verdict for the project: explicit, or the worst algorithm status.
    pub status: Status,
    pub note: Option<String>,
    pub fix: Option<String>,
    pub advisory: Option<Advisory>,
    pub reference: String,
    pub algorithms: Vec<Algorithm>,
}

impl Rule {
    /// Does this rule apply to a package with this name, version and set of
    /// enabled features?
    pub fn matches(&self, name: &str, version: &Version, features: &BTreeSet<String>) -> bool {
        self.crate_name == name
            && self.versions.as_ref().is_none_or(|v| v.matches(version))
            && self.features_all.iter().all(|f| features.contains(f))
            && (self.features_any.is_empty()
                || self.features_any.iter().any(|f| features.contains(f)))
            && self.features_none.iter().all(|f| !features.contains(f))
    }

    /// Human-readable explanation of why the rule matched.
    pub fn evidence(&self, version: &Version, features: &BTreeSet<String>) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(v) = &self.versions {
            out.push(format!("version {version} matches `{}`", v.as_str()));
        }
        let enabled: Vec<&str> = self
            .features_all
            .iter()
            .chain(self.features_any.iter())
            .filter(|f| features.contains(*f))
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if !enabled.is_empty() {
            out.push(format!("enabled features: {}", enabled.join(", ")));
        }
        if !self.features_none.is_empty() {
            out.push(format!("not enabled: {}", self.features_none.join(", ")));
        }
        out
    }

    fn from_raw(raw: RawRule) -> Result<Self> {
        let id = raw.id;
        ensure!(
            !id.is_empty()
                && id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "rule id `{id}` must be non-empty and use only a-z, 0-9 and -"
        );
        ensure!(!raw.crate_name.is_empty(), "rule `{id}`: `crate` is empty");
        ensure!(!raw.title.is_empty(), "rule `{id}`: `title` is empty");
        ensure!(
            raw.reference.starts_with("https://"),
            "rule `{id}`: `reference` must be an https:// URL"
        );
        for f in raw
            .features_all
            .iter()
            .chain(&raw.features_any)
            .chain(&raw.features_none)
        {
            ensure!(!f.is_empty(), "rule `{id}`: empty feature name");
        }
        for a in &raw.algorithms {
            ensure!(!a.name.is_empty(), "rule `{id}`: algorithm with empty name");
            if let Some(level) = a.nist_level {
                ensure!(
                    level <= 6,
                    "rule `{id}`: nist_level must be 0-6, got {level}"
                );
            }
        }
        if let Some(adv) = &raw.advisory {
            ensure!(
                adv.url.starts_with("https://"),
                "rule `{id}`: advisory url must be https://"
            );
        }
        let versions = raw
            .versions
            .as_deref()
            .map(VersionConstraint::parse)
            .transpose()
            .with_context(|| format!("rule `{id}`"))?;
        let status = match raw.status {
            Some(s) => s,
            None => raw
                .algorithms
                .iter()
                .map(|a| a.status)
                .min()
                .with_context(|| {
                    format!("rule `{id}`: set `status` or list at least one algorithm")
                })?,
        };
        Ok(Self {
            id,
            crate_name: raw.crate_name,
            title: raw.title,
            group: raw.group,
            category: raw.category,
            versions,
            features_all: raw.features_all,
            features_any: raw.features_any,
            features_none: raw.features_none,
            status,
            note: raw.note,
            fix: raw.fix,
            advisory: raw.advisory,
            reference: raw.reference,
            algorithms: raw.algorithms,
        })
    }
}

/// An ordered, validated collection of rules.
#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// The rules embedded in the binary.
    pub fn builtin() -> Result<Self> {
        Self::from_toml(BUILTIN_RULES).context("built-in rules are invalid")
    }

    pub fn from_toml(src: &str) -> Result<Self> {
        let file: RuleFile = toml::from_str(src).context("could not parse rules TOML")?;
        ensure!(
            file.schema == SCHEMA_VERSION,
            "unsupported rules schema {} (expected {SCHEMA_VERSION})",
            file.schema
        );
        let rules = file
            .rules
            .into_iter()
            .map(Rule::from_raw)
            .collect::<Result<Vec<_>>>()?;
        let set = Self { rules };
        set.validate()?;
        Ok(set)
    }

    /// Add rules from another set. A rule with an existing id replaces the
    /// old one in place; new ids are appended.
    pub fn extend(&mut self, other: RuleSet) -> Result<()> {
        let index: HashMap<String, usize> = self
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| (r.id.clone(), i))
            .collect();
        for rule in other.rules {
            match index.get(&rule.id) {
                Some(&i) => self.rules[i] = rule,
                None => self.rules.push(rule),
            }
        }
        self.validate()
    }

    fn validate(&self) -> Result<()> {
        let mut ids = HashSet::new();
        let mut group_crate: HashMap<&str, &str> = HashMap::new();
        for rule in &self.rules {
            ensure!(
                ids.insert(rule.id.as_str()),
                "duplicate rule id `{}`",
                rule.id
            );
            if let Some(group) = &rule.group {
                let crate_name = group_crate.entry(group).or_insert(&rule.crate_name);
                ensure!(
                    *crate_name == rule.crate_name,
                    "group `{group}` mixes crates `{crate_name}` and `{}`",
                    rule.crate_name
                );
            }
        }
        Ok(())
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// All rules that apply to a package. Within a group only the first
    /// matching rule (in file order) is returned.
    pub fn evaluate(
        &self,
        name: &str,
        version: &Version,
        features: &BTreeSet<String>,
    ) -> Vec<&Rule> {
        let mut seen_groups = HashSet::new();
        let mut out = Vec::new();
        for rule in &self.rules {
            if rule.crate_name != name {
                continue;
            }
            if let Some(group) = &rule.group {
                if seen_groups.contains(group.as_str()) {
                    continue;
                }
                if rule.matches(name, version, features) {
                    seen_groups.insert(group.as_str());
                    out.push(rule);
                }
            } else if rule.matches(name, version, features) {
                out.push(rule);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn feats(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn builtin_rules_are_valid() {
        let rules = RuleSet::builtin().unwrap();
        assert!(rules.len() > 40, "expected a useful number of rules");
    }

    #[test]
    fn prerelease_versions_use_semver_precedence() {
        let c = VersionConstraint::parse(">=0.0.4, <0.1.0-rc.4").unwrap();
        assert!(c.matches(&v("0.0.4")));
        assert!(c.matches(&v("0.1.0-pre.2")));
        assert!(c.matches(&v("0.1.0-rc.3")));
        assert!(!c.matches(&v("0.1.0-rc.4")));
        assert!(!c.matches(&v("0.1.0")));
        assert!(!c.matches(&v("0.1.2")));
        assert!(!c.matches(&v("0.0.3")));

        let next = VersionConstraint::parse(">=0.24.0-0").unwrap();
        assert!(next.matches(&v("0.24.0-dev.3")));
        assert!(!next.matches(&v("0.23.46")));

        let ge = VersionConstraint::parse(">=0.13.0").unwrap();
        assert!(ge.matches(&v("0.14.0-rc.1")));
    }

    #[test]
    fn build_metadata_is_ignored() {
        let c = VersionConstraint::parse(">=300.5.0").unwrap();
        assert!(c.matches(&v("300.5.0+3.5.0")));
        assert!(c.matches(&v("400.0.2+4.0.3")));
        assert!(!c.matches(&v("300.4.2+3.4.1")));
    }

    #[test]
    fn rejects_incomplete_or_unknown_comparisons() {
        assert!(VersionConstraint::parse("^0.23").is_err());
        assert!(VersionConstraint::parse(">=0.23").is_err());
        assert!(VersionConstraint::parse(">=0.23.0,").is_err());
    }

    #[test]
    fn groups_take_the_first_match_only() {
        let rules = RuleSet::from_toml(
            r#"
schema = 1

[[rule]]
id = "a-first"
crate = "demo"
title = "first"
group = "demo"
features_all = ["x"]
status = "hybrid"
reference = "https://example.org"

[[rule]]
id = "a-fallback"
crate = "demo"
title = "fallback"
group = "demo"
status = "depends"
reference = "https://example.org"

[[rule]]
id = "a-always"
crate = "demo"
title = "always"
status = "symmetric"
reference = "https://example.org"
"#,
        )
        .unwrap();
        let ids = |f: &[&str]| -> Vec<String> {
            rules
                .evaluate("demo", &v("1.0.0"), &feats(f))
                .iter()
                .map(|r| r.id.clone())
                .collect()
        };
        assert_eq!(ids(&["x"]), ["a-first", "a-always"]);
        assert_eq!(ids(&[]), ["a-fallback", "a-always"]);
    }

    #[test]
    fn status_defaults_to_worst_algorithm() {
        let rules = RuleSet::from_toml(
            r#"
schema = 1
[[rule]]
id = "mixed"
crate = "demo"
title = "mixed"
reference = "https://example.org"
algorithms = [
  { name = "ML-KEM-768", primitive = "kem", status = "post-quantum" },
  { name = "X25519", primitive = "key-agree", status = "quantum-vulnerable" },
]
"#,
        )
        .unwrap();
        assert_eq!(rules.rules()[0].status, Status::QuantumVulnerable);
    }

    #[test]
    fn extend_replaces_by_id_and_appends_new_rules() {
        let mut base = RuleSet::builtin().unwrap();
        let before = base.len();
        let extra = RuleSet::from_toml(
            r#"
schema = 1
[[rule]]
id = "rsa"
crate = "rsa"
title = "overridden"
status = "depends"
reference = "https://example.org"

[[rule]]
id = "my-internal-crypto"
crate = "my-internal-crypto"
title = "Internal crypto wrapper"
status = "depends"
reference = "https://example.org"
"#,
        )
        .unwrap();
        base.extend(extra).unwrap();
        assert_eq!(base.len(), before + 1);
        let rsa = base.rules().iter().find(|r| r.id == "rsa").unwrap();
        assert_eq!(rsa.title, "overridden");
    }

    #[test]
    fn rejects_duplicate_ids_and_mixed_groups() {
        let dup = r#"
schema = 1
[[rule]]
id = "x"
crate = "a"
title = "t"
status = "depends"
reference = "https://example.org"
[[rule]]
id = "x"
crate = "b"
title = "t"
status = "depends"
reference = "https://example.org"
"#;
        assert!(RuleSet::from_toml(dup).is_err());

        let mixed = r#"
schema = 1
[[rule]]
id = "x"
crate = "a"
group = "g"
title = "t"
status = "depends"
reference = "https://example.org"
[[rule]]
id = "y"
crate = "b"
group = "g"
title = "t"
status = "depends"
reference = "https://example.org"
"#;
        assert!(RuleSet::from_toml(mixed).is_err());
    }
}
