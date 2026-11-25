//! Turns a dependency graph and a rule set into a report.

use crate::graph::{Graph, ScopeOptions};
use crate::model::{Category, Scope, Status};
use crate::rules::{Advisory, Algorithm, RuleSet};
use anyhow::Result;
use cargo_metadata::{Metadata, Package, TargetKind};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// A package as it appears in reports.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct PackageRef {
    pub name: String,
    pub version: String,
    /// Package URL for crates.io packages (`pkg:cargo/name@version`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// `application` if the package has a binary target, otherwise `library`.
    #[serde(skip)]
    pub kind: &'static str,
    /// Cargo's package id (unique within the graph).
    pub id: String,
}

impl PackageRef {
    fn from_package(p: &Package) -> Self {
        let from_crates_io = p.source.as_ref().is_some_and(|s| s.is_crates_io());
        let is_bin = p.targets.iter().any(|t| t.kind.contains(&TargetKind::Bin));
        Self {
            name: p.name.to_string(),
            version: p.version.to_string(),
            purl: from_crates_io.then(|| format!("pkg:cargo/{}@{}", p.name, p.version)),
            kind: if is_bin { "application" } else { "library" },
            id: p.id.repr.clone(),
        }
    }

    pub fn label(&self) -> String {
        format!("{} {}", self.name, self.version)
    }
}

/// One rule that matched one package.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: String,
    pub title: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<Category>,
    pub package: PackageRef,
    pub scope: Scope,
    /// `true` when a workspace member depends on the package directly.
    pub direct: bool,
    /// `name version` entries from a workspace member to the package.
    pub path: Vec<String>,
    /// Platform conditions on that path; empty if pulled in on every platform.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub algorithms: Vec<Algorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory: Option<Advisory>,
    pub reference: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolInfo {
    pub name: &'static str,
    pub version: &'static str,
}

/// Everything a report format needs.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub tool: ToolInfo,
    /// Name of the workspace root directory.
    pub workspace: String,
    /// Workspace members the scan started from.
    pub roots: Vec<PackageRef>,
    pub scopes: Vec<Scope>,
    /// Target triple the dependency graph was filtered for; `None` means all
    /// platforms.
    pub target: Option<String>,
    /// Number of packages reached in the selected scopes.
    pub packages_scanned: usize,
    pub rules_evaluated: usize,
    pub findings: Vec<Finding>,
    pub summary: BTreeMap<Status, usize>,
}

impl Report {
    /// Findings whose status is in `statuses`.
    pub fn matching<'a>(
        &'a self,
        statuses: &'a BTreeSet<Status>,
    ) -> impl Iterator<Item = &'a Finding> {
        self.findings
            .iter()
            .filter(|f| statuses.contains(&f.status))
    }
}

pub fn analyze(metadata: &Metadata, rules: &RuleSet, opts: ScopeOptions) -> Result<Report> {
    let graph = Graph::new(metadata)?;
    let reached = graph.reachable(opts);

    let label = |id: &cargo_metadata::PackageId| {
        graph
            .package(id)
            .map(|p| format!("{} {}", p.name, p.version))
            .unwrap_or_else(|| id.repr.clone())
    };

    let mut findings = Vec::new();
    for (id, how) in &reached {
        let Some(pkg) = graph.package(id) else {
            continue;
        };
        let features: BTreeSet<String> = graph
            .node(id)
            .map(|n| n.features.iter().map(|f| f.to_string()).collect())
            .unwrap_or_default();
        for rule in rules.evaluate(&pkg.name, &pkg.version, &features) {
            findings.push(Finding {
                rule: rule.id.clone(),
                title: rule.title.clone(),
                status: rule.status,
                category: rule.category,
                package: PackageRef::from_package(pkg),
                scope: how.scope,
                direct: how.path.len() == 2,
                path: how.path.iter().map(&label).collect(),
                targets: how.targets.clone(),
                evidence: rule.evidence(&pkg.version, &features),
                algorithms: rule.algorithms.clone(),
                note: rule.note.clone(),
                fix: rule.fix.clone(),
                advisory: rule.advisory.clone(),
                reference: rule.reference.clone(),
            });
        }
    }
    findings.sort_by(|a, b| {
        (
            a.status,
            &a.package.name,
            &a.package.version,
            a.scope,
            &a.rule,
        )
            .cmp(&(
                b.status,
                &b.package.name,
                &b.package.version,
                b.scope,
                &b.rule,
            ))
    });

    let mut summary = BTreeMap::new();
    for f in &findings {
        *summary.entry(f.status).or_insert(0) += 1;
    }

    let mut roots: Vec<PackageRef> = metadata
        .workspace_members
        .iter()
        .filter_map(|id| graph.package(id))
        .map(PackageRef::from_package)
        .collect();
    roots.sort();

    let mut scopes = vec![Scope::Normal];
    if opts.include_dev {
        scopes.push(Scope::Dev);
    }
    if opts.include_build {
        scopes.push(Scope::Build);
    }

    Ok(Report {
        tool: ToolInfo {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        workspace: metadata
            .workspace_root
            .file_name()
            .unwrap_or("workspace")
            .to_string(),
        roots,
        scopes,
        target: None,
        packages_scanned: reached.len(),
        rules_evaluated: rules.len(),
        findings,
        summary,
    })
}
