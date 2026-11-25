//! Walks the resolved dependency graph from `cargo metadata`.

use crate::model::Scope;
use anyhow::{Context, Result};
use cargo_metadata::{DependencyKind, Metadata, Node, NodeDep, Package, PackageId, TargetKind};
use std::collections::{HashMap, VecDeque};

/// Which dependency kinds to follow besides normal dependencies.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScopeOptions {
    pub include_dev: bool,
    pub include_build: bool,
    /// Treat platform-specific edges as unconditional. Set this when the
    /// metadata was already filtered for one target (`--filter-platform`).
    pub ignore_platform_conditions: bool,
}

/// A package reached from a workspace member.
#[derive(Debug, Clone)]
pub struct Reached {
    pub scope: Scope,
    /// Package ids from a workspace member to this package, inclusive.
    pub path: Vec<PackageId>,
    /// Platform conditions (`cfg(...)` or target triples) on the path. Empty
    /// when the package is pulled in on every platform.
    pub targets: Vec<String>,
}

#[derive(Debug, Clone)]
struct Visit {
    scope: Scope,
    parent: Option<PackageId>,
    /// Platform condition of the edge from `parent`, if it is conditional.
    target: Option<String>,
}

/// Lookup tables over a `cargo metadata` result.
pub struct Graph<'m> {
    pub metadata: &'m Metadata,
    packages: HashMap<&'m PackageId, &'m Package>,
    nodes: HashMap<&'m PackageId, &'m Node>,
}

/// How an edge may be followed in a pass.
#[derive(Clone, Copy)]
enum Edge {
    Unconditional,
    Conditional,
}

impl<'m> Graph<'m> {
    pub fn new(metadata: &'m Metadata) -> Result<Self> {
        let resolve = metadata.resolve.as_ref().context(
            "`cargo metadata` output has no dependency graph (it must be produced without --no-deps)",
        )?;
        Ok(Self {
            metadata,
            packages: metadata.packages.iter().map(|p| (&p.id, p)).collect(),
            nodes: resolve.nodes.iter().map(|n| (&n.id, n)).collect(),
        })
    }

    pub fn package(&self, id: &PackageId) -> Option<&'m Package> {
        self.packages.get(id).copied()
    }

    pub fn node(&self, id: &PackageId) -> Option<&'m Node> {
        self.nodes.get(id).copied()
    }

    fn is_proc_macro(&self, id: &PackageId) -> bool {
        self.package(id).is_some_and(|p| {
            p.targets
                .iter()
                .any(|t| t.kind.contains(&TargetKind::ProcMacro))
        })
    }

    fn deps(&self, id: &PackageId) -> &'m [NodeDep] {
        self.node(id).map(|n| n.deps.as_slice()).unwrap_or(&[])
    }

    /// Every package reachable from the workspace members, with the best scope
    /// it is reachable in (normal > dev > build), preferring paths that apply
    /// on every platform, and a shortest such path.
    pub fn reachable(&self, opts: ScopeOptions) -> HashMap<PackageId, Reached> {
        let members = &self.metadata.workspace_members;
        let mut visits: HashMap<PackageId, Visit> = HashMap::new();
        let ignore = opts.ignore_platform_conditions;

        // Pass 1: what ships. Normal edges only; proc-macros run at compile
        // time, so they are left for the build pass.
        for m in members {
            visits.insert(
                m.clone(),
                Visit {
                    scope: Scope::Normal,
                    parent: None,
                    target: None,
                },
            );
        }
        let normal = |g: &Self, d: &NodeDep| -> Vec<Option<String>> {
            if g.is_proc_macro(&d.pkg) {
                Vec::new()
            } else {
                kinds(d, &[DependencyKind::Normal], ignore)
            }
        };
        self.walk(members.to_vec(), Scope::Normal, &mut visits, normal);

        // Pass 2: test-only code reached through members' dev-dependencies.
        if opts.include_dev {
            let mut seeds = Vec::new();
            for edge in [Edge::Unconditional, Edge::Conditional] {
                for m in members {
                    for d in self.deps(m) {
                        if visits.contains_key(&d.pkg) {
                            continue;
                        }
                        if let Some(target) =
                            pick(&kinds(d, &[DependencyKind::Development], ignore), edge)
                        {
                            visits.insert(
                                d.pkg.clone(),
                                Visit {
                                    scope: Scope::Dev,
                                    parent: Some(m.clone()),
                                    target,
                                },
                            );
                            seeds.push(d.pkg.clone());
                        }
                    }
                }
            }
            self.walk(seeds, Scope::Dev, &mut visits, normal);
        }

        // Pass 3: compile-time only code (build-dependencies, proc-macros and
        // everything they pull in).
        if opts.include_build {
            // Sorted so that the chosen paths do not depend on hash order.
            let mut reached: Vec<PackageId> = visits.keys().cloned().collect();
            reached.sort_by(|a, b| a.repr.cmp(&b.repr));
            let mut seeds = Vec::new();
            for edge in [Edge::Unconditional, Edge::Conditional] {
                for id in &reached {
                    for d in self.deps(id) {
                        if visits.contains_key(&d.pkg) {
                            continue;
                        }
                        let mut options = kinds(d, &[DependencyKind::Build], ignore);
                        if self.is_proc_macro(&d.pkg) {
                            options.extend(kinds(d, &[DependencyKind::Normal], ignore));
                        }
                        if let Some(target) = pick(&options, edge) {
                            visits.insert(
                                d.pkg.clone(),
                                Visit {
                                    scope: Scope::Build,
                                    parent: Some(id.clone()),
                                    target,
                                },
                            );
                            seeds.push(d.pkg.clone());
                        }
                    }
                }
            }
            self.walk(seeds, Scope::Build, &mut visits, |_, d| {
                kinds(d, &[DependencyKind::Normal, DependencyKind::Build], ignore)
            });
        }

        visits
            .keys()
            .map(|id| {
                let scope = visits[id].scope;
                let mut path = vec![id.clone()];
                let mut targets = Vec::new();
                let mut cur = id;
                while let Some(visit) = visits.get(cur) {
                    if let Some(t) = &visit.target {
                        targets.push(t.clone());
                    }
                    match &visit.parent {
                        Some(p) => {
                            path.push(p.clone());
                            cur = p;
                        }
                        None => break,
                    }
                }
                path.reverse();
                targets.reverse();
                (
                    id.clone(),
                    Reached {
                        scope,
                        path,
                        targets,
                    },
                )
            })
            .collect()
    }

    /// Breadth-first walk from `seeds`. Unconditional edges are exhausted
    /// before platform-specific ones, so a package that is pulled in on every
    /// platform is never reported as platform-specific.
    fn walk(
        &self,
        seeds: Vec<PackageId>,
        scope: Scope,
        visits: &mut HashMap<PackageId, Visit>,
        edge_targets: impl Fn(&Self, &NodeDep) -> Vec<Option<String>>,
    ) {
        let mut frontier = seeds;
        for edge in [Edge::Unconditional, Edge::Conditional] {
            if matches!(edge, Edge::Conditional) {
                // Re-explore everything reached in this pass, now allowing
                // conditional edges.
                frontier = visits
                    .iter()
                    .filter(|(_, v)| v.scope == scope)
                    .map(|(id, _)| id.clone())
                    .collect();
                frontier.sort_by(|a, b| a.repr.cmp(&b.repr));
            }
            let mut queue: VecDeque<PackageId> = frontier.iter().cloned().collect();
            while let Some(id) = queue.pop_front() {
                for d in self.deps(&id) {
                    if visits.contains_key(&d.pkg) {
                        continue;
                    }
                    if let Some(target) = pick(&edge_targets(self, d), edge) {
                        visits.insert(
                            d.pkg.clone(),
                            Visit {
                                scope,
                                parent: Some(id.clone()),
                                target,
                            },
                        );
                        queue.push_back(d.pkg.clone());
                    }
                }
            }
        }
    }
}

/// Platform conditions of the dependency kinds of an edge that match `wanted`
/// (`None` means "on every platform").
fn kinds(dep: &NodeDep, wanted: &[DependencyKind], ignore_targets: bool) -> Vec<Option<String>> {
    dep.dep_kinds
        .iter()
        .filter(|k| wanted.contains(&k.kind))
        .map(|k| {
            if ignore_targets {
                None
            } else {
                k.target.as_ref().map(|t| t.to_string())
            }
        })
        .collect()
}

/// Decide whether an edge can be followed in this phase. Returns the edge's
/// platform condition (`Some(None)` = unconditional).
fn pick(options: &[Option<String>], edge: Edge) -> Option<Option<String>> {
    if options.is_empty() {
        return None;
    }
    if options.iter().any(Option::is_none) {
        return Some(None);
    }
    match edge {
        Edge::Unconditional => None,
        Edge::Conditional => {
            let mut conds: Vec<&str> = options.iter().flatten().map(String::as_str).collect();
            conds.sort_unstable();
            conds.dedup();
            Some(Some(conds.join(" or ")))
        }
    }
}
