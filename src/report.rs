//! Human-readable text report.

use crate::analyze::{Finding, Report};
use crate::model::{Category, Scope, Status};
use crate::rules::Algorithm;
use anstyle::{AnsiColor, Style};
use std::io::{self, Write};

const RED: Style = AnsiColor::Red.on_default().bold();
const YELLOW: Style = AnsiColor::Yellow.on_default().bold();
const GREEN: Style = AnsiColor::Green.on_default().bold();
const BOLD: Style = Style::new().bold();
const DIM: Style = Style::new().dimmed();

fn status_style(status: Status) -> Style {
    if status.is_problem() {
        RED
    } else if status.is_warning() {
        YELLOW
    } else {
        GREEN
    }
}

/// Statuses shown as a compact one-line list instead of full entries.
fn is_compact(status: Status) -> bool {
    matches!(status, Status::Symmetric)
}

/// Writes the report with ANSI styles; wrap `out` in an `anstream` stream
/// to strip them when the destination is not a color terminal.
pub fn write_text(report: &Report, out: &mut dyn Write) -> io::Result<()> {
    let project = match report.roots.as_slice() {
        [one] => one.label(),
        [] => report.workspace.clone(),
        many => format!("{} ({} workspace members)", report.workspace, many.len()),
    };
    let scopes: Vec<&str> = report.scopes.iter().map(|s| s.as_str()).collect();
    writeln!(
        out,
        "{BOLD}{} {}{BOLD:#} · post-quantum readiness of {BOLD}{project}{BOLD:#}",
        report.tool.name, report.tool.version
    )?;
    let target = match &report.target {
        Some(t) => format!("target {t}"),
        None => "all targets".to_string(),
    };
    writeln!(
        out,
        "{DIM}{} packages scanned ({} dependencies, {target}) · {} rules{DIM:#}",
        report.packages_scanned,
        scopes.join(" + "),
        report.rules_evaluated
    )?;

    write_headline(report, out)?;

    if report.findings.is_empty() {
        writeln!(out)?;
        writeln!(out, "No known cryptographic crates found.")?;
        return Ok(());
    }

    for status in Status::ALL {
        let group: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.status == status)
            .collect();
        if group.is_empty() {
            continue;
        }
        let style = status_style(status);
        writeln!(out)?;
        if is_compact(status) {
            let names: Vec<String> = group.iter().map(|f| entry_label(f)).collect();
            writeln!(
                out,
                "{style}{} {} ({}){style:#}: {}",
                status.symbol(),
                status.heading(),
                group.len(),
                names.join(", ")
            )?;
            continue;
        }
        writeln!(
            out,
            "{style}{} {} ({}){style:#}",
            status.symbol(),
            status.heading(),
            group.len()
        )?;
        for f in group {
            write_entry(out, f)?;
        }
    }

    writeln!(out)?;
    let parts: Vec<String> = Status::ALL
        .iter()
        .filter_map(|s| {
            report.summary.get(s).map(|n| {
                let style = status_style(*s);
                format!("{style}{n} {}{style:#}", s.as_str())
            })
        })
        .collect();
    writeln!(out, "{BOLD}Summary:{BOLD:#} {}", parts.join(" · "))?;
    writeln!(
        out,
        "{DIM}Based on the resolved dependency graph and enabled Cargo features: it shows which \
         algorithms are compiled in, not which ones your code calls.{DIM:#}"
    )?;
    if report.findings.iter().any(|f| !f.targets.is_empty()) {
        writeln!(
            out,
            "{DIM}Entries marked (platform-specific) are only pulled in for some targets; \
             use --target <TRIPLE> to check one platform.{DIM:#}"
        )?;
    }
    Ok(())
}

/// One line per TLS finding: the answer to "is my TLS post-quantum?".
fn write_headline(report: &Report, out: &mut dyn Write) -> io::Result<()> {
    let tls: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.category == Some(Category::Tls))
        .collect();
    writeln!(out)?;
    if tls.is_empty() {
        writeln!(
            out,
            "{BOLD}{}:{BOLD:#} no supported TLS library found (rustls, OpenSSL, BoringSSL, native-tls)",
            Category::Tls.label()
        )?;
        return Ok(());
    }
    writeln!(out, "{BOLD}{}{BOLD:#}", Category::Tls.label())?;
    let width = tls
        .iter()
        .map(|f| entry_label(f).chars().count())
        .max()
        .unwrap_or(0);
    for f in tls {
        let style = status_style(f.status);
        let label = entry_label(f);
        let pad = width - label.chars().count();
        writeln!(
            out,
            "  {style}{} {:<18}{style:#} {label}{:pad$}  {}",
            f.status.symbol(),
            f.status.as_str(),
            "",
            f.title,
        )?;
    }
    Ok(())
}

fn entry_label(f: &Finding) -> String {
    let mut label = f.package.label();
    if f.scope != Scope::Normal {
        label.push_str(&format!(" [{}]", f.scope));
    }
    label
}

fn write_entry(out: &mut dyn Write, f: &Finding) -> io::Result<()> {
    let title = match f.category {
        Some(c) => format!("{}: {}", c.label(), f.title),
        None => f.title.clone(),
    };
    writeln!(out, "  {BOLD}{}{BOLD:#} · {title}", entry_label(f))?;
    if let Some(adv) = &f.advisory {
        writeln!(out, "    {RED}advisory:{RED:#} {} ({})", adv.id, adv.url)?;
    }
    if !f.algorithms.is_empty() {
        writeln!(out, "    algorithms: {}", algorithm_list(&f.algorithms))?;
    }
    if let Some(note) = &f.note {
        writeln!(out, "    {note}")?;
    }
    if let Some(fix) = &f.fix {
        writeln!(out, "    {GREEN}fix:{GREEN:#} {fix}")?;
    }
    if !f.evidence.is_empty() {
        writeln!(out, "    {DIM}why: {}{DIM:#}", f.evidence.join("; "))?;
    }
    let mut via = short_path(&f.path);
    if !f.targets.is_empty() {
        via.push_str(" (platform-specific)");
    }
    writeln!(out, "    {DIM}via: {via}{DIM:#}")?;
    Ok(())
}

/// `ML-KEM-512/768/1024 (kem), X25519 (key-agree)`: parameter sets of the
/// same algorithm are merged.
fn algorithm_list(algorithms: &[Algorithm]) -> String {
    let mut merged: Vec<(&Algorithm, Vec<&str>)> = Vec::new();
    for a in algorithms {
        match merged
            .iter_mut()
            .find(|(m, _)| m.name == a.name && m.primitive == a.primitive && m.status == a.status)
        {
            Some((_, params)) => params.extend(a.parameter_set.as_deref()),
            None => merged.push((a, a.parameter_set.as_deref().into_iter().collect())),
        }
    }
    merged
        .iter()
        .map(|(a, params)| {
            let style = status_style(a.status);
            let name = if params.is_empty() {
                a.name.clone()
            } else {
                format!("{}-{}", a.name, params.join("/"))
            };
            format!("{style}{name}{style:#} ({})", a.primitive)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `a → b → c`, eliding the middle of long chains.
fn short_path(path: &[String]) -> String {
    const MAX: usize = 6;
    if path.len() <= MAX {
        return path.join(" → ");
    }
    let head = &path[..2];
    let tail = &path[path.len() - 3..];
    format!("{} → … → {}", head.join(" → "), tail.join(" → "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Primitive;

    #[test]
    fn long_paths_are_elided() {
        let p: Vec<String> = (0..9).map(|i| format!("c{i}")).collect();
        assert_eq!(short_path(&p), "c0 → c1 → … → c6 → c7 → c8");
        let p: Vec<String> = (0..3).map(|i| format!("c{i}")).collect();
        assert_eq!(short_path(&p), "c0 → c1 → c2");
    }

    #[test]
    fn parameter_sets_are_merged() {
        let alg = |name: &str, p: Option<&str>, status| Algorithm {
            name: name.into(),
            primitive: Primitive::Kem,
            functions: vec![],
            status,
            parameter_set: p.map(Into::into),
            nist_level: None,
        };
        let list = algorithm_list(&[
            alg("ML-KEM", Some("512"), Status::PostQuantum),
            alg("ML-KEM", Some("768"), Status::PostQuantum),
            alg("X-Wing", None, Status::Hybrid),
        ]);
        let plain = anstream::adapter::strip_str(&list).to_string();
        assert_eq!(plain, "ML-KEM-512/768 (kem), X-Wing (kem)");
    }
}
