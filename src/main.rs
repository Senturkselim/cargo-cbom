use anyhow::{Context, Result};
use cargo_cbom::{RuleSet, ScopeOptions, Status, analyze, cbom, report};
use cargo_metadata::{CargoOpt, Metadata, MetadataCommand};
use clap::{Parser, ValueEnum};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode};

/// Check a Rust project's cryptography for post-quantum readiness and
/// generate a CycloneDX Cryptography Bill of Materials (CBOM).
#[derive(Debug, Parser)]
#[command(name = "cargo-cbom", bin_name = "cargo cbom", version, about)]
#[command(
    after_help = "Exit codes: 0 = ok, 1 = a finding matched --fail-on, 2 = error.\n\
Results describe what is compiled in (from the dependency graph and enabled features), \
not which functions your code calls."
)]
struct Cli {
    /// Path to Cargo.toml (defaults to the current directory's project)
    #[arg(long, value_name = "PATH")]
    manifest_path: Option<PathBuf>,

    /// Analyze saved `cargo metadata --format-version 1` output instead of
    /// running cargo ("-" reads stdin)
    #[arg(long, value_name = "FILE", conflicts_with_all = ["manifest_path", "features", "all_features", "no_default_features", "target", "all_targets", "locked", "offline", "frozen"])]
    metadata: Option<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Write the report to a file instead of stdout
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Exit with code 1 if any finding has one of these statuses
    /// (comma-separated; `vulnerable` = quantum-vulnerable + known-vulnerable)
    #[arg(long, value_enum, value_delimiter = ',', value_name = "STATUS")]
    fail_on: Vec<FailOn>,

    /// Also scan dev-dependencies of workspace members
    #[arg(long)]
    include_dev: bool,

    /// Also scan build-dependencies and proc-macros (compile-time only code)
    #[arg(long)]
    include_build: bool,

    /// Features to activate on workspace members (comma-separated)
    #[arg(short = 'F', long, value_delimiter = ',', value_name = "FEATURES")]
    features: Vec<String>,

    /// Activate all features of workspace members
    #[arg(long, conflicts_with = "no_default_features")]
    all_features: bool,

    /// Do not activate the `default` feature of workspace members
    #[arg(long)]
    no_default_features: bool,

    /// Only include dependencies for this target triple (default: the host)
    #[arg(long, value_name = "TRIPLE", conflicts_with = "all_targets")]
    target: Option<String>,

    /// Include platform-specific dependencies for every target
    #[arg(long)]
    all_targets: bool,

    /// Passed to cargo: require Cargo.lock to be up to date
    #[arg(long)]
    locked: bool,

    /// Passed to cargo: run without accessing the network
    #[arg(long)]
    offline: bool,

    /// Passed to cargo: --locked and --offline
    #[arg(long)]
    frozen: bool,

    /// Extra rules file (TOML); rules with an existing id replace built-in ones
    #[arg(long, value_name = "FILE")]
    rules: Vec<PathBuf>,

    /// Print the rules and exit
    #[arg(long)]
    list_rules: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable report
    Text,
    /// Findings as JSON
    Json,
    /// CycloneDX 1.6 CBOM (JSON)
    Cbom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FailOn {
    /// quantum-vulnerable and known-vulnerable
    Vulnerable,
    QuantumVulnerable,
    KnownVulnerable,
    ClassicallyBroken,
    PreStandardPq,
    Depends,
}

impl FailOn {
    fn statuses(self) -> &'static [Status] {
        match self {
            FailOn::Vulnerable => &[Status::QuantumVulnerable, Status::KnownVulnerable],
            FailOn::QuantumVulnerable => &[Status::QuantumVulnerable],
            FailOn::KnownVulnerable => &[Status::KnownVulnerable],
            FailOn::ClassicallyBroken => &[Status::ClassicallyBroken],
            FailOn::PreStandardPq => &[Status::PreStandardPq],
            FailOn::Depends => &[Status::Depends],
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        // `cargo cbom | head` closes stdout early; that is not an error.
        Err(err) if is_broken_pipe(&err) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain().any(|e| {
        let kind = e
            .downcast_ref::<io::Error>()
            .map(io::Error::kind)
            .or_else(|| {
                e.downcast_ref::<serde_json::Error>()
                    .and_then(|e| e.io_error_kind())
            });
        kind == Some(io::ErrorKind::BrokenPipe)
    })
}

fn run() -> Result<ExitCode> {
    // `cargo cbom ...` runs `cargo-cbom cbom ...`; drop the subcommand name.
    let mut args: Vec<OsString> = std::env::args_os().collect();
    if args.get(1).is_some_and(|a| a == "cbom") {
        args.remove(1);
    }
    let cli = Cli::parse_from(args);

    let mut rules = RuleSet::builtin()?;
    for path in &cli.rules {
        let src = std::fs::read_to_string(path)
            .with_context(|| format!("could not read rules file {}", path.display()))?;
        let extra = RuleSet::from_toml(&src).with_context(|| format!("in {}", path.display()))?;
        rules.extend(extra)?;
    }

    if cli.list_rules {
        list_rules(&rules)?;
        return Ok(ExitCode::SUCCESS);
    }

    let target = if cli.metadata.is_some() || cli.all_targets {
        None
    } else {
        match &cli.target {
            Some(t) => Some(t.clone()),
            None => Some(host_triple()?),
        }
    };
    let metadata = load_metadata(&cli, target.as_deref())?;
    let opts = ScopeOptions {
        include_dev: cli.include_dev,
        include_build: cli.include_build,
        ignore_platform_conditions: target.is_some(),
    };
    let mut report = analyze(&metadata, &rules, opts)?;
    report.target = target;

    match &cli.output {
        Some(path) => {
            let file = File::create(path)
                .with_context(|| format!("could not create {}", path.display()))?;
            let mut out = BufWriter::new(anstream::StripStream::new(file));
            write_report(&report, cli.format, &mut out)?;
            out.flush()?;
        }
        None => {
            let mut out = anstream::AutoStream::auto(io::stdout().lock());
            write_report(&report, cli.format, &mut out)?;
            out.flush()?;
        }
    }

    let fail_statuses: BTreeSet<Status> = cli
        .fail_on
        .iter()
        .flat_map(|f| f.statuses().iter().copied())
        .collect();
    let failing = report.matching(&fail_statuses).count();
    if failing > 0 {
        let names: Vec<&str> = fail_statuses.iter().map(|s| s.as_str()).collect();
        eprintln!(
            "cargo-cbom: {failing} finding(s) matched --fail-on ({})",
            names.join(", ")
        );
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

/// The host target triple, as reported by `rustc -vV`.
fn host_triple() -> Result<String> {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let out = Command::new(&rustc).arg("-vV").output().context(
        "could not run `rustc -vV` to find the host target (use --target or --all-targets)",
    )?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(|h| h.trim().to_string())
        .context("`rustc -vV` did not report a host target (use --target or --all-targets)")
}

fn load_metadata(cli: &Cli, target: Option<&str>) -> Result<Metadata> {
    if let Some(path) = &cli.metadata {
        let mut json = String::new();
        if path.as_os_str() == "-" {
            io::stdin().read_to_string(&mut json)?;
        } else {
            json = std::fs::read_to_string(path)
                .with_context(|| format!("could not read {}", path.display()))?;
        }
        return MetadataCommand::parse(json).context("could not parse cargo metadata JSON");
    }

    let mut cmd = MetadataCommand::new();
    if let Some(path) = &cli.manifest_path {
        cmd.manifest_path(path);
    }
    if cli.all_features {
        cmd.features(CargoOpt::AllFeatures);
    }
    if cli.no_default_features {
        cmd.features(CargoOpt::NoDefaultFeatures);
    }
    if !cli.features.is_empty() {
        cmd.features(CargoOpt::SomeFeatures(cli.features.clone()));
    }
    let mut other = Vec::new();
    if let Some(target) = target {
        other.push("--filter-platform".to_string());
        other.push(target.to_string());
    }
    for (on, flag) in [
        (cli.locked, "--locked"),
        (cli.offline, "--offline"),
        (cli.frozen, "--frozen"),
    ] {
        if on {
            other.push(flag.to_string());
        }
    }
    cmd.other_options(other);
    cmd.exec().context("`cargo metadata` failed")
}

fn write_report(report: &cargo_cbom::Report, format: Format, out: &mut dyn Write) -> Result<()> {
    match format {
        Format::Text => report::write_text(report, out)?,
        Format::Json => {
            serde_json::to_writer_pretty(&mut *out, report)?;
            writeln!(out)?;
        }
        Format::Cbom => {
            serde_json::to_writer_pretty(&mut *out, &cbom::to_cyclonedx(report))?;
            writeln!(out)?;
        }
    }
    Ok(())
}

fn list_rules(rules: &RuleSet) -> Result<()> {
    let mut out = anstream::AutoStream::auto(io::stdout().lock());
    writeln!(out, "{} rules", rules.len())?;
    for r in rules.rules() {
        let mut cond = Vec::new();
        if let Some(v) = &r.versions {
            cond.push(v.as_str().to_string());
        }
        if !r.features_all.is_empty() {
            cond.push(format!("all of [{}]", r.features_all.join(", ")));
        }
        if !r.features_any.is_empty() {
            cond.push(format!("any of [{}]", r.features_any.join(", ")));
        }
        if !r.features_none.is_empty() {
            cond.push(format!("none of [{}]", r.features_none.join(", ")));
        }
        let cond = if cond.is_empty() {
            String::new()
        } else {
            format!(" ({})", cond.join("; "))
        };
        writeln!(
            out,
            "{:<34} {:<22} {:<19} {}{cond}",
            r.id, r.crate_name, r.status, r.title
        )?;
    }
    out.flush()?;
    Ok(())
}
