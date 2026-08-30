use clap::{Parser, Subcommand, ValueEnum};
use globset::Glob;
use rbx_heal_core::{
    baseline::{self, BaselineAction, BaselineFile},
    config::{Config, VerifyCommand, VerifyConfig, VerifyKind},
    discovery::{canonical_project_root, discover_files},
    engine::{scan, ScanReport},
    history::{
        event_from_summary_with_findings, export as export_history, record,
        summarize as summarize_history,
    },
    model::{BaselineState, BaselineSummaryV1, FilePatchV1, Finding, Severity},
    parser::parse_source_with_path,
    path::{relative_utf8, validate_existing_file},
    transaction::{commit_fixes_with_validator, preview_fixes, recover_journal, TransactionError},
    verification::{command_identity, preflight_verification, run_verification},
};
use rbx_heal_rules::built_in_rules;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser, Debug)]
#[command(
    name = "rbx-heal",
    version,
    about = "Local deterministic Luau diagnostics and safe fixes"
)]
struct Cli {
    #[arg(long, global = true, default_value = ".")]
    project: PathBuf,
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Init,
    Check {
        paths: Vec<PathBuf>,
        #[arg(long)]
        no_baseline: bool,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },
    Fix {
        paths: Vec<PathBuf>,
        #[arg(long)]
        write: bool,
        #[arg(long)]
        no_baseline: bool,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
        #[arg(long)]
        save_artifacts: Option<PathBuf>,
    },
    Explain {
        rule_id: String,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    Doctor {
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },
    /// Run the read-only Slime Farm acceptance pilot.
    Pilot {
        /// Select the built-in pilot suite. The legacy Slime Farm suite remains
        /// the default for backwards compatibility; public-v1 is used by CI.
        #[arg(long, value_enum, default_value_t = PilotSuite::SlimeFarm)]
        suite: PilotSuite,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
}

#[derive(Subcommand, Debug)]
enum HistoryCommand {
    Export {
        destination: PathBuf,
    },
    Summarize {
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },
}

#[derive(Subcommand, Debug)]
enum BaselineCommand {
    Create {
        #[arg(long)]
        write: bool,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },
    Prune {
        #[arg(long)]
        write: bool,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Sarif,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PilotSuite {
    #[value(name = "slime-farm")]
    SlimeFarm,
    #[value(name = "public-v1")]
    PublicV1,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<u8, Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let root = canonical_project_root(&cli.project)?;
    if recover_journal(&root)? {
        eprintln!("recovered an incomplete previous heal transaction");
    }
    match cli.command {
        Command::Init => {
            let path = root.join("rbx-heal.toml");
            Config::write_sample(&path)?;
            println!("created {}", path.display());
            Ok(0)
        }
        Command::Check {
            paths,
            no_baseline,
            format,
        } => {
            let (config, _) = Config::load(&root, cli.config.as_deref())?;
            let report = run_scan(&root, &config, &paths, "check", !no_baseline)?;
            emit_report(&report, format)?;
            record_run(&report, &root, "scan", "not_run");
            Ok(if report.parse_errors > 0 {
                2
            } else if report.has_policy_findings(config.policy.fail_on) {
                1
            } else {
                0
            })
        }
        Command::Fix {
            paths,
            write,
            no_baseline,
            format,
            save_artifacts,
        } => {
            if matches!(format, OutputFormat::Sarif) {
                return Err("SARIF output is supported only by `check`".into());
            }
            let (config, _) = Config::load(&root, cli.config.as_deref())?;
            let report = run_scan(&root, &config, &paths, "fix", !no_baseline)?;
            if report.parse_errors > 0 {
                emit_report(&report, format)?;
                record_run(&report, &root, "parse-error", "not_run");
                return Ok(2);
            }
            let safe = report.safe_fixes().cloned().collect::<Vec<_>>();
            if !write {
                if let Some(destination) = save_artifacts.as_deref() {
                    save_preview_artifacts(destination, &root, &safe)?;
                }
                let preview = preview_fixes(&root, safe.into_iter())?;
                emit_report_with_patches(&report, format, Some(&preview.patches))?;
                for (path, candidate) in preview.files {
                    let diff = unified_diff(
                        &diff_label(&path, &root),
                        &std::fs::read_to_string(&path)?,
                        &candidate,
                    );
                    if matches!(format, OutputFormat::Human) {
                        println!("\n{}\n", diff);
                    }
                }
                record_run(&report, &root, "preview", "not_run");
                return Ok(if report.has_policy_findings(config.policy.fail_on) {
                    1
                } else {
                    0
                });
            }
            if safe.is_empty() {
                // Keep the JSON fix contract stable even when there are no
                // writable findings: agents can always consume a `patches`
                // array without special-casing the no-op path.
                emit_report_with_patches(&report, format, Some(&[]))?;
                record_run(&report, &root, "no-op", "not_run");
                return Ok(if report.has_policy_findings(config.policy.fail_on) {
                    1
                } else {
                    0
                });
            }
            // Build the same guarded patch preview that the transaction will
            // apply.  It is emitted for both dry-runs and writes so an agent
            // can consume one JSON envelope without parsing human output.
            let preview = preview_fixes(&root, safe.clone().into_iter())?;
            if let Some(destination) = save_artifacts.as_deref() {
                save_preview_artifacts(destination, &root, &safe)?;
            }
            let safe_rule_ids = safe
                .iter()
                .map(|finding| finding.rule_id.clone())
                .collect::<BTreeSet<_>>();
            let baseline_errors = report
                .findings
                .iter()
                .filter(|finding| finding.severity == Severity::Error)
                .map(|finding| {
                    (
                        finding.path.clone(),
                        finding.rule_id.clone(),
                        finding.message.clone(),
                    )
                })
                .collect::<BTreeSet<_>>();
            let rules = built_in_rules();
            let validator = |path: &Path, candidate: &str| -> Result<(), String> {
                let relative = relative_utf8(&root, path).map_err(|error| error.to_string())?;
                let file = parse_source_with_path(
                    path.to_path_buf(),
                    relative.clone(),
                    candidate.to_owned(),
                )
                .map_err(|error| error.to_string())?;
                let mut findings = Vec::new();
                for rule in &rules {
                    if config.is_enabled(rule.id()) {
                        let file_scope = config.scope_for_path(&relative);
                        if !rule.metadata().applicable_scopes.is_empty()
                            && !rule.metadata().applicable_scopes.contains(&file_scope)
                        {
                            continue;
                        }
                        rule.analyze(
                            &rbx_heal_core::RuleContext {
                                file: &file,
                                config: &config,
                            },
                            &mut findings,
                        );
                        for finding in findings
                            .iter_mut()
                            .filter(|finding| finding.rule_id == rule.id())
                        {
                            finding.severity =
                                config.severity_for(rule.id(), rule.default_severity());
                        }
                    }
                }
                if let Some(finding) = findings
                    .iter()
                    .find(|finding| safe_rule_ids.contains(&finding.rule_id))
                {
                    return Err(format!(
                        "safe-fix postcondition failed: {} remains",
                        finding.rule_id
                    ));
                }
                if let Some(finding) = findings.iter().find(|finding| {
                    finding.severity == Severity::Error
                        && !baseline_errors.contains(&(
                            relative.clone(),
                            finding.rule_id.clone(),
                            finding.message.clone(),
                        ))
                }) {
                    return Err(format!(
                        "safe-fix postcondition failed: new error {} appeared",
                        finding.rule_id
                    ));
                }
                Ok(())
            };
            match commit_fixes_with_validator(&root, &config, safe.into_iter(), Some(&validator)) {
                Ok(result) => {
                    let mut updated = run_scan(&root, &config, &paths, "fix", !no_baseline)?;
                    updated.summary.verification = result.verification.steps.clone();
                    updated.summary.rollback_status = result.verification.rollback_status.clone();
                    updated.summary.transaction = "committed".into();
                    emit_report_with_patches(&updated, format, Some(&preview.patches))?;
                    record_run(&updated, &root, "committed", "passed");
                    Ok(if updated.has_policy_findings(config.policy.fail_on) {
                        1
                    } else {
                        0
                    })
                }
                Err(TransactionError::VerificationFailed {
                    report: verification,
                }) => {
                    let mut failed = report.clone();
                    failed.summary.verification = verification.steps.clone();
                    failed.summary.rollback_status = verification.rollback_status.clone();
                    failed.summary.transaction = "rolled_back".into();
                    emit_report_with_patches(&failed, format, Some(&preview.patches))?;
                    eprintln!("verification failed; changes rolled back");
                    for step in verification.steps {
                        eprintln!("  {}: {}", step.name, step.status);
                    }
                    record_run(&failed, &root, "rollback", "failed");
                    Ok(3)
                }
                Err(error) => Err(Box::new(error)),
            }
        }
        Command::Baseline { command } => {
            let (config, _) = Config::load(&root, cli.config.as_deref())?;
            match command {
                BaselineCommand::Create {
                    write,
                    reason,
                    format,
                } => {
                    if matches!(format, OutputFormat::Sarif) {
                        return Err("SARIF output is supported only by `check`".into());
                    }
                    if write
                        && reason
                            .as_deref()
                            .is_none_or(|value| value.trim().is_empty())
                    {
                        return Err("`baseline create --write` requires --reason".into());
                    }
                    let report = run_scan(&root, &config, &[], "baseline", false)?;
                    let reason = reason.unwrap_or_else(|| "preview".into());
                    let (baseline, action) = baseline::create(&root, &report, &reason, write)?;
                    emit_baseline_action(&baseline, &action, format)?;
                    Ok(0)
                }
                BaselineCommand::Prune { write, format } => {
                    if matches!(format, OutputFormat::Sarif) {
                        return Err("SARIF output is supported only by `check`".into());
                    }
                    let report = run_scan(&root, &config, &[], "baseline", false)?;
                    let (baseline, action) = baseline::prune(&root, &report, write)?;
                    emit_baseline_action(&baseline, &action, format)?;
                    Ok(0)
                }
            }
        }
        Command::Explain { rule_id, format } => {
            if matches!(format, OutputFormat::Sarif) {
                return Err("SARIF output is supported only by `check`".into());
            }
            let rules = built_in_rules();
            if let Some(rule) = rules
                .iter()
                .find(|rule| rule.id().eq_ignore_ascii_case(&rule_id))
            {
                let metadata = rule.metadata();
                match format {
                    OutputFormat::Human => {
                        println!(
                            "{}\ncategory: {}\nseverity: {}\nconfidence: {}\nfixability: {}\npattern: {}\n\n{}\n\nrationale: {}\nremediation: {}\nscope: {:?}",
                            metadata.id,
                            metadata.category,
                            metadata.default_severity,
                            metadata.default_confidence,
                            metadata.fixability,
                            metadata.semantic_pattern,
                            metadata.summary,
                            metadata.rationale,
                            metadata.remediation,
                            metadata.applicable_scopes,
                        );
                        for example in metadata.examples {
                            println!("example ({}):\n{}", example.label, example.source);
                        }
                    }
                    OutputFormat::Json => {
                        #[derive(serde::Serialize)]
                        struct Explain<'a> {
                            schema_version: u32,
                            id: &'a str,
                            category: &'a str,
                            severity: Severity,
                            confidence: rbx_heal_core::Confidence,
                            fixability: rbx_heal_core::Fixability,
                            applicable_scopes: &'a [rbx_heal_core::ScopeKind],
                            summary: &'a str,
                            rationale: &'a str,
                            remediation: &'a str,
                            semantic_pattern: &'a str,
                            examples: &'a [rbx_heal_core::RuleExample],
                        }
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&Explain {
                                schema_version: 1,
                                id: metadata.id,
                                category: metadata.category,
                                severity: metadata.default_severity,
                                confidence: metadata.default_confidence,
                                fixability: metadata.fixability,
                                applicable_scopes: metadata.applicable_scopes,
                                summary: metadata.summary,
                                rationale: metadata.rationale,
                                remediation: metadata.remediation,
                                semantic_pattern: metadata.semantic_pattern,
                                examples: metadata.examples,
                            })?
                        );
                    }
                    OutputFormat::Sarif => unreachable!("SARIF is rejected above"),
                }
                Ok(0)
            } else {
                eprintln!("unknown rule `{rule_id}`");
                Ok(1)
            }
        }
        Command::Doctor { format } => doctor(&root, cli.config.as_deref(), format),
        Command::Pilot { suite, format } => match suite {
            PilotSuite::SlimeFarm => run_pilot(&root, format),
            PilotSuite::PublicV1 => run_public_pilot(&root, format),
        },
        Command::History {
            command: HistoryCommand::Export { destination },
        } => {
            let count = export_history(&destination)?;
            println!(
                "exported {count} history events to {}",
                destination.display()
            );
            Ok(0)
        }
        Command::History {
            command: HistoryCommand::Summarize { format },
        } => {
            let summary = summarize_history()?;
            match format {
                OutputFormat::Human => {
                    println!(
                        "history: {} runs, {} unsuppressed findings, {} suppressed, {} committed, {} rollbacks",
                        summary.runs,
                        summary.unsuppressed_findings,
                        summary.suppressed_findings,
                        summary.committed_fixes,
                        summary.rollbacks
                    );
                    println!(
                        "rates: suppression {:.1}%, fix success {:.1}%, rollback {:.1}%, verifier success {:.1}%",
                        summary.suppression_ratio * 100.0,
                        summary.fix_success_rate * 100.0,
                        summary.rollback_rate * 100.0,
                        summary.verifier_success_rate * 100.0,
                    );
                    println!(
                        "baseline totals: {} matched, {} new, {} stale",
                        summary.baseline_matched, summary.baseline_new, summary.baseline_stale
                    );
                    for (pattern, count) in &summary.patterns {
                        println!("pattern {pattern}: {count}");
                    }
                }
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&summary)?),
                OutputFormat::Sarif => return Err("SARIF output is supported only by check".into()),
            }
            Ok(0)
        }
    }
}

#[derive(serde::Deserialize)]
struct PilotSpec {
    version: u32,
    name: String,
    root_env: String,
    default_relative_root: String,
    repository: String,
    commit: String,
    official_verifiers: Vec<String>,
    official_gate_requires_rojo: bool,
    temporary_copy_write_test: bool,
}

#[derive(serde::Deserialize)]
struct PilotExpectationManifest {
    schema_version: u32,
    pilot: String,
    expectations: BTreeMap<String, bool>,
    source_policy: PilotSourcePolicy,
}

#[derive(Debug, serde::Deserialize)]
struct PilotSourcePolicy {
    hash_luau_before_and_after: bool,
    write_only_temporary_copy: bool,
}

const PILOT_SPEC_TEXT: &str = include_str!("../../../pilot/slime-farm.toml");
const PILOT_EXPECTATIONS_TEXT: &str = include_str!("../../../pilot/slime-farm-expectations.json");

fn pilot_spec() -> Result<(PilotSpec, PilotExpectationManifest), Box<dyn std::error::Error>> {
    let spec = toml::from_str::<PilotSpec>(PILOT_SPEC_TEXT)?;
    let expectations = serde_json::from_str::<PilotExpectationManifest>(PILOT_EXPECTATIONS_TEXT)?;
    if spec.version != 1
        || expectations.schema_version != 1
        || expectations.pilot != spec.name
        || !spec.repository.starts_with("https://github.com/")
        || spec.commit.len() != 40
        || !spec.commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        || spec.official_verifiers != ["luau_reparse", "rojo_build"]
        || !expectations.source_policy.hash_luau_before_and_after
        || !expectations.source_policy.write_only_temporary_copy
    {
        return Err("embedded Slime Farm pilot manifest is invalid".into());
    }
    Ok((spec, expectations))
}

#[derive(serde::Serialize)]
struct PilotReport {
    schema_version: u32,
    pilot: String,
    files_scanned: usize,
    bytes_scanned: usize,
    findings: usize,
    parse_errors: usize,
    rule_counts: BTreeMap<String, usize>,
    fingerprints: Vec<String>,
    expectations: BTreeMap<String, bool>,
    source_unchanged: bool,
    temporary_fix_status: String,
    verification: Vec<PilotVerification>,
    tool_versions: BTreeMap<String, String>,
    expected_commit: String,
    checkout_commit: Option<String>,
    official_gate_complete: bool,
    duration_ms: u128,
}

#[derive(Debug, serde::Serialize)]
struct PilotVerification {
    name: String,
    status: String,
    exit_code: Option<i32>,
    duration_ms: u128,
    output_truncated: bool,
}

#[derive(Debug, serde::Deserialize)]
struct PublicPilotManifest {
    schema_version: u32,
    suite: String,
    source_policy: PilotSourcePolicy,
    min_error_precision: f64,
    min_warning_precision: f64,
    projects: Vec<PublicPilotProject>,
}

#[derive(Debug, serde::Deserialize)]
struct PublicPilotProject {
    id: String,
    repository: String,
    commit: String,
    license: String,
    root_env: String,
    expectations: String,
    required_verifiers: Vec<String>,
    #[serde(default)]
    config: Config,
}

#[derive(Debug, serde::Deserialize)]
struct PublicPilotExpectations {
    schema_version: u32,
    project: String,
    #[serde(default)]
    rule_counts: BTreeMap<String, usize>,
    #[serde(default)]
    findings: Vec<PublicPilotFindingExpectation>,
}

#[derive(Debug, serde::Deserialize)]
struct PublicPilotFindingExpectation {
    baseline_id: String,
    rule_id: String,
    verdict: String,
    reason: String,
}

#[derive(Debug, serde::Serialize)]
struct PublicPilotFindingStats {
    reviewed: usize,
    unreviewed: usize,
    suppressed: usize,
    error_total: usize,
    warning_total: usize,
    error_true_positive: usize,
    warning_true_positive: usize,
    error_precision: f64,
    warning_precision: f64,
    rule_counts_match: bool,
    identities_match: bool,
}

#[derive(Debug, serde::Serialize)]
struct PublicPilotCaseReport {
    id: String,
    repository: String,
    commit: String,
    license: String,
    status: String,
    files_scanned: usize,
    bytes_scanned: usize,
    findings: usize,
    parse_errors: usize,
    rule_counts: BTreeMap<String, usize>,
    baseline_ids: Vec<String>,
    finding_stats: PublicPilotFindingStats,
    source_unchanged: bool,
    temporary_fix_status: String,
    verification: Vec<PilotVerification>,
    tool_versions: BTreeMap<String, String>,
    checkout_commit: Option<String>,
    official_gate_complete: bool,
    expectations_passed: bool,
    duration_ms: u128,
}

#[derive(Debug, serde::Serialize)]
struct PublicPilotSuiteReport {
    schema_version: u32,
    suite: String,
    cases: Vec<PublicPilotCaseReport>,
    cases_passed: usize,
    total_findings: usize,
    total_reviewed: usize,
    total_unreviewed: usize,
    official_gate_complete: bool,
    source_unchanged: bool,
    expectations_passed: bool,
    duration_ms: u128,
}

/// Additive, versioned report used by the manifest-driven public corpus gate.
type PilotSuiteReportV1 = PublicPilotSuiteReport;

const PUBLIC_PILOT_MANIFEST_TEXT: &str = include_str!("../../../pilot/public-v1.toml");
const PUBLIC_PLANT_EXPECTATIONS_TEXT: &str =
    include_str!("../../../pilot/public-v1-expectations/plant.json");
const PUBLIC_HACKER_TYCOON_EXPECTATIONS_TEXT: &str =
    include_str!("../../../pilot/public-v1-expectations/hacker-tycoon.json");
const PUBLIC_ROBLOQUAKE_EXPECTATIONS_TEXT: &str =
    include_str!("../../../pilot/public-v1-expectations/robloquake.json");

fn public_pilot_manifest() -> Result<PublicPilotManifest, Box<dyn std::error::Error>> {
    let manifest = toml::from_str::<PublicPilotManifest>(PUBLIC_PILOT_MANIFEST_TEXT)?;
    if manifest.schema_version != 1
        || manifest.suite != "public-v1"
        || !manifest.source_policy.hash_luau_before_and_after
        || !manifest.source_policy.write_only_temporary_copy
        || !(0.0..=1.0).contains(&manifest.min_error_precision)
        || !(0.0..=1.0).contains(&manifest.min_warning_precision)
        || manifest.projects.len() != 3
    {
        return Err("embedded public-v1 pilot manifest is invalid".into());
    }
    let mut ids = BTreeSet::new();
    for project in &manifest.projects {
        if !ids.insert(project.id.clone())
            || !project.repository.starts_with("https://github.com/")
            || project.commit.len() != 40
            || !project.commit.bytes().all(|byte| byte.is_ascii_hexdigit())
            || project.license.trim().is_empty()
            || project.root_env.trim().is_empty()
            || project.required_verifiers != ["luau_reparse", "rojo_build"]
            || !matches!(
                project.expectations.as_str(),
                "plant" | "hacker-tycoon" | "robloquake"
            )
        {
            return Err("invalid public-v1 project identity".into());
        }
        project.config.validate()?;
    }
    let expected = BTreeSet::from([
        "hacker-tycoon".to_string(),
        "robloquake".to_string(),
        "roblox-resources-plant".to_string(),
    ]);
    if ids != expected {
        return Err("public-v1 project set is incomplete".into());
    }
    Ok(manifest)
}

fn public_pilot_expectations(
    selector: &str,
) -> Result<PublicPilotExpectations, Box<dyn std::error::Error>> {
    let text = match selector {
        "plant" => PUBLIC_PLANT_EXPECTATIONS_TEXT,
        "hacker-tycoon" => PUBLIC_HACKER_TYCOON_EXPECTATIONS_TEXT,
        "robloquake" => PUBLIC_ROBLOQUAKE_EXPECTATIONS_TEXT,
        _ => return Err("unknown public-v1 expectation set".into()),
    };
    let expectations = serde_json::from_str::<PublicPilotExpectations>(text)?;
    if expectations.schema_version != 1
        || expectations.project.trim().is_empty()
        || expectations
            .rule_counts
            .keys()
            .any(|key| key.trim().is_empty())
    {
        return Err("invalid public-v1 expectations".into());
    }
    let mut ids = BTreeSet::new();
    for finding in &expectations.findings {
        if finding.baseline_id.len() != 64
            || !finding
                .baseline_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || finding.rule_id.trim().is_empty()
            || finding.reason.trim().is_empty()
            || !matches!(
                finding.verdict.as_str(),
                "true_positive" | "false_positive" | "needs_context" | "suppressed"
            )
            || !ids.insert(finding.baseline_id.clone())
        {
            return Err("invalid public-v1 finding expectation".into());
        }
    }
    Ok(expectations)
}

fn public_verification_config() -> VerifyConfig {
    VerifyConfig {
        commands: vec![
            VerifyCommand {
                // Luau's compiler exposes a stable parse-only mode, while
                // luau-analyze also typechecks/lints and can legitimately
                // return diagnostics for third-party projects.  The pilot's
                // official gate is a syntax reparse, so use the compiler's
                // --only-parse mode and keep analysis available to users via
                // the normal configured verifier path.
                kind: VerifyKind::Generic,
                name: "luau-reparse".into(),
                program: "luau-compile".into(),
                args: vec!["--only-parse".into(), "{changed}".into()],
                timeout_ms: Some(60_000),
                required: true,
                ..Default::default()
            },
            VerifyCommand {
                kind: VerifyKind::RojoBuild,
                name: "rojo-build".into(),
                program: "rojo".into(),
                args: vec!["build".into(), "default.project.json".into()],
                timeout_ms: Some(60_000),
                required: true,
                ..Default::default()
            },
        ],
        ..VerifyConfig::default()
    }
}

fn public_pilot_report_case(
    project: &PublicPilotProject,
    status: impl Into<String>,
) -> PublicPilotCaseReport {
    PublicPilotCaseReport {
        id: project.id.clone(),
        repository: project.repository.clone(),
        commit: project.commit.clone(),
        license: project.license.clone(),
        status: status.into(),
        files_scanned: 0,
        bytes_scanned: 0,
        findings: 0,
        parse_errors: 0,
        rule_counts: BTreeMap::new(),
        baseline_ids: Vec::new(),
        finding_stats: PublicPilotFindingStats {
            reviewed: 0,
            unreviewed: 0,
            suppressed: 0,
            error_total: 0,
            warning_total: 0,
            error_true_positive: 0,
            warning_true_positive: 0,
            error_precision: 1.0,
            warning_precision: 1.0,
            rule_counts_match: false,
            identities_match: false,
        },
        source_unchanged: false,
        temporary_fix_status: "not_run".into(),
        verification: Vec::new(),
        tool_versions: BTreeMap::new(),
        checkout_commit: None,
        official_gate_complete: false,
        expectations_passed: false,
        duration_ms: 0,
    }
}

fn public_precision(true_positives: usize, total: usize) -> f64 {
    if total == 0 {
        1.0
    } else {
        true_positives as f64 / total as f64
    }
}

fn run_public_pilot(
    engine_root: &Path,
    format: OutputFormat,
) -> Result<u8, Box<dyn std::error::Error>> {
    if matches!(format, OutputFormat::Sarif) {
        return Err("SARIF output is supported only by check".into());
    }
    let started = std::time::Instant::now();
    let manifest = public_pilot_manifest()?;
    let mut cases = Vec::with_capacity(manifest.projects.len());
    let mut exit_code = 0u8;
    for project in &manifest.projects {
        let expectations = public_pilot_expectations(&project.expectations)?;
        if expectations.project != project.id {
            return Err("public-v1 expectation project does not match manifest".into());
        }
        let (case, code) = run_public_pilot_case(engine_root, project, &expectations, &manifest)?;
        exit_code = exit_code.max(code);
        cases.push(case);
    }
    cases.sort_by(|left, right| left.id.cmp(&right.id));
    let cases_passed = cases.iter().filter(|case| case.status == "passed").count();
    let total_findings = cases.iter().map(|case| case.findings).sum();
    let total_reviewed = cases.iter().map(|case| case.finding_stats.reviewed).sum();
    let total_unreviewed = cases.iter().map(|case| case.finding_stats.unreviewed).sum();
    let report: PilotSuiteReportV1 = PublicPilotSuiteReport {
        schema_version: 1,
        suite: manifest.suite,
        cases_passed,
        total_findings,
        total_reviewed,
        total_unreviewed,
        official_gate_complete: cases.iter().all(|case| case.official_gate_complete),
        source_unchanged: cases.iter().all(|case| case.source_unchanged),
        expectations_passed: cases.iter().all(|case| case.expectations_passed),
        cases,
        duration_ms: started.elapsed().as_millis(),
    };
    match format {
        OutputFormat::Human => print_public_pilot_human(&report),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Sarif => unreachable!("SARIF output is rejected above"),
    }
    Ok(exit_code)
}

fn run_public_pilot_case(
    engine_root: &Path,
    project: &PublicPilotProject,
    expectations: &PublicPilotExpectations,
    manifest: &PublicPilotManifest,
) -> Result<(PublicPilotCaseReport, u8), Box<dyn std::error::Error>> {
    let started = std::time::Instant::now();
    let mut case = public_pilot_report_case(project, "not_run");
    let configured_root = match std::env::var_os(&project.root_env) {
        Some(root) => PathBuf::from(root),
        None => {
            case.status = "missing_root".into();
            case.duration_ms = started.elapsed().as_millis();
            return Ok((case, 2));
        }
    };
    let configured_root = if configured_root.is_absolute() {
        configured_root
    } else {
        engine_root.join(configured_root)
    };
    let project_root = match canonical_project_root(&configured_root) {
        Ok(root) => root,
        Err(_) => {
            case.status = "invalid_root".into();
            case.duration_ms = started.elapsed().as_millis();
            return Ok((case, 2));
        }
    };
    let before_hashes = match source_hashes(&project_root) {
        Ok(hashes) => hashes,
        Err(_) => {
            case.status = "source_hash_failed".into();
            case.duration_ms = started.elapsed().as_millis();
            return Ok((case, 2));
        }
    };
    let report = match scan(
        &project_root,
        &project.config,
        &[],
        &built_in_rules(),
        "pilot-public-v1",
    ) {
        Ok(report) => report,
        Err(_) => {
            case.status = "scan_failed".into();
            case.duration_ms = started.elapsed().as_millis();
            return Ok((case, 2));
        }
    };
    let non_parse_findings = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id != "RBX-PARSE-001")
        .collect::<Vec<_>>();
    let mut rule_counts = BTreeMap::new();
    let mut baseline_ids = Vec::new();
    let mut observed = BTreeMap::<String, &Finding>::new();
    let mut identity_complete = true;
    for finding in &non_parse_findings {
        *rule_counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
        let Some(id) = finding.baseline_id.as_deref() else {
            identity_complete = false;
            continue;
        };
        baseline_ids.push(id.to_owned());
        if observed.insert(id.to_owned(), *finding).is_some() {
            identity_complete = false;
        }
    }
    baseline_ids.sort();
    let expected = expectations
        .findings
        .iter()
        .map(|finding| (finding.baseline_id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    let mut reviewed = 0usize;
    let mut suppressed = 0usize;
    let mut error_total = 0usize;
    let mut warning_total = 0usize;
    let mut error_true_positive = 0usize;
    let mut warning_true_positive = 0usize;
    for (id, finding) in &observed {
        let Some(expected_finding) = expected.get(id.as_str()) else {
            continue;
        };
        reviewed += 1;
        if finding.suppressed || expected_finding.verdict == "suppressed" {
            suppressed += 1;
        }
        let true_positive = matches!(
            expected_finding.verdict.as_str(),
            "true_positive" | "suppressed"
        );
        match finding.severity {
            Severity::Error => {
                error_total += 1;
                if true_positive {
                    error_true_positive += 1;
                }
            }
            Severity::Warning => {
                warning_total += 1;
                if true_positive {
                    warning_true_positive += 1;
                }
            }
            _ => {}
        }
    }
    let identities_match = identity_complete
        && observed.len() == expected.len()
        && observed
            .keys()
            .map(|key| key.as_str())
            .eq(expected.keys().copied());
    let rule_counts_match = rule_counts == expectations.rule_counts;
    let finding_stats = PublicPilotFindingStats {
        reviewed,
        unreviewed: non_parse_findings.len().saturating_sub(reviewed),
        suppressed,
        error_total,
        warning_total,
        error_true_positive,
        warning_true_positive,
        error_precision: public_precision(error_true_positive, error_total),
        warning_precision: public_precision(warning_true_positive, warning_total),
        rule_counts_match,
        identities_match,
    };
    case.files_scanned = report.summary.files_scanned;
    case.bytes_scanned = report.summary.bytes_scanned;
    case.findings = non_parse_findings.len();
    case.parse_errors = report.parse_errors;
    case.rule_counts = rule_counts;
    case.baseline_ids = baseline_ids;
    case.finding_stats = finding_stats;
    case.temporary_fix_status = match run_temporary_fix(&project_root, &project.config) {
        Ok(status) => status,
        Err(_) => "safe_write_failed".into(),
    };
    let after_hashes = source_hashes(&project_root).unwrap_or_default();
    case.source_unchanged = before_hashes == after_hashes;
    case.tool_versions = ["rojo", "luau-analyze", "luau-compile"]
        .into_iter()
        .map(|program| (program.to_string(), tool_version(program)))
        .collect();
    let files = match discover_files(&project_root, &project.config, &[]) {
        Ok(files) => files,
        Err(_) => {
            case.status = "discovery_failed".into();
            case.duration_ms = started.elapsed().as_millis();
            return Ok((case, 2));
        }
    };
    let verification = run_verification(&project_root, &public_verification_config(), &files);
    case.verification = verification
        .steps
        .iter()
        .map(|step| PilotVerification {
            name: step.name.clone(),
            status: step.status.clone(),
            exit_code: step.exit_code,
            duration_ms: step.duration_ms,
            output_truncated: step.output_truncated,
        })
        .collect();
    case.checkout_commit = git_commit(&project_root);
    let required_verifiers_passed = ["luau-reparse", "rojo-build"].iter().all(|name| {
        case.verification
            .iter()
            .any(|step| step.name == *name && step.status == "passed")
    });
    case.official_gate_complete = report.parse_errors == 0
        && case.source_unchanged
        && case.temporary_fix_status == "passed"
        && required_verifiers_passed
        && case.checkout_commit.as_deref() == Some(project.commit.as_str());
    case.expectations_passed = report.parse_errors == 0
        && case.finding_stats.unreviewed == 0
        && case.finding_stats.identities_match
        && case.finding_stats.rule_counts_match
        && case.finding_stats.error_precision >= manifest.min_error_precision
        && case.finding_stats.warning_precision >= manifest.min_warning_precision;
    let runtime_verification_failure = case
        .verification
        .iter()
        .any(|step| matches!(step.status.as_str(), "failed" | "timeout"));
    let missing_verifier = case
        .verification
        .iter()
        .any(|step| matches!(step.status.as_str(), "missing" | "identity_mismatch"));
    let code = if !case.source_unchanged || case.temporary_fix_status != "passed" {
        case.status = "write_safety_failed".into();
        3
    } else if runtime_verification_failure {
        case.status = "verification_failed".into();
        3
    } else if report.parse_errors > 0 || missing_verifier {
        case.status = if missing_verifier {
            "missing_verifier".into()
        } else {
            "parse_failed".into()
        };
        2
    } else if case.checkout_commit.as_deref() != Some(project.commit.as_str()) {
        case.status = "commit_mismatch".into();
        2
    } else if !case.expectations_passed {
        case.status = "expectations_failed".into();
        1
    } else {
        case.status = "passed".into();
        0
    };
    case.duration_ms = started.elapsed().as_millis();
    Ok((case, code))
}

fn print_public_pilot_human(report: &PublicPilotSuiteReport) {
    println!(
        "public-v1 pilot: {}/{} cases passed, {} findings ({} reviewed, {} unreviewed), {} ms",
        report.cases_passed,
        report.cases.len(),
        report.total_findings,
        report.total_reviewed,
        report.total_unreviewed,
        report.duration_ms
    );
    for case in &report.cases {
        println!(
            "  {} [{}] files={} findings={} parse_errors={} expectations={} official_gate={}",
            case.id,
            case.status,
            case.files_scanned,
            case.findings,
            case.parse_errors,
            if case.expectations_passed {
                "pass"
            } else {
                "fail"
            },
            if case.official_gate_complete {
                "complete"
            } else {
                "incomplete"
            }
        );
        println!(
            "    precision: error {:.1}%, warning {:.1}%; identities={} rules={}",
            case.finding_stats.error_precision * 100.0,
            case.finding_stats.warning_precision * 100.0,
            case.finding_stats.identities_match,
            case.finding_stats.rule_counts_match
        );
        for step in &case.verification {
            println!("    verifier {}: {}", step.name, step.status);
        }
    }
    if !report.official_gate_complete {
        println!(
            "official gate incomplete: required tools or pinned checkout identity are unavailable"
        );
    }
}

fn run_pilot(engine_root: &Path, format: OutputFormat) -> Result<u8, Box<dyn std::error::Error>> {
    let (pilot_spec, expectation_manifest) = pilot_spec()?;
    let started = std::time::Instant::now();
    let configured_root = std::env::var_os(&pilot_spec.root_env)
        .map(PathBuf::from)
        .unwrap_or_else(|| engine_root.join(&pilot_spec.default_relative_root));
    let pilot_root = if configured_root.is_absolute() {
        configured_root
    } else {
        engine_root.join(configured_root)
    };
    let pilot_root = canonical_project_root(&pilot_root)?;
    let before_hashes = source_hashes(&pilot_root)?;
    let config = Config::default();
    let report = scan(&pilot_root, &config, &[], &built_in_rules(), "pilot")?;
    let mut rule_counts = BTreeMap::new();
    let mut fingerprints = Vec::new();
    for finding in &report.findings {
        *rule_counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
        if let Some(fingerprint) = &finding.occurrence_id {
            fingerprints.push(fingerprint.clone());
        }
    }
    fingerprints.sort();
    let observed_expectations = pilot_expectations(&report);
    let expectations = expectation_manifest
        .expectations
        .keys()
        .map(|name| {
            (
                name.clone(),
                observed_expectations.get(name).copied().unwrap_or(false),
            )
        })
        .collect::<BTreeMap<_, _>>();

    // Exercise safe-write plumbing only on an isolated copy. The real pilot
    // tree is hashed before and after this operation and is never written.
    let temporary_fix_status = if pilot_spec.temporary_copy_write_test {
        run_temporary_fix(&pilot_root, &config)?
    } else {
        "disabled_by_manifest".into()
    };
    let after_hashes = source_hashes(&pilot_root)?;
    let source_unchanged = before_hashes == after_hashes;

    let tool_versions = ["rojo", "luau-analyze", "luau-compile", "stylua"]
        .into_iter()
        .map(|program| (program.to_string(), tool_version(program)))
        .collect::<BTreeMap<_, _>>();
    let verification_config = VerifyConfig {
        commands: vec![
            VerifyCommand {
                kind: VerifyKind::Generic,
                name: "luau-reparse".into(),
                program: "luau-compile".into(),
                args: vec!["--only-parse".into(), "{changed}".into()],
                timeout_ms: Some(60_000),
                required: false,
                ..Default::default()
            },
            VerifyCommand {
                kind: VerifyKind::RojoBuild,
                name: "rojo-build".into(),
                program: "rojo".into(),
                args: vec!["build".into(), "default.project.json".into()],
                timeout_ms: Some(60_000),
                required: false,
                ..Default::default()
            },
        ],
        ..VerifyConfig::default()
    };
    let pilot_files = discover_files(&pilot_root, &config, &[])?;
    let verification = run_verification(&pilot_root, &verification_config, &pilot_files);
    let verification_steps = verification
        .steps
        .iter()
        .map(|step| PilotVerification {
            name: step.name.clone(),
            status: step.status.clone(),
            exit_code: step.exit_code,
            duration_ms: step.duration_ms,
            output_truncated: step.output_truncated,
        })
        .collect::<Vec<_>>();
    let required_verifiers_passed = pilot_spec.official_verifiers.iter().all(|name| {
        let expected = match name.as_str() {
            "luau_reparse" => "luau-reparse",
            "rojo_build" => "rojo-build",
            other => other,
        };
        verification
            .steps
            .iter()
            .any(|step| step.name == expected && step.status == "passed")
    });
    let rojo_passed = !pilot_spec.official_gate_requires_rojo
        || verification
            .steps
            .iter()
            .any(|step| step.name == "rojo-build" && step.status == "passed");
    let checkout_commit = git_commit(&pilot_root);
    let official_gate_complete = report.parse_errors == 0
        && required_verifiers_passed
        && rojo_passed
        && checkout_commit.as_deref() == Some(pilot_spec.commit.as_str());
    let expectations_passed = expectations.values().all(|value| *value);
    let pilot_report = PilotReport {
        schema_version: 1,
        pilot: pilot_spec.name,
        files_scanned: report.summary.files_scanned,
        bytes_scanned: report.summary.bytes_scanned,
        findings: report.summary.findings,
        parse_errors: report.parse_errors,
        rule_counts,
        fingerprints,
        expectations,
        source_unchanged,
        temporary_fix_status,
        verification: verification_steps,
        tool_versions,
        expected_commit: pilot_spec.commit,
        checkout_commit,
        official_gate_complete,
        duration_ms: started.elapsed().as_millis(),
    };
    match format {
        OutputFormat::Human => print_pilot_human(&pilot_report, &pilot_root),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&pilot_report)?),
        OutputFormat::Sarif => return Err("SARIF output is supported only by check".into()),
    }
    if report.parse_errors > 0 {
        Ok(2)
    } else if !expectations_passed || !source_unchanged || !official_gate_complete {
        Ok(1)
    } else {
        Ok(0)
    }
}

fn pilot_expectations(report: &ScanReport) -> BTreeMap<String, bool> {
    let mut expectations = BTreeMap::new();
    expectations.insert(
        "data_load_failure_default_found".into(),
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-002"),
    );
    expectations.insert(
        "two_unguarded_server_remotes_found".into(),
        report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RBX-NET-001")
            .count()
            >= 2,
    );
    expectations.insert(
        "data_service_has_no_owner_violation".into(),
        !report.findings.iter().any(|finding| {
            finding.rule_id == "RBX-DATA-001"
                && finding.path.to_ascii_lowercase().contains("dataservice")
        }),
    );
    expectations.insert(
        "conveyor_has_no_frame_traversal".into(),
        !report.findings.iter().any(|finding| {
            finding.rule_id == "RBX-PERF-001"
                && finding
                    .path
                    .to_ascii_lowercase()
                    .contains("conveyorcontroller")
        }),
    );
    expectations
}

fn print_pilot_human(report: &PilotReport, root: &Path) {
    println!("Slime Farm pilot: {}", root.display());
    println!(
        "scanned {} files ({} bytes), {} findings, {} ms",
        report.files_scanned, report.bytes_scanned, report.findings, report.duration_ms
    );
    for (rule, count) in &report.rule_counts {
        println!("  {rule}: {count}");
    }
    for (name, passed) in &report.expectations {
        println!("  {}: {}", name, if *passed { "pass" } else { "fail" });
    }
    println!("source unchanged: {}", report.source_unchanged);
    println!(
        "checkout commit: {} (expected {})",
        report.checkout_commit.as_deref().unwrap_or("unknown"),
        report.expected_commit
    );
    println!("temporary safe-fix copy: {}", report.temporary_fix_status);
    for step in &report.verification {
        println!("  verifier {}: {}", step.name, step.status);
    }
    if !report.official_gate_complete {
        println!("official gate incomplete: install/configure real Rojo to run the build gate");
    }
}

fn source_hashes(root: &Path) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    let mut hashes = BTreeMap::new();
    collect_source_hashes(root, root, &mut hashes)?;
    Ok(hashes)
}

fn git_commit(root: &Path) -> Option<String> {
    let root_text = root.to_string_lossy();
    let root_text = root_text.strip_prefix("\\\\?\\").unwrap_or(&root_text);
    let output = std::process::Command::new("git")
        .arg("-c")
        .arg(format!("safe.directory={root_text}"))
        .arg("-C")
        .arg(root_text)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn collect_source_hashes(
    root: &Path,
    current: &Path,
    hashes: &mut BTreeMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let walker = walkdir::WalkDir::new(current)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            !entry.file_type().is_dir()
                || !matches!(
                    entry.file_name().to_string_lossy().as_ref(),
                    ".git" | "build" | "node_modules" | "Packages" | "ServerPackages"
                )
        });
    for entry in walker {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type().is_symlink() {
            // A symlink is not traversed, but it still must resolve inside the
            // selected root before the pilot can claim its hash is trustworthy.
            rbx_heal_core::path::validate_existing_path(root, path)?;
            continue;
        }
        if entry.file_type().is_dir() {
            // Junctions may be reported as directories on Windows. Validate
            // the canonical target before allowing the walker to descend.
            rbx_heal_core::path::validate_existing_path(root, path)?;
        }
        if entry.file_type().is_file()
            && path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| matches!(extension, "lua" | "luau"))
        {
            let validated = validate_existing_file(root, path)?;
            let relative = relative_utf8(root, validated.absolute())?;
            hashes.insert(
                relative,
                blake3::hash(&fs::read(validated.absolute())?)
                    .to_hex()
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn run_temporary_fix(
    source_root: &Path,
    config: &Config,
) -> Result<String, Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let copy_root = temp.path().join("slime-farm-copy");
    copy_tree(source_root, &copy_root)?;
    let synthetic = copy_root.join("src").join("__rbx_heal_synthetic__.luau");
    if let Some(parent) = synthetic.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&synthetic, "local Players = game:service(\"Players\")\n")?;
    let report = scan(&copy_root, config, &[], &built_in_rules(), "pilot-copy")?;
    let safe = report.safe_fixes().cloned().collect::<Vec<_>>();
    if safe.is_empty() {
        return Ok("synthetic_fixture_not_detected".into());
    }
    if rbx_heal_core::transaction::commit_fixes(&copy_root, config, safe.into_iter()).is_err() {
        return Ok("safe_write_failed".into());
    }

    // Exercise the rollback path with a verifier that passes `--version` but
    // exits non-zero for the actual transaction. Using this executable keeps
    // the fixture portable and still sends argv directly without an engine-
    // inserted shell.
    let rollback_root = temp.path().join("slime-farm-rollback-copy");
    copy_tree(source_root, &rollback_root)?;
    let rollback_synthetic = rollback_root
        .join("src")
        .join("__rbx_heal_synthetic__.luau");
    if let Some(parent) = rollback_synthetic.parent() {
        fs::create_dir_all(parent)?;
    }
    let rollback_original = "local Players = game:service(\"Players\")\n";
    fs::write(&rollback_synthetic, rollback_original)?;
    let rollback_report = scan(&rollback_root, config, &[], &built_in_rules(), "pilot-copy")?;
    let rollback_safe = rollback_report.safe_fixes().cloned().collect::<Vec<_>>();
    if rollback_safe.is_empty() {
        return Ok("rollback_fixture_not_detected".into());
    }
    let failing_program = std::env::current_exe()?;
    let failing_config = Config {
        verify: VerifyConfig {
            commands: vec![VerifyCommand {
                kind: VerifyKind::Generic,
                name: "pilot-failing-verifier".into(),
                program: failing_program.to_string_lossy().into_owned(),
                args: vec!["__rbx_heal_pilot_fail__".into()],
                timeout_ms: Some(5_000),
                required: true,
                ..Default::default()
            }],
            ..VerifyConfig::default()
        },
        ..config.clone()
    };
    let rollback_result = rbx_heal_core::transaction::commit_fixes(
        &rollback_root,
        &failing_config,
        rollback_safe.into_iter(),
    );
    if !matches!(
        rollback_result,
        Err(TransactionError::VerificationFailed { .. })
    ) || fs::read_to_string(&rollback_synthetic)? != rollback_original
    {
        return Ok("rollback_failed".into());
    }
    Ok("passed".into())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let path = entry.path();
        let target = destination.join(entry.file_name());
        let name = entry.file_name().to_string_lossy().to_string();
        rbx_heal_core::path::validate_existing_path(source, &path)?;
        if entry.file_type()?.is_symlink() {
            continue;
        }
        if entry.file_type()?.is_dir() {
            if matches!(
                name.as_str(),
                ".git" | "build" | "node_modules" | "Packages" | "ServerPackages"
            ) {
                continue;
            }
            copy_tree(&path, &target)?;
        } else {
            fs::copy(path, target)?;
        }
    }
    Ok(())
}

fn tool_version(program: &str) -> String {
    let identity = command_identity(program);
    if identity == "missing" || identity == "aftman_shim" {
        "missing".into()
    } else {
        identity
            .rsplit_once(": ")
            .map(|(_, version)| version)
            .unwrap_or(identity.as_str())
            .chars()
            .take(128)
            .collect()
    }
}

fn run_scan(
    root: &Path,
    config: &Config,
    paths: &[PathBuf],
    command: &str,
    use_baseline: bool,
) -> Result<ScanReport, Box<dyn std::error::Error>> {
    let mut report = scan(root, config, paths, &built_in_rules(), command)?;
    if use_baseline {
        baseline::apply(root, &mut report, paths.is_empty())?;
    }
    Ok(report)
}

fn emit_report(
    report: &ScanReport,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    emit_report_with_patches(report, format, None)
}

fn emit_report_with_patches(
    report: &ScanReport,
    format: OutputFormat,
    patches: Option<&[FilePatchV1]>,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Json => {
            #[derive(serde::Serialize)]
            struct Envelope<'a> {
                schema_version: u32,
                summary: &'a rbx_heal_core::model::RunSummary,
                findings: &'a [Finding],
                files: &'a [rbx_heal_core::model::FileSummary],
                #[serde(skip_serializing_if = "Option::is_none")]
                patches: Option<&'a [FilePatchV1]>,
            }
            let envelope = Envelope {
                schema_version: 1,
                summary: &report.summary,
                findings: &report.findings,
                files: &report.files,
                patches,
            };
            println!("{}", serde_json::to_string_pretty(&envelope)?);
        }
        OutputFormat::Human => {
            println!(
                "rbx-heal: {} files, {} findings ({} unsuppressed), {} safe fixes in {} ms",
                report.summary.files_scanned,
                report.summary.findings,
                report.summary.unsuppressed_findings,
                report.summary.safe_fixes,
                report.summary.duration_ms
            );
            if let Some(baseline) = &report.summary.baseline {
                println!(
                    "baseline: {} matched, {} new, {} stale ({})",
                    baseline.matched, baseline.new, baseline.stale, baseline.coverage
                );
            }
            for finding in &report.findings {
                let state = if finding.suppressed {
                    "suppressed".to_string()
                } else if finding.baseline_state == Some(BaselineState::Matched) {
                    "baseline".to_string()
                } else {
                    finding.severity.to_string()
                };
                println!(
                    "{} [{}] {}:{}:{} {} ({})",
                    state,
                    finding.rule_id,
                    finding.path,
                    finding.range.start.line,
                    finding.range.start.column,
                    finding.message,
                    finding.fixability
                );
                if let Some(reason) = &finding.suppression_reason {
                    println!("  reason: {reason}");
                }
            }
        }
        OutputFormat::Sarif => {
            println!("{}", render_sarif(report)?);
        }
    }
    Ok(())
}

fn emit_baseline_action(
    baseline: &BaselineFile,
    action: &BaselineAction,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Human => {
            println!(
                "baseline {}: {} entries ({}; {} stale)",
                action.action,
                action.entries,
                if action.written {
                    "written"
                } else {
                    "preview only"
                },
                action.stale
            );
            println!("reason: {}", baseline.reason);
        }
        OutputFormat::Json => {
            #[derive(serde::Serialize)]
            struct Envelope<'a> {
                schema_version: u32,
                baseline: &'a BaselineFile,
                action: &'a BaselineAction,
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&Envelope {
                    schema_version: 1,
                    baseline,
                    action,
                })?
            );
        }
        OutputFormat::Sarif => {
            return Err("SARIF output is supported only by check".into());
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(serde::Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(serde::Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(serde::Serialize)]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(serde::Serialize)]
struct SarifRule {
    id: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifText,
    #[serde(rename = "fullDescription")]
    full_description: SarifText,
    help: SarifText,
    properties: BTreeMap<String, String>,
}

#[derive(serde::Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifText,
    locations: Vec<SarifLocation>,
    #[serde(rename = "partialFingerprints")]
    partial_fingerprints: BTreeMap<String, String>,
    #[serde(rename = "baselineState", skip_serializing_if = "Option::is_none")]
    baseline_state: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    suppressions: Vec<SarifSuppression>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fixes: Vec<SarifFix>,
}

#[derive(serde::Serialize)]
struct SarifText {
    text: String,
}

#[derive(serde::Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(serde::Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(serde::Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(serde::Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
    #[serde(rename = "startColumn")]
    start_column: usize,
    #[serde(rename = "endLine")]
    end_line: usize,
    #[serde(rename = "endColumn")]
    end_column: usize,
}

#[derive(serde::Serialize)]
struct SarifSuppression {
    kind: String,
    justification: String,
}

#[derive(serde::Serialize)]
struct SarifFix {
    description: SarifText,
    #[serde(rename = "artifactChanges")]
    artifact_changes: Vec<SarifArtifactChange>,
}

#[derive(serde::Serialize)]
struct SarifArtifactChange {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    replacements: Vec<SarifReplacement>,
}

#[derive(serde::Serialize)]
struct SarifReplacement {
    #[serde(rename = "deletedRegion")]
    deleted_region: SarifRegion,
    #[serde(rename = "insertedContent")]
    inserted_content: SarifText,
}

fn render_sarif(report: &ScanReport) -> Result<String, Box<dyn std::error::Error>> {
    if report.findings.len() > 25_000 {
        return Err(
            "SARIF output exceeds GitHub's 25,000-result limit; use JSON or split the scan".into(),
        );
    }
    let rules = built_in_rules();
    let mut rule_map = BTreeMap::<String, SarifRule>::new();
    for rule in &rules {
        let metadata = rule.metadata();
        rule_map.insert(metadata.id.to_owned(), sarif_rule_from_metadata(metadata));
    }
    for finding in &report.findings {
        rule_map
            .entry(finding.rule_id.clone())
            .or_insert_with(|| SarifRule {
                id: finding.rule_id.clone(),
                short_description: SarifText {
                    text: finding.category.clone(),
                },
                full_description: SarifText {
                    text: finding.message.clone(),
                },
                help: SarifText {
                    text: String::new(),
                },
                properties: BTreeMap::new(),
            });
    }
    let results = report
        .findings
        .iter()
        .map(sarif_result)
        .collect::<Result<Vec<_>, _>>()?;
    let log = SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "rbx-heal",
                    version: env!("CARGO_PKG_VERSION"),
                    rules: rule_map.into_values().collect(),
                },
            },
            results,
        }],
    };
    Ok(serde_json::to_string_pretty(&log)?)
}

fn sarif_rule_from_metadata(metadata: &rbx_heal_core::RuleMetadata) -> SarifRule {
    let mut properties = BTreeMap::new();
    properties.insert("category".into(), metadata.category.into());
    properties.insert("severity".into(), metadata.default_severity.to_string());
    properties.insert("confidence".into(), metadata.default_confidence.to_string());
    properties.insert("semanticPattern".into(), metadata.semantic_pattern.into());
    SarifRule {
        id: metadata.id.into(),
        short_description: SarifText {
            text: metadata.summary.into(),
        },
        full_description: SarifText {
            text: metadata.rationale.into(),
        },
        help: SarifText {
            text: metadata.remediation.into(),
        },
        properties,
    }
}

fn sarif_result(finding: &Finding) -> Result<SarifResult, Box<dyn std::error::Error>> {
    let mut partial_fingerprints = BTreeMap::new();
    partial_fingerprints.insert(
        "primaryLocationLineHash".into(),
        finding
            .baseline_id
            .clone()
            .unwrap_or_else(|| sarif_fallback_fingerprint(finding)),
    );
    let baseline_state = Some(match finding.baseline_state.unwrap_or(BaselineState::New) {
        BaselineState::New => "new".into(),
        BaselineState::Matched => "unchanged".into(),
    });
    let suppressions = finding
        .suppressed
        .then(|| SarifSuppression {
            kind: finding
                .suppression_origin
                .clone()
                .unwrap_or_else(|| "external".into()),
            justification: finding
                .suppression_reason
                .clone()
                .unwrap_or_else(|| "suppressed by project policy".into()),
        })
        .into_iter()
        .collect();
    let fixes = if finding.fixability == rbx_heal_core::Fixability::Safe {
        let edits = if finding.edits.is_empty() {
            finding.edit.iter().cloned().collect::<Vec<_>>()
        } else {
            finding.edits.clone()
        };
        if edits.is_empty() {
            Vec::new()
        } else {
            vec![SarifFix {
                description: SarifText {
                    text: finding
                        .fix_description
                        .clone()
                        .unwrap_or_else(|| "apply safe fix".into()),
                },
                artifact_changes: vec![SarifArtifactChange {
                    artifact_location: SarifArtifactLocation {
                        uri: sarif_uri(&finding.path),
                    },
                    replacements: edits
                        .into_iter()
                        .map(|edit| SarifReplacement {
                            deleted_region: sarif_region(edit.range),
                            inserted_content: SarifText {
                                text: edit.replacement,
                            },
                        })
                        .collect(),
                }],
            }]
        }
    } else {
        Vec::new()
    };
    Ok(SarifResult {
        rule_id: finding.rule_id.clone(),
        level: match finding.severity {
            Severity::Error => "error".into(),
            Severity::Warning => "warning".into(),
            Severity::Info => "note".into(),
        },
        message: SarifText {
            text: finding.message.clone(),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: sarif_uri(&finding.path),
                },
                region: sarif_region(finding.range),
            },
        }],
        partial_fingerprints,
        baseline_state,
        suppressions,
        fixes,
    })
}

fn sarif_region(range: rbx_heal_core::Range) -> SarifRegion {
    SarifRegion {
        start_line: range.start.line.max(1),
        start_column: range.start.column.max(1),
        end_line: range.end.line.max(range.start.line).max(1),
        end_column: range.end.column.max(1),
    }
}

fn sarif_uri(path: &str) -> String {
    let mut uri = String::new();
    for byte in path.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            uri.push(*byte as char);
        } else {
            uri.push('%');
            uri.push_str(&format!("{byte:02X}"));
        }
    }
    uri
}

fn sarif_fallback_fingerprint(finding: &Finding) -> String {
    let value = format!(
        "rbx-heal-sarif-v1|{}|{}|{}|{}",
        finding.rule_id, finding.path, finding.range.start.byte, finding.range.end.byte
    );
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn record_run(report: &ScanReport, root: &Path, action: &str, verification_status: &str) {
    let event = event_from_summary_with_findings(
        &report.summary,
        root,
        action,
        &report.findings,
        verification_status,
    );
    if let Err(error) = record(&event) {
        eprintln!("warning: could not record local history: {error}");
    }
}

fn save_preview_artifacts(
    destination: &Path,
    root: &Path,
    findings: &[Finding],
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(destination)?;
    for (index, finding) in findings.iter().enumerate() {
        let path = validate_existing_file(root, Path::new(&finding.path))?.into_absolute();
        let source = std::fs::read_to_string(&path)?;
        let preview =
            rbx_heal_core::transaction::preview_fixes(root, std::iter::once(finding.clone()))?;
        if let Some(candidate) = preview.files.get(&path) {
            let name = format!(
                "{}-{}-{index}",
                finding.rule_id,
                sanitize_name(&finding.path)
            );
            std::fs::write(
                destination.join(format!("{name}.diff")),
                unified_diff(&diff_label(&path, root), &source, candidate),
            )?;
        }
    }
    Ok(())
}

fn sanitize_name(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn unified_diff(path: &str, before: &str, after: &str) -> String {
    let mut output = format!("--- a/{path}\n+++ b/{path}\n");
    for line in before.lines() {
        output.push('-');
        output.push_str(line);
        output.push('\n');
    }
    for line in after.lines() {
        output.push('+');
        output.push_str(line);
        output.push('\n');
    }
    output
}

fn diff_label(path: &Path, root: &Path) -> String {
    relative_utf8(root, path).unwrap_or_else(|_| "<invalid-path>".into())
}

fn doctor(
    root: &Path,
    explicit: Option<&Path>,
    format: OutputFormat,
) -> Result<u8, Box<dyn std::error::Error>> {
    let (config, path) = Config::load(root, explicit)?;
    let mut failed = false;
    let mut checks = Vec::<(String, String, Option<String>)>::new();
    let discovered = discover_files(root, &config, &[])?;
    let mut scope_counts = BTreeMap::<String, usize>::new();
    for file in &discovered {
        let relative = relative_utf8(root, file)?;
        let scope = format!("{:?}", config.scope_for_path(&relative)).to_ascii_lowercase();
        *scope_counts.entry(scope).or_default() += 1;
    }
    checks.push((
        "files".into(),
        format!("{} discovered", discovered.len()),
        None,
    ));
    for scope in ["server", "client", "shared", "production", "unknown"] {
        checks.push((
            format!("scope:{scope}"),
            scope_counts
                .get(scope)
                .map(|count| count.to_string())
                .unwrap_or_else(|| "0".into()),
            None,
        ));
    }
    let datastore_owner_match = config.architecture.datastore_owners.iter().any(|pattern| {
        Glob::new(pattern).ok().is_some_and(|glob| {
            let matcher = glob.compile_matcher();
            discovered.iter().any(|file| {
                relative_utf8(root, file)
                    .ok()
                    .is_some_and(|relative| matcher.is_match(relative))
            })
        })
    });
    checks.push((
        "owner:datastore".into(),
        if datastore_owner_match {
            "matched".into()
        } else {
            "no owner paths matched".into()
        },
        None,
    ));
    if scope_counts.get("server").copied().unwrap_or_default() == 0 {
        checks.push((
            "scope:server-warning".into(),
            "no server files discovered".into(),
            None,
        ));
    }
    let preflight = preflight_verification(&config.verify);
    for (command, step) in config.verify.commands.iter().zip(preflight.steps.iter()) {
        let identity = command_identity(&command.program);
        let available = step.status == "available";
        let status = if identity == "aftman_shim" {
            "aftman shim".to_owned()
        } else {
            step.status.clone()
        };
        checks.push((
            format!("verify:{}", command.name),
            status,
            if identity == "aftman_shim" {
                Some("aftman_shim".to_owned())
            } else if available {
                Some("verified".to_owned())
            } else {
                None
            },
        ));
        if command.required && !available {
            failed = true;
        }
    }
    for (name, program) in [
        ("rojo", "rojo"),
        ("luau-analyze", "luau-analyze"),
        ("stylua", "stylua"),
    ] {
        let identity = command_identity(program);
        let available = identity != "missing" && identity != "aftman_shim";
        checks.push((
            format!("optional:{name}"),
            if identity == "aftman_shim" {
                "aftman shim".into()
            } else if available {
                "available".into()
            } else {
                "not installed".into()
            },
            match identity.as_str() {
                "aftman_shim" => Some("aftman_shim".to_owned()),
                "missing" => None,
                _ => Some("verified".to_owned()),
            },
        ));
    }
    let mut baseline_summary = None::<BaselineSummaryV1>;
    match baseline::load(root) {
        Ok(Some(_)) => {
            let report = run_scan(root, &config, &[], "doctor", true)?;
            baseline_summary = report.summary.baseline.clone();
            let stale = baseline_summary
                .as_ref()
                .map(|summary| summary.stale)
                .unwrap_or(0);
            checks.push((
                "baseline".into(),
                if stale == 0 {
                    "valid".into()
                } else {
                    format!("valid; {stale} stale")
                },
                Some(format!(
                    "fingerprint-v{}",
                    baseline_summary
                        .as_ref()
                        .map(|summary| summary.fingerprint_version)
                        .unwrap_or(0)
                )),
            ));
            if report.parse_errors > 0 {
                checks.push((
                    "baseline:coverage".into(),
                    "parse errors prevent a complete coverage check".into(),
                    None,
                ));
            }
        }
        Ok(None) => checks.push(("baseline".into(), "not configured".into(), None)),
        Err(error) => {
            checks.push(("baseline".into(), "malformed".into(), None));
            eprintln!("warning: {error}");
            failed = true;
        }
    }
    let enabled_rules = built_in_rules()
        .iter()
        .filter(|rule| config.is_enabled(rule.id()))
        .count();
    match format {
        OutputFormat::Human => {
            println!("project: {}", root.display());
            println!(
                "config: {}",
                path.map_or_else(|| "defaults".into(), |path| path.display().to_string())
            );
            println!("files discovered: {}", discovered.len());
            println!("scope distribution: {:?}", scope_counts);
            for (name, status, identity) in checks {
                if let Some(identity) = identity {
                    println!("{name}: {status} ({identity})");
                } else {
                    println!("{name}: {status}");
                }
            }
            println!("enabled rules: {enabled_rules}/{}", built_in_rules().len());
        }
        OutputFormat::Json => {
            #[derive(serde::Serialize)]
            struct Doctor<'a> {
                schema_version: u32,
                project: &'a str,
                config: Option<String>,
                checks: Vec<DoctorCheck>,
                built_in_rules: usize,
                enabled_rules: usize,
                files_scanned: usize,
                scope_counts: BTreeMap<String, usize>,
                #[serde(skip_serializing_if = "Option::is_none")]
                baseline: Option<BaselineSummaryV1>,
                passed: bool,
            }
            #[derive(serde::Serialize)]
            struct DoctorCheck {
                name: String,
                status: String,
                #[serde(skip_serializing_if = "Option::is_none")]
                identity: Option<String>,
            }
            let checks = checks
                .into_iter()
                .map(|(name, status, identity)| DoctorCheck {
                    name,
                    status,
                    identity,
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&Doctor {
                    schema_version: 1,
                    project: ".",
                    config: path.and_then(|path| {
                        let canonical = fs::canonicalize(path).ok()?;
                        relative_utf8(root, &canonical).ok()
                    }),
                    checks,
                    built_in_rules: built_in_rules().len(),
                    enabled_rules,
                    files_scanned: discovered.len(),
                    scope_counts,
                    baseline: baseline_summary,
                    passed: !failed,
                })?
            );
        }
        OutputFormat::Sarif => return Err("SARIF output is supported only by check".into()),
    }
    Ok(if failed { 2 } else { 0 })
}
