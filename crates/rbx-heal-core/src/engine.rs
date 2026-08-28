use crate::{
    config::{Config, ScopeKind},
    discovery::discover_files,
    model::{
        Confidence, Edit, FileSummary, Finding, Fixability, Position, Range, RunSummary, Severity,
    },
    parser::{parse_path, LexKind, ParsedFile},
    suppression::apply_suppressions,
};
use rayon::prelude::*;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Instant,
};
use thiserror::Error;

/// Metadata and behavior for one deterministic rule.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct RuleExample {
    pub label: &'static str,
    pub source: &'static str,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct RuleMetadata {
    pub id: &'static str,
    pub category: &'static str,
    pub default_severity: Severity,
    pub default_confidence: Confidence,
    pub fixability: Fixability,
    pub applicable_scopes: &'static [ScopeKind],
    pub summary: &'static str,
    pub rationale: &'static str,
    pub remediation: &'static str,
    pub examples: &'static [RuleExample],
    pub semantic_pattern: &'static str,
}

/// Context passed to the public rule interface.
pub struct RuleContext<'a> {
    pub file: &'a ParsedFile,
    pub config: &'a Config,
}

/// Versioned name for a rule-produced finding.  It aliases the JSON model so
/// old consumers can continue to use `Finding` directly.
pub type RuleFinding = Finding;

/// Public rule contract used by the engine and agent-facing integrations.
/// Implementations receive one indexed file context and may return guarded
/// byte edits only when a finding is proven safe.
pub trait Rule: Send + Sync {
    fn metadata(&self) -> &'static RuleMetadata;
    fn analyze(&self, context: &RuleContext<'_>, output: &mut Vec<RuleFinding>);
    fn safe_fix(&self, _context: &RuleContext<'_>, _finding: &RuleFinding) -> Option<Vec<Edit>> {
        None
    }

    fn id(&self) -> &'static str {
        self.metadata().id
    }
    fn category(&self) -> &'static str {
        self.metadata().category
    }
    fn default_severity(&self) -> Severity {
        self.metadata().default_severity
    }
    fn default_confidence(&self) -> Confidence {
        self.metadata().default_confidence
    }
    fn fixability(&self) -> Fixability {
        self.metadata().fixability
    }
    fn description(&self) -> &'static str {
        self.metadata().summary
    }
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error(transparent)]
    Discovery(#[from] crate::discovery::DiscoveryError),
    #[error("invalid project path: {0}")]
    Path(#[from] crate::path::PathError),
}

#[derive(Clone, Debug, Default)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub files: Vec<FileSummary>,
    pub parse_errors: usize,
    pub summary: RunSummary,
}

type ScanOneSuccess = (FileSummary, Vec<Finding>);
type ScanOneFailure = Box<(FileSummary, Finding)>;

impl ScanReport {
    pub fn unsuppressed_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|finding| !finding.suppressed)
    }

    pub fn has_policy_findings(&self, threshold: Severity) -> bool {
        self.unsuppressed_findings().any(|finding| {
            finding.severity >= threshold
                && finding.baseline_state != Some(crate::model::BaselineState::Matched)
        })
    }

    pub fn safe_fixes(&self) -> impl Iterator<Item = &Finding> {
        self.unsuppressed_findings().filter(|finding| {
            finding.fixability == Fixability::Safe
                && (!finding.edits.is_empty() || finding.edit.is_some())
        })
    }
}

pub fn scan(
    project_root: &Path,
    config: &Config,
    inputs: &[PathBuf],
    rules: &[Box<dyn Rule>],
    command_name: &str,
) -> Result<ScanReport, ScanError> {
    let started = Instant::now();
    let project_root = crate::path::canonical_project_root(project_root)?;
    let paths = discover_files(&project_root, config, inputs)?;
    let mut report = ScanReport::default();
    let results = paths
        .par_iter()
        .map(|path| scan_one(path, &project_root, config, rules))
        .collect::<Vec<_>>();
    for result in results {
        match result {
            Ok((file, findings)) => {
                report.files.push(file);
                report.findings.extend(findings);
            }
            Err(error) => {
                let (summary, finding) = *error;
                report.parse_errors += 1;
                report.files.push(summary);
                report.findings.push(finding);
            }
        }
    }

    report.findings.sort_by(|a, b| {
        (&a.path, a.range.start.byte, a.range.end.byte, &a.rule_id).cmp(&(
            &b.path,
            b.range.start.byte,
            b.range.end.byte,
            &b.rule_id,
        ))
    });
    // Assign occurrence IDs only after deterministic ordering. The ID is a
    // keyed digest over semantic identity and an ordinal within that scope;
    // it deliberately excludes offsets, messages and source text.
    let mut occurrence_ordinals = BTreeMap::<(String, String, String, String), usize>::new();
    let mut baseline_ordinals = BTreeMap::<(String, String, String, String, String), usize>::new();
    for finding in &mut report.findings {
        let pattern =
            crate::history::pattern_id(&finding.rule_id, finding.semantic_pattern.as_deref());
        let scope = finding
            .scope
            .map(|scope| format!("{scope:?}"))
            .unwrap_or_else(|| "unknown".into());
        let key = (
            finding.rule_id.clone(),
            finding.path.clone(),
            pattern.clone(),
            scope.clone(),
        );
        let ordinal = occurrence_ordinals.entry(key).or_default();
        finding.occurrence_id = Some(crate::history::stable_fingerprint(
            &project_root,
            &finding.rule_id,
            &finding.path,
            &pattern,
            &scope,
            *ordinal,
        ));
        if let (Some(anchor), Some(statement)) = (
            finding.baseline_anchor.as_deref(),
            finding.baseline_statement.as_deref(),
        ) {
            let key = (
                finding.rule_id.clone(),
                finding.path.clone(),
                pattern.clone(),
                anchor.to_owned(),
                statement.to_owned(),
            );
            let baseline_ordinal = baseline_ordinals.entry(key).or_default();
            finding.baseline_id = Some(crate::history::baseline_fingerprint(
                &finding.rule_id,
                &pattern,
                &finding.path,
                anchor,
                statement,
                *baseline_ordinal,
            ));
            *baseline_ordinal += 1;
        }
        *ordinal += 1;
    }
    let findings = report.findings.len();
    let unsuppressed = report
        .findings
        .iter()
        .filter(|finding| !finding.suppressed)
        .count();
    let safe_fixes = report
        .findings
        .iter()
        .filter(|finding| {
            !finding.suppressed
                && finding.fixability == Fixability::Safe
                && (!finding.edits.is_empty() || finding.edit.is_some())
        })
        .count();
    report.summary = RunSummary {
        schema_version: 1,
        command: command_name.into(),
        // Public JSON must not leak an absolute filesystem path.  The CLI
        // already establishes the project root; reports use a stable relative
        // marker and findings carry only project-relative paths.
        project: ".".into(),
        files_scanned: report.files.len(),
        bytes_scanned: report.files.iter().map(|file| file.bytes).sum(),
        findings,
        unsuppressed_findings: unsuppressed,
        safe_fixes,
        duration_ms: started.elapsed().as_millis(),
        verification: Vec::new(),
        transaction: "none".into(),
        parse_errors: report.parse_errors,
        policy_threshold: Some(config.policy.fail_on),
        fingerprint_version: 2,
        rollback_status: None,
        baseline: None,
    };
    Ok(report)
}

fn scan_one(
    path: &Path,
    project_root: &Path,
    config: &Config,
    rules: &[Box<dyn Rule>],
) -> Result<ScanOneSuccess, ScanOneFailure> {
    match parse_path(path, project_root) {
        Ok(file) => {
            let mut findings = Vec::new();
            analyze_file(&file, config, rules, &mut findings);
            let source_hash = blake3::hash(file.source.as_bytes()).to_hex().to_string();
            for finding in &mut findings {
                finding.source_hash = Some(source_hash.clone());
            }
            Ok((
                FileSummary {
                    path: file.relative_path.clone(),
                    bytes: file.source.len(),
                    findings: findings.len(),
                    parse_ok: true,
                },
                findings,
            ))
        }
        Err(error) => {
            // Discovery already rejects non-UTF-8 paths, but keep the parse
            // error surface fail-closed if a caller supplies a custom path.
            let relative = crate::path::relative_utf8(project_root, path)
                .unwrap_or_else(|_| "<invalid-path>".into());
            Err(Box::new((
                FileSummary {
                    path: relative.clone(),
                    bytes: 0,
                    findings: 1,
                    parse_ok: false,
                },
                Finding::new(
                    "RBX-PARSE-001",
                    "syntax",
                    Severity::Error,
                    Confidence::High,
                    relative,
                    Range {
                        start: Position {
                            line: 1,
                            column: 1,
                            byte: 0,
                        },
                        end: Position {
                            line: 1,
                            column: 1,
                            byte: 0,
                        },
                    },
                    format!("Luau source could not be parsed: {error}"),
                ),
            )))
        }
    }
}

fn analyze_file(
    file: &ParsedFile,
    config: &Config,
    rules: &[Box<dyn Rule>],
    findings: &mut Vec<Finding>,
) {
    let context = RuleContext { file, config };
    let file_scope = config.scope_for_path(&file.relative_path);
    for rule in rules {
        if !config.is_enabled(rule.id()) {
            continue;
        }
        let applicable_scopes = rule.metadata().applicable_scopes;
        if !applicable_scopes.is_empty() && !applicable_scopes.contains(&file_scope) {
            continue;
        }
        let before = findings.len();
        rule.analyze(&context, findings);
        for finding in findings.iter_mut().skip(before) {
            if finding.fixability == Fixability::None
                && rule.metadata().fixability != Fixability::None
            {
                finding.fixability = rule.metadata().fixability;
            }
            if finding.fixability == Fixability::Safe
                && finding.edit.is_none()
                && finding.edits.is_empty()
            {
                if let Some(edits) = rule.safe_fix(&context, finding) {
                    finding.edit = (edits.len() == 1).then(|| edits[0].clone());
                    finding.edits = edits;
                }
            }
            if finding.edits.is_empty() {
                if let Some(edit) = finding.edit.clone() {
                    finding.edits.push(edit);
                }
            }
        }
        for finding in findings[before..].iter_mut() {
            finding.severity = config.severity_for(rule.id(), rule.default_severity());
            if finding.scope.is_none() {
                finding.scope = Some(config.scope_for_path(&finding.path));
            }
            if finding.semantic_pattern.is_none() {
                finding.semantic_pattern = Some(rule.metadata().semantic_pattern.to_string());
            }
            if finding.remediation.is_none() && !rule.metadata().remediation.is_empty() {
                finding.remediation = Some(rule.metadata().remediation.to_string());
            }
            if finding.confidence_reason.is_none() {
                finding.confidence_reason =
                    Some(if rule.default_confidence() == Confidence::High {
                        "rule predicate was proven by indexed syntax and scope facts".into()
                    } else {
                        "rule uses a conservative heuristic and may require review".into()
                    });
            }
            let (anchor, statement) = semantic_identity(file, finding);
            finding.baseline_anchor = Some(anchor);
            finding.baseline_statement = Some(statement);
            apply_suppressions(finding, file, config);
        }
    }
}

/// Build stable, source-free semantic anchors for project baselines. The
/// digest is derived from significant tokens only, so comments and formatting
/// changes do not churn the identity while actual code changes do.
fn semantic_identity(file: &ParsedFile, finding: &Finding) -> (String, String) {
    let token_index = file
        .significant
        .iter()
        .copied()
        .find(|index| file.tokens[*index].range == finding.range)
        .or_else(|| {
            file.significant.iter().copied().find(|index| {
                let range = file.tokens[*index].range;
                range.start.byte < finding.range.end.byte
                    && finding.range.start.byte < range.end.byte
            })
        });
    let Some(token_index) = token_index else {
        return ("file".into(), "unresolved".into());
    };
    let position = file
        .semantic
        .significant_position(token_index)
        .unwrap_or_default();
    let (statement_start, statement_end) = statement_bounds(file, position);
    let statement = digest_tokens(file, statement_start..statement_end);
    let anchor = file
        .semantic
        .enclosing_function(token_index)
        .and_then(|function_id| file.semantic.function(function_id))
        .map(|function| {
            let function_position = file
                .semantic
                .significant_position(function.function_token)
                .unwrap_or(function.body_tokens.start.saturating_sub(1));
            let header_end = function.body_tokens.start.min(file.significant.len());
            let header = digest_tokens(file, function_position..header_end);
            format!(
                "function:{:?}:{}:{}",
                function.kind,
                function.callback_signal.as_deref().unwrap_or(""),
                header
            )
        })
        .unwrap_or_else(|| "file".into());
    (anchor, statement)
}

fn statement_bounds(file: &ParsedFile, position: usize) -> (usize, usize) {
    let mut start = position;
    let mut depth = 0usize;
    while start > 0 {
        let previous = &file.tokens[file.significant[start - 1]];
        let current = &file.tokens[file.significant[start]];
        let text = &previous.text;
        match text.as_str() {
            ")" | "]" | "}" => depth += 1,
            "(" | "[" | "{" if depth > 0 => depth -= 1,
            ";" | "then" | "do" | "else" | "elseif" | "end" | "until" if depth == 0 => break,
            _ if depth == 0
                && previous.range.end.line < current.range.start.line
                && !continues_statement_after(text)
                && !continues_statement_before(&current.text) =>
            {
                break
            }
            _ => {}
        }
        start -= 1;
    }
    let mut end = (position + 1).min(file.significant.len());
    depth = 0;
    while end < file.significant.len() {
        let token = &file.tokens[file.significant[end]];
        let text = &token.text;
        match text.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" if depth > 0 => depth -= 1,
            ";" | "then" | "do" | "else" | "elseif" | "end" | "until" if depth == 0 => break,
            _ if depth == 0
                && file.tokens[file.significant[end - 1]].range.end.line
                    < token.range.start.line
                && !continues_statement_after(&file.tokens[file.significant[end - 1]].text)
                && !continues_statement_before(text) =>
            {
                break
            }
            _ => {}
        }
        end += 1;
    }
    (start, end)
}

fn continues_statement_after(token: &str) -> bool {
    matches!(
        token,
        "." | ":"
            | ","
            | "="
            | "+="
            | "-="
            | "*="
            | "/="
            | "//="
            | "%="
            | "^="
            | "..="
            | "+"
            | "-"
            | "*"
            | "/"
            | "//"
            | "%"
            | "^"
            | ".."
            | "and"
            | "or"
            | "not"
            | "("
            | "{"
            | "["
    )
}

fn continues_statement_before(token: &str) -> bool {
    matches!(
        token,
        "." | ":"
            | ","
            | ")"
            | "}"
            | "]"
            | "+"
            | "-"
            | "*"
            | "/"
            | "//"
            | "%"
            | "^"
            | ".."
            | "and"
            | "or"
    )
}

fn digest_tokens(file: &ParsedFile, range: std::ops::Range<usize>) -> String {
    let mut hasher = blake3::Hasher::new();
    for position in range {
        let Some(token_index) = file.significant.get(position).copied() else {
            continue;
        };
        let token = &file.tokens[token_index];
        let kind = match token.kind {
            LexKind::Identifier => b'i',
            LexKind::String => b's',
            LexKind::Number => b'n',
            LexKind::Symbol => b'y',
            LexKind::Comment => b'c',
            LexKind::Whitespace => b'w',
            LexKind::Other => b'o',
        };
        hasher.update(&[kind]);
        hasher.update(&(token.text.len() as u64).to_le_bytes());
        hasher.update(token.text.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}
