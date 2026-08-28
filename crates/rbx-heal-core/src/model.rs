use crate::config::ScopeKind;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity used by policy thresholds and machine-readable output.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    #[default]
    Warning,
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        })
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "warning" | "warn" => Ok(Self::Warning),
            "error" | "err" => Ok(Self::Error),
            other => Err(format!("unknown severity `{other}`")),
        }
    }
}

/// How confidently a rule can attribute a finding to a source pattern.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    #[default]
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        })
    }
}

/// Whether a finding can be changed automatically.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fixability {
    #[default]
    None,
    Suggested,
    Safe,
}

/// Whether a finding is new relative to the checked-in project baseline.
/// This is deliberately separate from suppression: a matched baseline entry
/// remains visible and reviewable, it simply does not fail the policy gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BaselineState {
    New,
    Matched,
}

impl fmt::Display for BaselineState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::New => "new",
            Self::Matched => "matched",
        })
    }
}

impl fmt::Display for Fixability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Fixability::None => "none",
            Fixability::Suggested => "suggested",
            Fixability::Safe => "safe",
        })
    }
}

/// One-based source location with a byte offset for lossless edits.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Position {
    pub line: usize,
    pub column: usize,
    pub byte: usize,
}

/// Half-open source range.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

/// A guarded text edit. `expected` is checked immediately before application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edit {
    pub range: Range,
    pub expected: String,
    pub replacement: String,
}

/// A JSON-safe representation of a guarded edit in a patch preview.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PatchEditV1 {
    pub range: Range,
    pub expected: String,
    pub replacement: String,
}

/// Machine-readable preview for one changed file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilePatchV1 {
    pub path: String,
    pub original_hash: String,
    pub candidate_hash: String,
    #[serde(default)]
    pub rule_ids: Vec<String>,
    pub edits: Vec<PatchEditV1>,
}

/// Stable name for an individual machine-readable fix preview entry.
pub type FixPreviewV1 = FilePatchV1;

/// Structured evidence kept alongside the legacy string evidence field.
/// Ranges are optional because some evidence (for example a config decision)
/// has no source location.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EvidenceDetail {
    pub kind: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<Range>,
}

impl Edit {
    pub fn new(range: Range, expected: impl Into<String>, replacement: impl Into<String>) -> Self {
        Self {
            range,
            expected: expected.into(),
            replacement: replacement.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub schema_version: u32,
    pub rule_id: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub path: String,
    pub range: Range,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_details: Vec<EvidenceDetail>,
    pub fixability: Fixability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_description: Option<String>,
    #[serde(default)]
    pub suppressed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppression_reason: Option<String>,
    /// Internal origin used when rendering SARIF suppression kinds. It is
    /// deliberately omitted from the public JSON contract; the reason remains
    /// the user-facing field.
    #[serde(skip)]
    pub suppression_origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurrence_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_state: Option<BaselineState>,
    #[serde(skip)]
    pub edit: Option<Edit>,
    /// All guarded edits returned by the rule contract. The `edit` field is
    /// retained as a compatibility shortcut for the single-edit MVP model.
    #[serde(skip)]
    pub edits: Vec<Edit>,
    /// Hash captured during the scan; used to reject edits when unrelated bytes changed.
    #[serde(skip)]
    pub source_hash: Option<String>,
    /// Semantic anchor and statement digest used to derive the portable
    /// baseline identity. These are internal and never serialized.
    #[serde(skip)]
    pub(crate) baseline_anchor: Option<String>,
    #[serde(skip)]
    pub(crate) baseline_statement: Option<String>,
}

/// Stable JSON schema aliases for consumers that want explicit versioned names.
pub type FindingV1 = Finding;

impl Finding {
    pub fn new(
        rule_id: impl Into<String>,
        category: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        path: impl Into<String>,
        range: Range,
        message: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            rule_id: rule_id.into(),
            category: category.into(),
            severity,
            confidence,
            path: path.into(),
            range,
            message: message.into(),
            evidence: Vec::new(),
            evidence_details: Vec::new(),
            fixability: Fixability::None,
            fix_description: None,
            suppressed: false,
            suppression_reason: None,
            suppression_origin: None,
            scope: None,
            semantic_pattern: None,
            confidence_reason: None,
            occurrence_id: None,
            remediation: None,
            baseline_id: None,
            baseline_state: None,
            edit: None,
            edits: Vec::new(),
            source_hash: None,
            baseline_anchor: None,
            baseline_statement: None,
        }
    }

    pub fn with_evidence(mut self, evidence: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.evidence = evidence.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_evidence_details(
        mut self,
        evidence: impl IntoIterator<Item = EvidenceDetail>,
    ) -> Self {
        self.evidence_details = evidence.into_iter().collect();
        self
    }

    pub fn with_semantic_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.semantic_pattern = Some(pattern.into());
        self
    }

    pub fn with_confidence_reason(mut self, reason: impl Into<String>) -> Self {
        self.confidence_reason = Some(reason.into());
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    pub fn with_fix(
        mut self,
        fixability: Fixability,
        description: impl Into<String>,
        edit: Edit,
    ) -> Self {
        self.fixability = fixability;
        self.fix_description = Some(description.into());
        self.edit = Some(edit.clone());
        self.edits = vec![edit];
        self
    }

    pub fn suggested(mut self, description: impl Into<String>) -> Self {
        self.fixability = Fixability::Suggested;
        self.fix_description = Some(description.into());
        self
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FileSummary {
    pub path: String,
    pub bytes: usize,
    pub findings: usize,
    pub parse_ok: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VerificationStep {
    pub name: String,
    pub status: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    #[serde(default)]
    pub output_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RunSummary {
    pub schema_version: u32,
    pub command: String,
    pub project: String,
    pub files_scanned: usize,
    pub bytes_scanned: usize,
    pub findings: usize,
    pub unsuppressed_findings: usize,
    pub safe_fixes: usize,
    pub duration_ms: u128,
    pub verification: Vec<VerificationStep>,
    pub transaction: String,
    #[serde(default)]
    pub parse_errors: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_threshold: Option<Severity>,
    #[serde(default)]
    pub fingerprint_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineSummaryV1>,
}

/// Additive JSON v1 summary for project-baseline matching.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BaselineSummaryV1 {
    pub enabled: bool,
    pub coverage: String,
    pub matched: usize,
    pub new: usize,
    pub stale: usize,
    #[serde(default)]
    pub fingerprint_version: u32,
}

/// Stable JSON schema alias for the run envelope metadata.
pub type RunSummaryV1 = RunSummary;
