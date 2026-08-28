//! Project-local, reviewable finding baseline support.
//!
//! Baselines are intentionally separate from private history. They contain
//! only deterministic finding metadata and are safe to commit to a project so
//! a team can ratchet CI without hiding the existing debt from reports.

use crate::{
    engine::ScanReport,
    model::{BaselineState, BaselineSummaryV1, Confidence, Fixability, Severity},
    path::{canonical_project_root, validate_relative_input, PathError},
    transaction::{sync_dir, write_atomic_metadata, ProjectLock},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub const BASELINE_SCHEMA_VERSION: u32 = 1;
pub const BASELINE_FINGERPRINT_VERSION: u32 = 1;
pub const BASELINE_RELATIVE_PATH: &str = ".rbx-heal/baseline.json";

#[derive(Debug, Error)]
pub enum BaselineError {
    #[error("baseline I/O failed at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("baseline JSON is invalid at {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("baseline validation failed at {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
    #[error("baseline path is unsafe: {0}")]
    Path(#[from] PathError),
    #[error("could not acquire project lock: {0}")]
    Locked(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineEntry {
    pub id: String,
    pub rule_id: String,
    pub pattern_id: String,
    pub path: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub fixability: Fixability,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineFile {
    pub schema_version: u32,
    pub fingerprint_version: u32,
    pub reason: String,
    pub entries: Vec<BaselineEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BaselineAction {
    pub action: String,
    pub path: String,
    pub entries: usize,
    pub matched: usize,
    pub new: usize,
    pub stale: usize,
    pub written: bool,
}

pub fn baseline_path(project_root: &Path) -> PathBuf {
    project_root.join(BASELINE_RELATIVE_PATH.replace('/', std::path::MAIN_SEPARATOR_STR))
}

/// Read and validate the optional project baseline. A missing metadata
/// directory or file means baseline support is disabled for this run.
pub fn load(project_root: &Path) -> Result<Option<BaselineFile>, BaselineError> {
    let root = canonical_project_root(project_root)?;
    let metadata_dir = root.join(".rbx-heal");
    if let Some(metadata) = symlink_metadata(&metadata_dir)? {
        if is_link_or_junction(&metadata) {
            return Err(BaselineError::Invalid {
                path: metadata_dir,
                reason: "metadata directory must not be a symlink or junction".into(),
            });
        }
        if !metadata.is_dir() {
            return Err(BaselineError::Invalid {
                path: metadata_dir,
                reason: "metadata path is not a directory".into(),
            });
        }
    }
    let path = baseline_path(&root);
    let Some(metadata) = symlink_metadata(&path)? else {
        return Ok(None);
    };
    if is_link_or_junction(&metadata) {
        return Err(BaselineError::Invalid {
            path,
            reason: "baseline file must not be a symlink or junction".into(),
        });
    }
    crate::path::validate_existing_file(&root, &path)?;
    let text = fs::read_to_string(&path).map_err(|source| BaselineError::Io {
        path: path.clone(),
        source,
    })?;
    let baseline =
        serde_json::from_str::<BaselineFile>(&text).map_err(|source| BaselineError::Json {
            path: path.clone(),
            source,
        })?;
    validate_baseline(&root, &path, &baseline)?;
    Ok(Some(baseline))
}

/// Apply baseline state to a scan report. `full_coverage` is false for
/// explicit partial paths, in which case stale entries are deliberately not
/// inferred from files that were not scanned.
pub fn apply(
    project_root: &Path,
    report: &mut ScanReport,
    full_coverage: bool,
) -> Result<(), BaselineError> {
    let Some(baseline) = load(project_root)? else {
        report.summary.baseline = None;
        return Ok(());
    };
    let entries = baseline
        .entries
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut current_ids = BTreeSet::new();
    let mut matched = 0usize;
    let mut new = 0usize;
    for finding in &mut report.findings {
        if let Some(id) = finding.baseline_id.as_deref() {
            current_ids.insert(id.to_owned());
        }
        if finding.suppressed {
            continue;
        }
        match finding.baseline_id.as_deref() {
            Some(id) if entries.contains_key(id) => {
                let entry = entries[id];
                let pattern = crate::history::pattern_id(
                    &finding.rule_id,
                    finding.semantic_pattern.as_deref(),
                );
                if entry.rule_id != finding.rule_id
                    || entry.pattern_id != pattern
                    || entry.path != finding.path
                {
                    return Err(BaselineError::Invalid {
                        path: baseline_path(project_root),
                        reason: format!("baseline entry {id} metadata does not match the finding"),
                    });
                }
                finding.baseline_state = Some(BaselineState::Matched);
                matched += 1;
            }
            Some(_) => {
                finding.baseline_state = Some(BaselineState::New);
                new += 1;
            }
            None => {
                finding.baseline_state = Some(BaselineState::New);
                new += 1;
            }
        }
    }
    let stale = if full_coverage {
        baseline
            .entries
            .iter()
            .filter(|entry| !current_ids.contains(entry.id.as_str()))
            .count()
    } else {
        0
    };
    report.summary.baseline = Some(BaselineSummaryV1 {
        enabled: true,
        coverage: if full_coverage {
            "full".into()
        } else {
            "partial".into()
        },
        matched,
        new,
        stale,
        fingerprint_version: baseline.fingerprint_version,
    });
    Ok(())
}

pub fn create(
    project_root: &Path,
    report: &ScanReport,
    reason: &str,
    write: bool,
) -> Result<(BaselineFile, BaselineAction), BaselineError> {
    let root = canonical_project_root(project_root)?;
    if report.parse_errors > 0 {
        return Err(BaselineError::Invalid {
            path: baseline_path(&root),
            reason: "cannot create a baseline from a scan with parse errors".into(),
        });
    }
    if reason.trim().is_empty() {
        return Err(BaselineError::Invalid {
            path: baseline_path(&root),
            reason: "a non-empty reason is required".into(),
        });
    }
    let entries = entries_from_report(report);
    let baseline = BaselineFile {
        schema_version: BASELINE_SCHEMA_VERSION,
        fingerprint_version: BASELINE_FINGERPRINT_VERSION,
        reason: reason.trim().to_owned(),
        entries,
    };
    let path = baseline_path(&root);
    validate_baseline(&root, &path, &baseline)?;
    let mut action = BaselineAction {
        action: "create".into(),
        path: BASELINE_RELATIVE_PATH.into(),
        entries: baseline.entries.len(),
        matched: 0,
        new: baseline.entries.len(),
        stale: 0,
        written: false,
    };
    if write {
        let _lock = acquire_lock(&root)?;
        reject_existing_baseline(&root, &path)?;
        write_baseline(&root, &path, &baseline)?;
        action.written = true;
    }
    Ok((baseline, action))
}

pub fn prune(
    project_root: &Path,
    report: &ScanReport,
    write: bool,
) -> Result<(BaselineFile, BaselineAction), BaselineError> {
    let root = canonical_project_root(project_root)?;
    let path = baseline_path(&root);
    let Some(mut baseline) = load(&root)? else {
        return Err(BaselineError::Invalid {
            path,
            reason: "no baseline exists".into(),
        });
    };
    if report.parse_errors > 0 {
        return Err(BaselineError::Invalid {
            path,
            reason: "cannot prune a baseline from a scan with parse errors".into(),
        });
    }
    let current_ids = report
        .findings
        .iter()
        .filter_map(|finding| finding.baseline_id.as_deref())
        .collect::<BTreeSet<_>>();
    let before = baseline.entries.len();
    baseline
        .entries
        .retain(|entry| current_ids.contains(entry.id.as_str()));
    let stale = before.saturating_sub(baseline.entries.len());
    let mut action = BaselineAction {
        action: "prune".into(),
        path: BASELINE_RELATIVE_PATH.into(),
        entries: baseline.entries.len(),
        matched: baseline.entries.len(),
        new: 0,
        stale,
        written: false,
    };
    if write && stale > 0 {
        let _lock = acquire_lock(&root)?;
        // Re-read after taking the lock so a concurrent prune/create cannot be
        // overwritten with a stale candidate.
        let current = load(&root)?.ok_or_else(|| BaselineError::Invalid {
            path: baseline_path(&root),
            reason: "baseline disappeared while pruning".into(),
        })?;
        let current_ids = report
            .findings
            .iter()
            .filter_map(|finding| finding.baseline_id.as_deref())
            .collect::<BTreeSet<_>>();
        let mut candidate = current;
        candidate
            .entries
            .retain(|entry| current_ids.contains(entry.id.as_str()));
        write_baseline(&root, &path, &candidate)?;
        baseline = candidate;
        action.entries = baseline.entries.len();
        action.matched = baseline.entries.len();
        action.stale = before.saturating_sub(baseline.entries.len());
        action.written = true;
    }
    Ok((baseline, action))
}

fn entries_from_report(report: &ScanReport) -> Vec<BaselineEntry> {
    let mut entries = report
        .findings
        .iter()
        .filter(|finding| !finding.suppressed)
        .filter_map(|finding| {
            Some(BaselineEntry {
                id: finding.baseline_id.clone()?,
                rule_id: finding.rule_id.clone(),
                pattern_id: crate::history::pattern_id(
                    &finding.rule_id,
                    finding.semantic_pattern.as_deref(),
                ),
                path: finding.path.clone(),
                severity: finding.severity,
                confidence: finding.confidence,
                fixability: finding.fixability,
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| (&a.id, &a.rule_id, &a.path).cmp(&(&b.id, &b.rule_id, &b.path)));
    entries
}

fn validate_baseline(
    _root: &Path,
    path: &Path,
    baseline: &BaselineFile,
) -> Result<(), BaselineError> {
    if baseline.schema_version != BASELINE_SCHEMA_VERSION {
        return Err(invalid(
            path,
            format!("unsupported schema version {}", baseline.schema_version),
        ));
    }
    if baseline.fingerprint_version != BASELINE_FINGERPRINT_VERSION {
        return Err(invalid(
            path,
            format!(
                "unsupported fingerprint version {}",
                baseline.fingerprint_version
            ),
        ));
    }
    if baseline.reason.trim().is_empty() {
        return Err(invalid(path, "reason must not be empty"));
    }
    let mut ids = BTreeSet::new();
    for entry in &baseline.entries {
        if entry.id.len() != 64
            || entry.id != entry.id.to_ascii_lowercase()
            || !entry.id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid(path, format!("invalid baseline id `{}`", entry.id)));
        }
        if entry.rule_id.trim().is_empty() || entry.pattern_id.trim().is_empty() {
            return Err(invalid(
                path,
                "baseline entries require rule_id and pattern_id",
            ));
        }
        if entry.path.is_empty()
            || entry.path.contains('\\')
            || entry.path.chars().any(|character| character.is_control())
        {
            return Err(invalid(
                path,
                format!(
                    "baseline path must be relative UTF-8 with `/`: `{}`",
                    entry.path
                ),
            ));
        }
        validate_relative_input(Path::new(&entry.path))
            .map_err(|error| invalid(path, error.to_string()))?;
        if !ids.insert(entry.id.as_str()) {
            return Err(invalid(
                path,
                format!("duplicate baseline id `{}`", entry.id),
            ));
        }
    }
    Ok(())
}

fn write_baseline(root: &Path, path: &Path, baseline: &BaselineFile) -> Result<(), BaselineError> {
    let directory = ensure_metadata_dir(root)?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| invalid(path, "baseline path escaped project root"))?;
    validate_relative_input(relative).map_err(|error| invalid(path, error.to_string()))?;
    let text = serde_json::to_vec_pretty(baseline).map_err(|source| BaselineError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    let target = directory.join(
        path.file_name()
            .ok_or_else(|| invalid(path, "baseline path has no file name"))?,
    );
    if target != path {
        return Err(invalid(path, "baseline target escaped metadata directory"));
    }
    write_atomic_metadata(&target, &text).map_err(|source| BaselineError::Io {
        path: target,
        source,
    })?;
    sync_dir(&directory);
    Ok(())
}

fn ensure_metadata_dir(root: &Path) -> Result<PathBuf, BaselineError> {
    let path = root.join(".rbx-heal");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if is_link_or_junction(&metadata) {
                return Err(invalid(&path, "metadata directory must not be a symlink"));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&path).map_err(|source| BaselineError::Io {
                path: path.clone(),
                source,
            })?;
            sync_dir(root);
        }
        Err(source) => return Err(BaselineError::Io { path, source }),
    }
    let validated = crate::path::validate_existing_path(root, &path)?;
    if !validated.absolute().is_dir() {
        return Err(invalid(&path, "metadata path is not a directory"));
    }
    Ok(validated.into_absolute())
}

fn reject_existing_baseline(root: &Path, path: &Path) -> Result<(), BaselineError> {
    if let Some(metadata) = symlink_metadata(path)? {
        if is_link_or_junction(&metadata) {
            return Err(invalid(path, "refusing to overwrite a symlink baseline"));
        }
        let _ = crate::path::validate_existing_file(root, path)?;
        return Err(invalid(path, "baseline already exists"));
    }
    Ok(())
}

fn acquire_lock(root: &Path) -> Result<ProjectLock, BaselineError> {
    ProjectLock::acquire(root).map_err(|error| BaselineError::Locked(error.to_string()))
}

fn is_link_or_junction(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_REPARSE_POINT covers directory junctions as well as
        // symbolic links, which must never be used as the baseline target.
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn symlink_metadata(path: &Path) -> Result<Option<fs::Metadata>, BaselineError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(BaselineError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn invalid(path: &Path, reason: impl Into<String>) -> BaselineError {
    BaselineError::Invalid {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        engine::ScanReport,
        model::{Confidence, Finding, Position, Range, Severity},
    };
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn creates_and_applies_baseline_without_hiding_findings() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/Legacy.luau"), "return 1\n").unwrap();
        let mut finding = Finding::new(
            "RBX-X",
            "test",
            Severity::Warning,
            Confidence::High,
            "src/Legacy.luau",
            Range {
                start: Position {
                    line: 1,
                    column: 1,
                    byte: 0,
                },
                end: Position {
                    line: 1,
                    column: 7,
                    byte: 6,
                },
            },
            "test finding",
        );
        finding.baseline_id =
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
        finding.semantic_pattern = Some("test/v1".into());
        let report = ScanReport {
            findings: vec![finding],
            ..Default::default()
        };
        let (_, action) = create(dir.path(), &report, "legacy debt at adoption", true).unwrap();
        assert!(action.written);
        let mut next = report.clone();
        apply(dir.path(), &mut next, true).unwrap();
        assert_eq!(next.summary.baseline.as_ref().unwrap().matched, 1);
        assert!(!next.has_policy_findings(Severity::Warning));
        assert_eq!(
            next.findings[0].baseline_state,
            Some(BaselineState::Matched)
        );
    }

    #[test]
    fn rejects_duplicate_and_unsafe_entries() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".rbx-heal")).unwrap();
        let path = baseline_path(dir.path());
        let json = r#"{"schema_version":1,"fingerprint_version":1,"reason":"x","entries":[{"id":"0000000000000000000000000000000000000000000000000000000000000000","rule_id":"RBX-X","pattern_id":"x/v1","path":"../escape","severity":"warning","confidence":"high","fixability":"none"}]}"#;
        fs::write(&path, json).unwrap();
        assert!(matches!(
            load(dir.path()),
            Err(BaselineError::Invalid { .. })
        ));
    }

    #[test]
    fn no_baseline_is_a_noop() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/Clean.luau"), "return 1\n").unwrap();
        let mut report = ScanReport {
            findings: vec![Finding::new(
                "RBX-X",
                "test",
                Severity::Warning,
                Confidence::High,
                "src/Clean.luau",
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
                "x",
            )],
            ..Default::default()
        };
        apply(dir.path(), &mut report, true).unwrap();
        assert!(report.summary.baseline.is_none());
        assert!(report.findings[0].baseline_state.is_none());
    }
}
