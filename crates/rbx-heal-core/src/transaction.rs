use crate::{
    model::{Edit, FilePatchV1, Finding, PatchEditV1},
    parser::parse_source,
    path::{canonical_project_root, relative_utf8, validate_finding_file, PathError},
    verification::{prepare_verification, run_prepared_verification, VerificationReport},
    Config,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("could not acquire project lock at {0}")]
    Locked(PathBuf),
    #[error("file changed since scan: {0}")]
    ConcurrentChange(PathBuf),
    #[error("edit conflict in {path}: {message}")]
    EditConflict { path: PathBuf, message: String },
    #[error("could not read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("candidate failed Luau parse in {path}: {message}")]
    CandidateParse { path: PathBuf, message: String },
    #[error("verification failed; all changes were rolled back")]
    VerificationFailed { report: VerificationReport },
    #[error("recovery journal error: {0}")]
    Journal(String),
    #[error("invalid project path: {0}")]
    Path(#[from] PathError),
}

#[derive(Clone, Debug, Default)]
pub struct FixPreview {
    pub files: BTreeMap<PathBuf, String>,
    pub safe_fixes: usize,
    pub patches: Vec<FilePatchV1>,
}

#[derive(Clone, Debug, Default)]
pub struct CommitResult {
    pub changed_files: Vec<PathBuf>,
    pub verification: VerificationReport,
}

pub type CandidateValidator<'a> = dyn Fn(&Path, &str) -> Result<(), String> + 'a;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum JournalState {
    #[default]
    Prepared,
    Applying,
    Verifying,
    Committed,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    #[serde(default = "journal_version")]
    schema_version: u32,
    #[serde(default)]
    state: JournalState,
    /// Empty in v2.  v1 stored an absolute project path and is read only for
    /// one-time recovery of journals created by the MVP.
    #[serde(default)]
    project: String,
    entries: Vec<JournalEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalEntry {
    /// Always project-relative in v2.  v1 entries are also relative, but
    /// their backup path was absolute.
    path: String,
    /// Project-relative to `.rbx-heal/` in v2, absolute in v1.
    backup: String,
    #[serde(default)]
    original_hash: String,
    #[serde(default)]
    readonly: bool,
    /// POSIX permission bits. Windows uses readonly/ACL semantics instead;
    /// this optional field keeps older journals readable.
    #[serde(default)]
    mode: Option<u32>,
}

fn journal_version() -> u32 {
    1
}

fn new_journal(entries: Vec<JournalEntry>) -> Journal {
    Journal {
        schema_version: 2,
        state: JournalState::Prepared,
        project: String::new(),
        entries,
    }
}

pub fn preview_fixes(
    project_root: &Path,
    findings: impl Iterator<Item = Finding>,
) -> Result<FixPreview, TransactionError> {
    let project_root = canonical_project_root(project_root)?;
    let mut by_file: BTreeMap<PathBuf, Vec<Edit>> = BTreeMap::new();
    let mut rule_ids_by_file: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
    let mut expected_hashes: BTreeMap<PathBuf, String> = BTreeMap::new();
    for finding in findings {
        let edits = if finding.edits.is_empty() {
            finding.edit.into_iter().collect::<Vec<_>>()
        } else {
            finding.edits
        };
        for edit in edits {
            let path =
                validate_finding_file(&project_root, Path::new(&finding.path))?.into_absolute();
            rule_ids_by_file
                .entry(path.clone())
                .or_default()
                .push(finding.rule_id.clone());
            if let Some(expected_hash) = finding.source_hash.as_ref() {
                if let Some(existing) = expected_hashes.get(&path) {
                    if existing != expected_hash {
                        return Err(TransactionError::ConcurrentChange(path));
                    }
                } else {
                    expected_hashes.insert(path.clone(), expected_hash.clone());
                }
            }
            by_file.entry(path).or_default().push(edit);
        }
    }
    let mut preview = FixPreview::default();
    for (path, mut edits) in by_file {
        edits.sort_by(|a, b| b.range.start.byte.cmp(&a.range.start.byte));
        let source = fs::read_to_string(&path).map_err(|source| TransactionError::Read {
            path: path.clone(),
            source,
        })?;
        if let Some(expected_hash) = expected_hashes.get(&path) {
            let actual_hash = hash_bytes(source.as_bytes());
            if expected_hash != &actual_hash {
                return Err(TransactionError::ConcurrentChange(path));
            }
        }
        let candidate = apply_edits(&source, &edits, &path)?;
        parse_source(&candidate).map_err(|error| TransactionError::CandidateParse {
            path: path.clone(),
            message: error.to_string(),
        })?;
        preview.safe_fixes += edits.len();
        let patch = FilePatchV1 {
            path: relative_utf8(&project_root, &path)?,
            original_hash: hash_bytes(source.as_bytes()),
            candidate_hash: hash_bytes(candidate.as_bytes()),
            rule_ids: {
                let mut rule_ids = rule_ids_by_file.remove(&path).unwrap_or_default();
                rule_ids.sort();
                rule_ids.dedup();
                rule_ids
            },
            edits: edits
                .iter()
                .map(|edit| PatchEditV1 {
                    range: edit.range,
                    expected: edit.expected.clone(),
                    replacement: edit.replacement.clone(),
                })
                .collect(),
        };
        preview.patches.push(patch);
        preview.files.insert(path, candidate);
    }
    Ok(preview)
}

pub fn commit_fixes(
    project_root: &Path,
    config: &Config,
    findings: impl Iterator<Item = Finding>,
) -> Result<CommitResult, TransactionError> {
    commit_fixes_with_validator(project_root, config, findings, None)
}

pub fn commit_fixes_with_validator(
    project_root: &Path,
    config: &Config,
    findings: impl Iterator<Item = Finding>,
    validator: Option<&CandidateValidator<'_>>,
) -> Result<CommitResult, TransactionError> {
    let project_root = canonical_project_root(project_root)?;
    let lock = ProjectLock::acquire(&project_root)?;
    recover_journal_unlocked(&project_root)?;
    let mut by_file: BTreeMap<PathBuf, Vec<Edit>> = BTreeMap::new();
    let mut expected_hashes: BTreeMap<PathBuf, String> = BTreeMap::new();
    for finding in findings {
        let edits = if finding.edits.is_empty() {
            finding.edit.into_iter().collect::<Vec<_>>()
        } else {
            finding.edits
        };
        for edit in edits {
            let path =
                validate_finding_file(&project_root, Path::new(&finding.path))?.into_absolute();
            if let Some(expected_hash) = finding.source_hash.as_ref() {
                if let Some(existing) = expected_hashes.get(&path) {
                    if existing != expected_hash {
                        return Err(TransactionError::ConcurrentChange(path));
                    }
                } else {
                    expected_hashes.insert(path.clone(), expected_hash.clone());
                }
            }
            by_file.entry(path).or_default().push(edit);
        }
    }
    if by_file.is_empty() {
        drop(lock);
        return Ok(CommitResult::default());
    }

    // Resolve every configured verifier before touching a source file.  A
    // missing required executable is a verification failure (exit code 3 at
    // the CLI) and therefore cannot leave a partially written transaction.
    let prepared_verification = prepare_verification(&config.verify);
    if !prepared_verification.report.passed {
        drop(lock);
        return Err(TransactionError::VerificationFailed {
            report: prepared_verification.report,
        });
    }

    let mut candidates = BTreeMap::new();
    let mut originals = BTreeMap::new();
    for (path, mut edits) in by_file {
        edits.sort_by(|a, b| b.range.start.byte.cmp(&a.range.start.byte));
        let source = fs::read_to_string(&path).map_err(|source| TransactionError::Read {
            path: path.clone(),
            source,
        })?;
        if let Some(expected_hash) = expected_hashes.get(&path) {
            let actual_hash = hash_bytes(source.as_bytes());
            if expected_hash != &actual_hash {
                return Err(TransactionError::ConcurrentChange(path));
            }
        }
        let candidate = apply_edits(&source, &edits, &path)?;
        parse_source(&candidate).map_err(|error| TransactionError::CandidateParse {
            path: path.clone(),
            message: error.to_string(),
        })?;
        if let Some(validate) = validator {
            validate(&path, &candidate).map_err(|message| TransactionError::CandidateParse {
                path: path.clone(),
                message,
            })?;
        }
        originals.insert(path.clone(), source);
        candidates.insert(path, candidate);
    }
    let journal_id = unique_id();
    let recovery_root = ensure_recovery_dir(&project_root)?;
    let journal_dir = recovery_root.join(&journal_id);
    fs::create_dir(&journal_dir).map_err(|error| TransactionError::Journal(error.to_string()))?;
    let mut journal_entries = Vec::new();
    for (index, (path, original)) in originals.iter().enumerate() {
        let backup = journal_dir.join(format!("{index}.bak"));
        write_durable_file(&backup, original.as_bytes())
            .map_err(|error| TransactionError::Journal(error.to_string()))?;
        journal_entries.push(JournalEntry {
            path: relative_utf8(&project_root, path)?,
            backup: format!("recovery/{journal_id}/{index}.bak"),
            original_hash: hash_bytes(original.as_bytes()),
            readonly: fs::metadata(path)
                .map(|metadata| metadata.permissions().readonly())
                .unwrap_or(false),
            mode: file_mode(path),
        });
    }
    sync_dir(&journal_dir);
    if let Some(parent) = journal_dir.parent() {
        sync_dir(parent);
    }
    let mut journal = new_journal(journal_entries);
    let journal_path = project_root.join(".rbx-heal").join("recovery.json");
    if fs::symlink_metadata(&journal_path).is_ok() {
        reject_link_or_junction(&journal_path)?;
        crate::path::validate_existing_file(&project_root, &journal_path)?;
    }
    write_journal(&journal_path, &journal)?;
    journal.state = JournalState::Applying;
    write_journal(&journal_path, &journal)?;

    for (path, candidate) in &candidates {
        // A symlink/junction can be swapped after discovery. Re-canonicalize
        // immediately before every replacement, then require that it still
        // denotes the exact validated file we hashed.
        let validated = crate::path::validate_existing_file(&project_root, path)?;
        if validated.absolute() != path {
            return Err(TransactionError::Path(PathError::OutsideRoot {
                path: path.clone(),
            }));
        }
        if hash_file(path).map_err(|source| TransactionError::Read {
            path: path.clone(),
            source,
        })? != hash_bytes(originals.get(path).expect("original exists").as_bytes())
        {
            if let Err(rollback_error) = rollback(&project_root, &journal) {
                return Err(TransactionError::Journal(format!(
                    "concurrent change and rollback failed: {rollback_error}"
                )));
            }
            cleanup_journal(&journal_path, Some(&journal_dir));
            return Err(TransactionError::ConcurrentChange(path.clone()));
        }
        if let Err(source) = write_atomic(path, candidate) {
            if let Err(rollback_error) = rollback(&project_root, &journal) {
                return Err(TransactionError::Journal(format!(
                    "write failed ({source}) and rollback failed: {rollback_error}"
                )));
            }
            cleanup_journal(&journal_path, Some(&journal_dir));
            return Err(TransactionError::Write {
                path: path.clone(),
                source,
            });
        }
    }

    let changed_paths = candidates.keys().cloned().collect::<Vec<_>>();
    journal.state = JournalState::Verifying;
    write_journal(&journal_path, &journal)?;
    let verification = run_prepared_verification(
        &project_root,
        &config.verify,
        &changed_paths,
        &prepared_verification,
    );
    if !verification.passed {
        match rollback(&project_root, &journal) {
            Ok(()) => {
                cleanup_journal(&journal_path, Some(&journal_dir));
                return Err(TransactionError::VerificationFailed {
                    report: verification,
                });
            }
            Err(error) => {
                let mut report = verification;
                report.passed = false;
                report.rollback_status = Some("failed".into());
                report.steps.push(crate::model::VerificationStep {
                    name: "rollback".into(),
                    status: "failed".into(),
                    error: Some(error.to_string()),
                    ..Default::default()
                });
                // Keep the verifying journal and backup evidence in place so
                // the next invocation can recover after a partial rollback.
                return Err(TransactionError::VerificationFailed { report });
            }
        }
    }
    journal.state = JournalState::Committed;
    write_journal(&journal_path, &journal)?;
    cleanup_journal(&journal_path, Some(&journal_dir));
    drop(lock);
    Ok(CommitResult {
        changed_files: changed_paths,
        verification,
    })
}

pub fn apply_edits(source: &str, edits: &[Edit], path: &Path) -> Result<String, TransactionError> {
    let mut candidate = source.to_owned();
    let mut ordered = edits.to_vec();
    ordered.sort_by(|a, b| b.range.start.byte.cmp(&a.range.start.byte));
    let mut previous_start = source.len();
    for edit in &ordered {
        let start = edit.range.start.byte;
        let end = edit.range.end.byte;
        if start > end || end > source.len() || end > previous_start {
            return Err(TransactionError::EditConflict {
                path: path.to_path_buf(),
                message: "edits overlap or are out of bounds".into(),
            });
        }
        if source.get(start..end) != Some(edit.expected.as_str()) {
            return Err(TransactionError::EditConflict {
                path: path.to_path_buf(),
                message: format!(
                    "expected {:?} at byte range {}..{}",
                    edit.expected, start, end
                ),
            });
        }
        candidate.replace_range(start..end, &edit.replacement);
        previous_start = start;
    }
    Ok(candidate)
}

fn write_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    write_atomic_bytes(path, content.as_bytes(), None, file_mode(path))
}

/// Atomic, durable replacement shared by small project metadata files such as
/// the checked-in baseline manifest. Source edits continue to use the guarded
/// transaction path below.
pub(crate) fn write_atomic_metadata(path: &Path, content: &[u8]) -> std::io::Result<()> {
    write_atomic_bytes(path, content, None, file_mode(path))
}

fn write_atomic_bytes(
    path: &Path,
    content: &[u8],
    readonly_override: Option<bool>,
    mode_override: Option<u32>,
) -> std::io::Result<()> {
    #[cfg(not(unix))]
    let _ = mode_override;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = NamedTempFile::new_in(parent)?;
    temp.write_all(content)?;
    let readonly = readonly_override.or_else(|| {
        fs::metadata(path)
            .ok()
            .map(|metadata| metadata.permissions().readonly())
    });
    if let Some(readonly) = readonly {
        let mut permissions = temp.as_file().metadata()?.permissions();
        permissions.set_readonly(readonly);
        temp.as_file().set_permissions(permissions)?;
    }
    #[cfg(unix)]
    if let Some(mode) = mode_override {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = temp.as_file().metadata()?.permissions();
        permissions.set_mode(mode);
        temp.as_file().set_permissions(permissions)?;
    }
    temp.flush()?;
    temp.as_file_mut().sync_all()?;
    let temp_path = temp.into_temp_path();
    atomic_replace(&temp_path, path)?;
    sync_dir(parent);
    Ok(())
}

fn write_durable_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(content)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn write_journal(path: &Path, journal: &Journal) -> Result<(), TransactionError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| TransactionError::Journal(error.to_string()))?;
    let mut temp = NamedTempFile::new_in(parent)
        .map_err(|error| TransactionError::Journal(error.to_string()))?;
    serde_json::to_writer_pretty(temp.as_file_mut(), journal)
        .map_err(|error| TransactionError::Journal(error.to_string()))?;
    temp.as_file_mut()
        .write_all(b"\n")
        .map_err(|error| TransactionError::Journal(error.to_string()))?;
    temp.as_file_mut()
        .flush()
        .map_err(|error| TransactionError::Journal(error.to_string()))?;
    temp.as_file_mut()
        .sync_all()
        .map_err(|error| TransactionError::Journal(error.to_string()))?;
    let temp_path = temp.into_temp_path();
    atomic_replace(&temp_path, path)
        .map_err(|error| TransactionError::Journal(error.to_string()))?;
    sync_dir(parent);
    Ok(())
}

pub(crate) fn sync_dir(path: &Path) {
    if let Ok(directory) = File::open(path) {
        let _ = directory.sync_all();
    }
}

#[cfg(not(windows))]
fn atomic_replace(temp_path: &Path, path: &Path) -> std::io::Result<()> {
    // POSIX rename replaces the destination atomically.
    fs::rename(temp_path, path)
}

#[cfg(windows)]
fn atomic_replace(temp_path: &Path, path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let source = temp_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn unique_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{}", std::process::id(), nanos)
}

fn hash_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
fn hash_file(path: &Path) -> std::io::Result<String> {
    Ok(hash_bytes(&fs::read(path)?))
}

fn file_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .ok()
            .map(|metadata| metadata.permissions().mode())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

fn rollback(project_root: &Path, journal: &Journal) -> Result<(), TransactionError> {
    for entry in &journal.entries {
        let relative = Path::new(&entry.path);
        crate::path::validate_relative_input(relative)
            .map_err(|error| TransactionError::Journal(error.to_string()))?;
        let target = project_root.join(relative);
        let target = recovery_target(project_root, &target)?;
        let backup = backup_path(project_root, journal, entry)?;
        let bytes =
            fs::read(&backup).map_err(|error| TransactionError::Journal(error.to_string()))?;
        if !entry.original_hash.is_empty() && hash_bytes(&bytes) != entry.original_hash {
            return Err(TransactionError::Journal(format!(
                "backup hash mismatch for {}",
                entry.path
            )));
        }
        write_atomic_bytes(&target, &bytes, Some(entry.readonly), entry.mode)
            .map_err(|error| TransactionError::Journal(error.to_string()))?;
    }
    Ok(())
}

pub fn recover_journal(project_root: &Path) -> Result<bool, TransactionError> {
    let project_root = canonical_project_root(project_root)?;
    let heal_dir = project_root.join(".rbx-heal");
    // Inspect metadata instead of `exists()`: a dangling or escaping
    // symlink/junction must be rejected, not silently treated as no journal.
    match fs::symlink_metadata(&heal_dir) {
        Ok(metadata) => {
            if is_link_or_junction(&metadata) {
                return Err(TransactionError::Journal(
                    "transaction metadata directory must not be a symlink or junction".into(),
                ));
            }
            if !metadata.is_dir() {
                return Err(TransactionError::Journal(
                    "transaction metadata path is not a directory".into(),
                ));
            }
            crate::path::validate_existing_path(&project_root, &heal_dir)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(TransactionError::Journal(error.to_string())),
    }
    let journal_path = heal_dir.join("recovery.json");
    if fs::symlink_metadata(&journal_path).is_err() {
        return Ok(false);
    }
    reject_link_or_junction(&journal_path)?;
    crate::path::validate_existing_file(&project_root, &journal_path)?;
    let _lock = ProjectLock::acquire(&project_root)?;
    recover_journal_unlocked(&project_root)
}

fn recover_journal_unlocked(project_root: &Path) -> Result<bool, TransactionError> {
    let heal_dir = project_root.join(".rbx-heal");
    reject_link_or_junction(&heal_dir)?;
    if !heal_dir.is_dir() {
        return Err(TransactionError::Journal(
            "transaction metadata path is not a directory".into(),
        ));
    }
    crate::path::validate_existing_path(project_root, &heal_dir)?;
    let journal_path = heal_dir.join("recovery.json");
    if fs::symlink_metadata(&journal_path).is_err() {
        return Ok(false);
    }
    reject_link_or_junction(&journal_path)?;
    crate::path::validate_existing_file(project_root, &journal_path)?;
    let text = fs::read_to_string(&journal_path)
        .map_err(|error| TransactionError::Journal(error.to_string()))?;
    let journal: Journal = serde_json::from_str(&text)
        .map_err(|error| TransactionError::Journal(error.to_string()))?;
    if journal.schema_version > 2 {
        return Err(TransactionError::Journal(format!(
            "unsupported recovery journal version {}",
            journal.schema_version
        )));
    }
    // Validate every entry before either restoring bytes or deleting recovery
    // evidence. This keeps a structurally valid but malicious committed
    // journal from bypassing path/backup confinement during cleanup.
    for entry in &journal.entries {
        crate::path::validate_relative_input(Path::new(&entry.path))
            .map_err(|error| TransactionError::Journal(error.to_string()))?;
        let _ = backup_path(project_root, &journal, entry)?;
    }
    if journal.state != JournalState::Committed {
        rollback(project_root, &journal)?;
    }
    let journal_dir = journal_directory(project_root, &journal)?;
    cleanup_journal(&journal_path, journal_dir.as_deref());
    Ok(true)
}

fn backup_path(
    project_root: &Path,
    journal: &Journal,
    entry: &JournalEntry,
) -> Result<PathBuf, TransactionError> {
    let backup = Path::new(&entry.backup);
    if journal.schema_version <= 1 {
        if !backup.is_absolute() {
            return Err(TransactionError::Journal(
                "legacy recovery backup must be absolute".into(),
            ));
        }
        let recovery_root = project_root.join(".rbx-heal").join("recovery");
        let recovery_root = fs::canonicalize(&recovery_root)
            .map_err(|error| TransactionError::Journal(error.to_string()))?;
        let canonical_backup = fs::canonicalize(backup)
            .map_err(|error| TransactionError::Journal(error.to_string()))?;
        if !canonical_backup.starts_with(&recovery_root) {
            return Err(TransactionError::Journal(
                "legacy recovery backup escapes project recovery directory".into(),
            ));
        }
        return Ok(canonical_backup);
    }
    crate::path::validate_relative_input(backup)
        .map_err(|error| TransactionError::Journal(error.to_string()))?;
    let candidate = project_root.join(".rbx-heal").join(backup);
    reject_link_or_junction(&candidate)?;
    if !candidate.is_file() {
        return Err(TransactionError::Journal(format!(
            "recovery backup is missing: {}",
            candidate.display()
        )));
    }
    Ok(crate::path::validate_existing_file(project_root, &candidate)?.into_absolute())
}

fn recovery_target(project_root: &Path, target: &Path) -> Result<PathBuf, TransactionError> {
    let relative = target
        .strip_prefix(project_root)
        .map_err(|error| TransactionError::Journal(error.to_string()))?;
    crate::path::validate_relative_input(relative)
        .map_err(|error| TransactionError::Journal(error.to_string()))?;
    reject_link_or_junction(target)?;
    if target.exists() {
        return Ok(crate::path::validate_existing_file(project_root, target)?.into_absolute());
    }
    let parent = target
        .parent()
        .ok_or_else(|| TransactionError::Journal("recovery target has no parent".into()))?;
    reject_link_or_junction(parent)?;
    let validated_parent = crate::path::validate_existing_path(project_root, parent)?;
    Ok(validated_parent.absolute().join(
        target
            .file_name()
            .ok_or_else(|| TransactionError::Journal("recovery target has no filename".into()))?,
    ))
}

fn journal_directory(
    project_root: &Path,
    journal: &Journal,
) -> Result<Option<PathBuf>, TransactionError> {
    let Some(entry) = journal.entries.first() else {
        return Ok(None);
    };
    if journal.schema_version <= 1 {
        let backup = backup_path(project_root, journal, entry)?;
        let recovery_root = fs::canonicalize(project_root.join(".rbx-heal/recovery"))
            .map_err(|error| TransactionError::Journal(error.to_string()))?;
        let directory = backup
            .parent()
            .ok_or_else(|| TransactionError::Journal("legacy backup has no parent".into()))?;
        if !directory.starts_with(&recovery_root) {
            return Err(TransactionError::Journal(
                "legacy recovery directory escapes project recovery directory".into(),
            ));
        }
        return Ok(Some(directory.to_path_buf()));
    }
    let backup = Path::new(&entry.backup);
    crate::path::validate_relative_input(backup)
        .map_err(|error| TransactionError::Journal(error.to_string()))?;
    let directory = backup
        .parent()
        .map(|parent| project_root.join(".rbx-heal").join(parent))
        .ok_or_else(|| TransactionError::Journal("recovery backup has no parent".into()))?;
    reject_link_or_junction(&directory)?;
    let validated = crate::path::validate_existing_path(project_root, &directory)?;
    Ok(Some(validated.into_absolute()))
}

fn cleanup_journal(journal_path: &Path, journal_dir: Option<&Path>) {
    let _ = fs::remove_file(journal_path);
    if let Some(journal_dir) = journal_dir {
        let _ = fs::remove_dir_all(journal_dir);
        if let Some(recovery_dir) = journal_dir.parent() {
            sync_dir(recovery_dir);
        }
    }
    if let Some(parent) = journal_path.parent() {
        sync_dir(parent);
    }
}

pub(crate) struct ProjectLock {
    file: File,
    path: PathBuf,
}

impl ProjectLock {
    pub(crate) fn acquire(project_root: &Path) -> Result<Self, TransactionError> {
        let lock_dir = ensure_heal_dir(project_root)?;
        let path = lock_dir.join("project.lock");
        // OpenOptions follows a symlink. Validate an existing lock inode first
        // so a malicious link cannot redirect the advisory lock outside the
        // canonical project root (broken links fail closed as well).
        if fs::symlink_metadata(&path).is_ok() {
            reject_link_or_junction(&path)?;
            crate::path::validate_existing_file(project_root, &path)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|_| TransactionError::Locked(path.clone()))?;
        if !try_lock(&file) {
            return Err(TransactionError::Locked(path));
        }
        Ok(Self { file, path })
    }
}

/// Create the transaction metadata directory without ever following a
/// symlink/junction outside the project.  This is called before any lock,
/// journal, backup, or source replacement is attempted.
pub(crate) fn ensure_heal_dir(project_root: &Path) -> Result<PathBuf, TransactionError> {
    let path = project_root.join(".rbx-heal");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if is_link_or_junction(&metadata) {
                return Err(TransactionError::Journal(
                    "transaction metadata directory must not be a symlink or junction".into(),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&path).map_err(|error| TransactionError::Journal(error.to_string()))?;
            sync_dir(project_root);
        }
        Err(error) => return Err(TransactionError::Journal(error.to_string())),
    }
    let validated = crate::path::validate_existing_path(project_root, &path)?;
    if !validated.absolute().is_dir() {
        return Err(TransactionError::Journal(
            "transaction metadata path is not a directory".into(),
        ));
    }
    Ok(validated.into_absolute())
}

fn ensure_recovery_dir(project_root: &Path) -> Result<PathBuf, TransactionError> {
    let heal_dir = ensure_heal_dir(project_root)?;
    let path = heal_dir.join("recovery");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if is_link_or_junction(&metadata) {
                return Err(TransactionError::Journal(
                    "recovery directory must not be a symlink or junction".into(),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&path).map_err(|error| TransactionError::Journal(error.to_string()))?;
            sync_dir(&heal_dir);
        }
        Err(error) => return Err(TransactionError::Journal(error.to_string())),
    }
    let validated = crate::path::validate_existing_path(project_root, &path)?;
    if !validated.absolute().is_dir() {
        return Err(TransactionError::Journal(
            "recovery path is not a directory".into(),
        ));
    }
    Ok(validated.into_absolute())
}

impl Drop for ProjectLock {
    fn drop(&mut self) {
        unlock(&self.file);
        // Keep the lock inode in place.  Removing it would permit a second
        // process to open a new inode while this handle is still being
        // released, defeating the advisory lock.
        let _ = &self.path;
    }
}

fn reject_link_or_junction(path: &Path) -> Result<(), TransactionError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if is_link_or_junction(&metadata) {
                Err(TransactionError::Journal(format!(
                    "transaction metadata path must not be a symlink or junction: {}",
                    path.display()
                )))
            } else {
                Ok(())
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(TransactionError::Journal(error.to_string())),
    }
}

fn is_link_or_junction(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(windows)]
fn try_lock(file: &File) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY},
        System::IO::OVERLAPPED,
    };
    let mut overlapped = OVERLAPPED::default();
    unsafe {
        LockFileEx(
            file.as_raw_handle() as _,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        ) != 0
    }
}

#[cfg(windows)]
fn unlock(file: &File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{Storage::FileSystem::UnlockFileEx, System::IO::OVERLAPPED};
    let mut overlapped = OVERLAPPED::default();
    unsafe {
        let _ = UnlockFileEx(
            file.as_raw_handle() as _,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        );
    }
}

#[cfg(unix)]
fn try_lock(file: &File) -> bool {
    use std::os::unix::io::AsRawFd;
    unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) == 0 }
}

#[cfg(unix)]
fn unlock(file: &File) {
    use std::os::unix::io::AsRawFd;
    unsafe {
        let _ = flock(file.as_raw_fd(), LOCK_UN);
    }
}

#[cfg(unix)]
const LOCK_EX: i32 = 2;
#[cfg(unix)]
const LOCK_NB: i32 = 4;
#[cfg(unix)]
const LOCK_UN: i32 = 8;

#[cfg(unix)]
unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

#[cfg(not(any(unix, windows)))]
fn try_lock(_file: &File) -> bool {
    true
}

#[cfg(not(any(unix, windows)))]
fn unlock(_file: &File) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{VerifyCommand, VerifyConfig, VerifyKind},
        model::{Confidence, Position, Range, Severity},
    };
    use tempfile::tempdir;

    fn edit(start: usize, end: usize, expected: &str, replacement: &str) -> Edit {
        Edit::new(
            Range {
                start: Position {
                    line: 1,
                    column: start + 1,
                    byte: start,
                },
                end: Position {
                    line: 1,
                    column: end + 1,
                    byte: end,
                },
            },
            expected,
            replacement,
        )
    }

    #[test]
    fn applies_non_overlapping_edits_in_reverse_order() {
        let result = apply_edits(
            "abc def",
            &[edit(0, 3, "abc", "ABC"), edit(4, 7, "def", "XYZ")],
            Path::new("fixture.luau"),
        )
        .unwrap();
        assert_eq!(result, "ABC XYZ");
    }

    #[test]
    fn rejects_overlapping_edits() {
        let error = apply_edits(
            "abcdef",
            &[edit(1, 4, "bcd", "X"), edit(3, 6, "def", "Y")],
            Path::new("fixture.luau"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("overlap"));
    }

    #[test]
    fn unicode_edit_requires_and_preserves_utf8_boundaries() {
        let source = "é money";
        let edit = Edit::new(
            Range {
                start: Position {
                    line: 1,
                    column: 1,
                    byte: 0,
                },
                end: Position {
                    line: 1,
                    column: 2,
                    byte: 2,
                },
            },
            "é",
            "E",
        );
        assert_eq!(
            apply_edits(source, &[edit], Path::new("unicode.luau")).unwrap(),
            "E money"
        );
        assert!(apply_edits(
            source,
            &[Edit::new(
                Range {
                    start: Position {
                        line: 1,
                        column: 1,
                        byte: 1,
                    },
                    end: Position {
                        line: 1,
                        column: 2,
                        byte: 2,
                    },
                },
                "é",
                "X",
            )],
            Path::new("unicode.luau")
        )
        .is_err());
    }

    #[test]
    fn preview_does_not_write_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fixture.luau");
        fs::write(&path, "local Players = game:service(\"Players\")\n").unwrap();
        let finding = Finding::new(
            "RBX-API-002",
            "api",
            Severity::Warning,
            Confidence::High,
            "fixture.luau",
            Range::default(),
            "service",
        )
        .with_fix(
            crate::model::Fixability::Safe,
            "rename",
            edit(21, 28, "service", "GetService"),
        );
        let preview = preview_fixes(dir.path(), std::iter::once(finding)).unwrap();
        let canonical_path = fs::canonicalize(&path).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "local Players = game:service(\"Players\")\n"
        );
        assert!(preview
            .files
            .get(&canonical_path)
            .unwrap()
            .contains("GetService"));
    }

    #[test]
    fn preview_accepts_multiple_guarded_edits_from_one_finding() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fixture.luau");
        fs::write(&path, "local aa = 1\nlocal bb = 2\n").unwrap();
        let mut finding = Finding::new(
            "RBX-TEST-EDIT",
            "test",
            Severity::Warning,
            Confidence::High,
            "fixture.luau",
            Range::default(),
            "two edits",
        );
        finding.fixability = crate::model::Fixability::Safe;
        finding.edits = vec![edit(6, 8, "aa", "AA"), edit(19, 21, "bb", "BB")];
        let preview = preview_fixes(dir.path(), std::iter::once(finding)).unwrap();
        let canonical_path = fs::canonicalize(&path).unwrap();
        assert_eq!(preview.safe_fixes, 2);
        assert_eq!(
            preview.files[&canonical_path],
            "local AA = 1\nlocal BB = 2\n"
        );
        assert_eq!(preview.patches[0].edits.len(), 2);
    }

    #[test]
    fn preview_rejects_finding_path_escape_before_reading_or_writing() {
        let dir = tempdir().unwrap();
        let outside = dir.path().parent().unwrap().join("rbx-heal-outside.luau");
        fs::write(&outside, "original\n").unwrap();
        let finding = Finding::new(
            "RBX-TEST-EDIT",
            "test",
            Severity::Warning,
            Confidence::High,
            "../rbx-heal-outside.luau",
            Range::default(),
            "escape",
        )
        .with_fix(
            crate::model::Fixability::Safe,
            "must not apply",
            edit(0, 0, "", "changed"),
        );
        let result = preview_fixes(dir.path(), std::iter::once(finding));
        assert!(matches!(result, Err(TransactionError::Path(_))));
        assert_eq!(fs::read_to_string(&outside).unwrap(), "original\n");
        let _ = fs::remove_file(outside);
    }

    #[cfg(unix)]
    #[test]
    fn lock_symlink_outside_project_is_rejected() {
        use std::os::unix::fs::symlink;
        let project = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let metadata = project.path().join(".rbx-heal");
        fs::create_dir(&metadata).unwrap();
        let outside_lock = outside.path().join("lock");
        fs::write(&outside_lock, b"").unwrap();
        symlink(&outside_lock, metadata.join("project.lock")).unwrap();
        let error =
            commit_fixes(project.path(), &Config::default(), std::iter::empty()).unwrap_err();
        assert!(matches!(
            error,
            TransactionError::Path(PathError::OutsideRoot { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn journal_symlink_outside_project_is_rejected_before_reading() {
        use std::os::unix::fs::symlink;
        let project = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let metadata = project.path().join(".rbx-heal");
        fs::create_dir(&metadata).unwrap();
        let outside_journal = outside.path().join("recovery.json");
        fs::write(&outside_journal, b"not a journal").unwrap();
        symlink(&outside_journal, metadata.join("recovery.json")).unwrap();
        let error = recover_journal(project.path()).unwrap_err();
        assert!(matches!(
            error,
            TransactionError::Path(PathError::OutsideRoot { .. })
        ));
        assert_eq!(fs::read(&outside_journal).unwrap(), b"not a journal");
    }

    #[test]
    fn failed_verification_rolls_back_all_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fixture.luau");
        let original = "local Players = game:service(\"Players\")\n";
        fs::write(&path, original).unwrap();
        let config = Config {
            verify: VerifyConfig {
                default_timeout_ms: 5_000,
                max_output_bytes: 64 * 1024,
                commands: vec![VerifyCommand {
                    kind: VerifyKind::Generic,
                    name: "fail".into(),
                    program: "cmd.exe".into(),
                    args: vec!["/C".into(), "exit".into(), "1".into()],
                    timeout_ms: Some(5_000),
                    required: true,
                    ..Default::default()
                }],
            },
            ..Config::default()
        };
        let finding = Finding::new(
            "RBX-API-002",
            "api",
            Severity::Warning,
            Confidence::High,
            "fixture.luau",
            Range::default(),
            "service",
        )
        .with_fix(
            crate::model::Fixability::Safe,
            "rename",
            edit(21, 28, "service", "GetService"),
        );
        let result = commit_fixes(dir.path(), &config, std::iter::once(finding));
        assert!(matches!(
            result,
            Err(TransactionError::VerificationFailed { .. })
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        assert!(!dir.path().join(".rbx-heal/recovery.json").exists());
    }

    #[test]
    fn missing_required_verifier_is_preflighted_before_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fixture.luau");
        let original = "local Players = game:service(\"Players\")\n";
        fs::write(&path, original).unwrap();
        let config = Config {
            verify: VerifyConfig {
                commands: vec![VerifyCommand {
                    kind: VerifyKind::Generic,
                    name: "missing".into(),
                    program: "rbx-heal-missing-required-verifier".into(),
                    args: Vec::new(),
                    timeout_ms: Some(1_000),
                    required: true,
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Config::default()
        };
        let finding = Finding::new(
            "RBX-API-002",
            "api",
            Severity::Warning,
            Confidence::High,
            "fixture.luau",
            Range::default(),
            "service",
        )
        .with_fix(
            crate::model::Fixability::Safe,
            "rename",
            edit(21, 28, "service", "GetService"),
        );
        let result = commit_fixes(dir.path(), &config, std::iter::once(finding));
        assert!(matches!(
            result,
            Err(TransactionError::VerificationFailed { report })
                if report.steps.iter().any(|step| step.status == "missing")
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_commit_preserves_posix_mode_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("fixture.luau");
        fs::write(&path, "local Players = game:service(\"Players\")\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let finding = Finding::new(
            "RBX-API-002",
            "api",
            Severity::Warning,
            Confidence::High,
            "fixture.luau",
            Range::default(),
            "service",
        )
        .with_fix(
            crate::model::Fixability::Safe,
            "rename",
            edit(21, 28, "service", "GetService"),
        );
        commit_fixes(dir.path(), &Config::default(), std::iter::once(finding)).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn scan_hash_rejects_unrelated_concurrent_change() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fixture.luau");
        let scanned = "local Players = game:service(\"Players\")\n";
        fs::write(&path, format!("{scanned}-- changed after scan\n")).unwrap();
        let mut finding = Finding::new(
            "RBX-API-002",
            "api",
            Severity::Warning,
            Confidence::High,
            "fixture.luau",
            Range::default(),
            "service",
        )
        .with_fix(
            crate::model::Fixability::Safe,
            "rename",
            edit(21, 28, "service", "GetService"),
        );
        finding.source_hash = Some(hash_bytes(scanned.as_bytes()));
        let result = commit_fixes(dir.path(), &Config::default(), std::iter::once(finding));
        assert!(matches!(result, Err(TransactionError::ConcurrentChange(_))));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("{scanned}-- changed after scan\n")
        );
    }

    #[test]
    fn recovers_incomplete_journal_before_next_run() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fixture.luau");
        fs::write(&path, "changed").unwrap();
        let backup_dir = dir.path().join(".rbx-heal/recovery/crash");
        fs::create_dir_all(&backup_dir).unwrap();
        let backup = backup_dir.join("0.bak");
        fs::write(&backup, "original").unwrap();
        let journal = Journal {
            schema_version: 1,
            state: JournalState::Prepared,
            project: dir.path().to_string_lossy().into_owned(),
            entries: vec![JournalEntry {
                path: "fixture.luau".into(),
                backup: backup.to_string_lossy().into_owned(),
                original_hash: hash_bytes(b"original"),
                readonly: false,
                mode: None,
            }],
        };
        fs::write(
            dir.path().join(".rbx-heal/recovery.json"),
            serde_json::to_string(&journal).unwrap(),
        )
        .unwrap();
        assert!(recover_journal(dir.path()).unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
        assert!(!dir.path().join(".rbx-heal/recovery.json").exists());
    }

    #[test]
    fn malformed_journal_is_preserved_and_fails_closed() {
        let dir = tempdir().unwrap();
        let heal_dir = dir.path().join(".rbx-heal");
        fs::create_dir_all(&heal_dir).unwrap();
        let journal_path = heal_dir.join("recovery.json");
        fs::write(&journal_path, b"{\"schema_version\":99,\"entries\":[]}").unwrap();
        let error = recover_journal(dir.path()).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported recovery journal version"));
        assert_eq!(
            fs::read(&journal_path).unwrap(),
            b"{\"schema_version\":99,\"entries\":[]}"
        );
    }
}
