use crate::model::{Confidence, Finding, Fixability, RunSummary, Severity};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("could not locate local application data directory")]
    Directory,
    #[error("history I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("history is locked by another process: {0}")]
    Locked(PathBuf),
    #[error("history serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid history record at line {line}: {reason}")]
    InvalidRecord { line: usize, reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryFinding {
    pub fingerprint: String,
    #[serde(default)]
    pub occurrence_fingerprint: String,
    pub pattern_id: String,
    pub rule_id: String,
    #[serde(default = "default_finding_action")]
    pub action: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub fixability: Fixability,
    pub suppressed: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HistoryCounts {
    pub findings: usize,
    pub unsuppressed_findings: usize,
    pub safe_fixes: usize,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
    #[serde(default)]
    pub suppressed_findings: usize,
    #[serde(default)]
    pub severity_counts: BTreeMap<String, usize>,
    #[serde(default)]
    pub confidence_counts: BTreeMap<String, usize>,
    #[serde(default)]
    pub fixability_counts: BTreeMap<String, usize>,
    #[serde(default)]
    pub baseline_matched: usize,
    #[serde(default)]
    pub baseline_new: usize,
    #[serde(default)]
    pub baseline_stale: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryEvent {
    pub schema_version: u32,
    pub project_hash: String,
    pub engine_version: String,
    pub rule_pack_version: String,
    pub command: String,
    pub action: String,
    pub rule_ids: Vec<String>,
    pub finding_fingerprints: Vec<String>,
    pub duration_ms: u128,
    pub verification_status: String,
    #[serde(default = "default_fingerprint_version")]
    pub fingerprint_version: u32,
    #[serde(default)]
    pub project_hash_version: u32,
    #[serde(default)]
    pub timestamp_utc_ms: u128,
    #[serde(default)]
    pub run_id: String,
    #[serde(default)]
    pub counts: HistoryCounts,
    #[serde(default)]
    pub findings: Vec<HistoryFinding>,
}

fn default_fingerprint_version() -> u32 {
    1
}

fn default_finding_action() -> String {
    "unknown".into()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HistorySummary {
    pub schema_version: u32,
    pub runs: usize,
    pub actions: BTreeMap<String, usize>,
    pub patterns: BTreeMap<String, usize>,
    pub verifier_statuses: BTreeMap<String, usize>,
    pub suppressed_findings: usize,
    pub unsuppressed_findings: usize,
    pub committed_fixes: usize,
    pub rollbacks: usize,
    /// Ratios are derived from metadata only; no source or verifier output is
    /// required to calculate them.
    #[serde(default)]
    pub suppression_ratio: f64,
    #[serde(default)]
    pub fix_success_rate: f64,
    #[serde(default)]
    pub rollback_rate: f64,
    #[serde(default)]
    pub verifier_success_rate: f64,
    #[serde(default)]
    pub baseline_matched: usize,
    #[serde(default)]
    pub baseline_new: usize,
    #[serde(default)]
    pub baseline_stale: usize,
}

pub fn history_path() -> Result<PathBuf, HistoryError> {
    let dirs = ProjectDirs::from("com", "openai", "rbx-heal").ok_or(HistoryError::Directory)?;
    Ok(dirs.data_dir().join("history.jsonl"))
}

fn key_path() -> Result<PathBuf, HistoryError> {
    let dirs = ProjectDirs::from("com", "openai", "rbx-heal").ok_or(HistoryError::Directory)?;
    Ok(dirs.data_dir().join("installation.key"))
}

static INSTALLATION_KEY: OnceLock<[u8; 32]> = OnceLock::new();

fn installation_key() -> [u8; 32] {
    *INSTALLATION_KEY.get_or_init(load_or_create_installation_key)
}

fn load_or_create_installation_key() -> [u8; 32] {
    let path = key_path().ok();
    let key_is_symlink = path.as_ref().is_some_and(|path| {
        fs::symlink_metadata(path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
    });
    if let Some(path) = path.as_ref().filter(|_| !key_is_symlink) {
        if let Ok(text) = fs::read_to_string(path) {
            let text = text.trim();
            if text.len() == 64 {
                let mut bytes = [0u8; 32];
                let mut valid = true;
                for (index, slot) in bytes.iter_mut().enumerate() {
                    let pair = &text[index * 2..index * 2 + 2];
                    match u8::from_str_radix(pair, 16) {
                        Ok(value) => *slot = value,
                        Err(_) => {
                            valid = false;
                            break;
                        }
                    }
                }
                if valid {
                    return bytes;
                }
            }
        }
    }
    // New installations use the operating system CSPRNG.  The fallback is
    // only a last-resort availability guard; normal platforms never take it.
    let mut key = [0u8; 32];
    if getrandom::fill(&mut key).is_err() {
        let seed = format!(
            "rbx-heal-installation-fallback:{}:{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        key.copy_from_slice(blake3::hash(seed.as_bytes()).as_bytes());
    }
    if let Some(path) = path.filter(|_| !key_is_symlink) {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
            set_private_directory_permissions(parent);
        }
        if let Ok(mut file) = OpenOptions::new().write(true).create_new(true).open(&path) {
            set_private_permissions(&file);
            let _ = file.write_all(hex_bytes(&key).as_bytes());
            let _ = file.sync_all();
        } else if let Ok(text) = fs::read_to_string(&path) {
            let text = text.trim();
            if text.len() == 64 {
                let mut existing = [0u8; 32];
                let mut valid = true;
                for (index, slot) in existing.iter_mut().enumerate() {
                    match u8::from_str_radix(&text[index * 2..index * 2 + 2], 16) {
                        Ok(value) => *slot = value,
                        Err(_) => {
                            valid = false;
                            break;
                        }
                    }
                }
                if valid {
                    return existing;
                }
            }
        }
    }
    key
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn record(event: &HistoryEvent) -> Result<(), HistoryError> {
    validate_event(event, 1)?;
    let path = history_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_private_directory_permissions(parent);
    }
    reject_history_symlink(&path)?;
    let _lock = HistoryLock::acquire(&path)?;
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    set_private_permissions(&file);
    serde_json::to_writer(&mut file, event)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

pub fn export(destination: &Path) -> Result<usize, HistoryError> {
    export_from(&history_source()?, destination)
}

fn export_from(source: &Path, destination: &Path) -> Result<usize, HistoryError> {
    reject_history_symlink(source)?;
    if source.is_file()
        && fs::canonicalize(destination)
            .ok()
            .zip(fs::canonicalize(source).ok())
            .is_some_and(|(destination, source)| destination == source)
    {
        return Err(HistoryError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "history export destination cannot be the source history file",
        )));
    }
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temp = NamedTempFile::new_in(parent)?;
    let mut count = 0;
    if source.is_file() {
        let _lock = HistoryLock::acquire(source)?;
        let reader = BufReader::new(File::open(source)?);
        for (index, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event = parse_event(&line, index + 1)?;
            serde_json::to_writer(temp.as_file_mut(), &event)?;
            temp.write_all(b"\n")?;
            count += 1;
        }
    }
    temp.as_file_mut().flush()?;
    temp.as_file_mut().sync_all()?;
    let temp_path = temp.into_temp_path();
    atomic_replace(&temp_path, destination)?;
    Ok(count)
}

pub fn summarize() -> Result<HistorySummary, HistoryError> {
    let source = history_source()?;
    let mut summary = HistorySummary {
        schema_version: 1,
        ..Default::default()
    };
    reject_history_symlink(&source)?;
    if !source.is_file() {
        return Ok(summary);
    }
    let _lock = HistoryLock::acquire(&source)?;
    for (index, line) in BufReader::new(File::open(source)?).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let event = parse_event(&line, index + 1)?;
        summary.runs += 1;
        *summary.actions.entry(event.action.clone()).or_default() += 1;
        *summary
            .verifier_statuses
            .entry(event.verification_status.clone())
            .or_default() += 1;
        if event.action == "committed" {
            summary.committed_fixes += 1;
        }
        if event.action == "rollback" {
            summary.rollbacks += 1;
        }
        summary.baseline_matched += event.counts.baseline_matched;
        summary.baseline_new += event.counts.baseline_new;
        summary.baseline_stale += event.counts.baseline_stale;
        if event.findings.is_empty() {
            summary.suppressed_findings += event
                .counts
                .findings
                .saturating_sub(event.counts.unsuppressed_findings);
            summary.unsuppressed_findings += event.counts.unsuppressed_findings;
        } else {
            summary.suppressed_findings += event
                .findings
                .iter()
                .filter(|finding| finding.suppressed)
                .count();
            summary.unsuppressed_findings += event
                .findings
                .iter()
                .filter(|finding| !finding.suppressed)
                .count();
            for finding in event.findings {
                *summary.patterns.entry(finding.pattern_id).or_default() += 1;
            }
        }
    }
    let total_findings = summary.suppressed_findings + summary.unsuppressed_findings;
    summary.suppression_ratio = ratio(summary.suppressed_findings, total_findings);
    let fix_attempts = summary
        .actions
        .get("committed")
        .copied()
        .unwrap_or_default()
        + summary.rollbacks;
    summary.fix_success_rate = ratio(summary.committed_fixes, fix_attempts);
    summary.rollback_rate = ratio(summary.rollbacks, fix_attempts);
    let verification_runs = summary.verifier_statuses.values().copied().sum::<usize>();
    let verification_successes = summary
        .verifier_statuses
        .get("passed")
        .copied()
        .unwrap_or_default();
    summary.verifier_success_rate = ratio(verification_successes, verification_runs);
    Ok(summary)
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn history_source() -> Result<PathBuf, HistoryError> {
    history_path()
}

fn reject_history_symlink(path: &Path) -> Result<(), HistoryError> {
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(HistoryError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("history path must not be a symlink: {}", path.display()),
        )));
    }
    Ok(())
}

fn parse_event(line: &str, line_number: usize) -> Result<HistoryEvent, HistoryError> {
    let event = serde_json::from_str::<HistoryEvent>(line).map_err(|error| {
        HistoryError::InvalidRecord {
            line: line_number,
            reason: error.to_string(),
        }
    })?;
    validate_event(&event, line_number)?;
    Ok(event)
}

fn validate_event(event: &HistoryEvent, line: usize) -> Result<(), HistoryError> {
    if event.schema_version != 1 {
        return Err(HistoryError::InvalidRecord {
            line,
            reason: format!(
                "unsupported history schema version {}",
                event.schema_version
            ),
        });
    }
    if !matches!(event.fingerprint_version, 1 | 2) {
        return Err(HistoryError::InvalidRecord {
            line,
            reason: format!(
                "unsupported fingerprint version {}",
                event.fingerprint_version
            ),
        });
    }
    if event.project_hash_version > 2 {
        return Err(HistoryError::InvalidRecord {
            line,
            reason: format!(
                "unsupported project hash version {}",
                event.project_hash_version
            ),
        });
    }
    for (field, value) in [
        ("project_hash", event.project_hash.as_str()),
        ("engine_version", event.engine_version.as_str()),
        ("rule_pack_version", event.rule_pack_version.as_str()),
        ("command", event.command.as_str()),
        ("action", event.action.as_str()),
        ("verification_status", event.verification_status.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(HistoryError::InvalidRecord {
                line,
                reason: format!("{field} must not be empty"),
            });
        }
    }
    if !is_hex_digest(&event.project_hash) {
        return Err(HistoryError::InvalidRecord {
            line,
            reason: "project_hash must be a 64-character hexadecimal digest".into(),
        });
    }
    for (field, value) in [
        ("engine_version", event.engine_version.as_str()),
        ("rule_pack_version", event.rule_pack_version.as_str()),
        ("command", event.command.as_str()),
        ("action", event.action.as_str()),
        ("verification_status", event.verification_status.as_str()),
        ("run_id", event.run_id.as_str()),
    ] {
        if value.len() > 256
            || value
                .chars()
                .any(|character| character.is_control() || matches!(character, '/' | '\\'))
        {
            return Err(HistoryError::InvalidRecord {
                line,
                reason: format!("{field} contains disallowed path/control characters"),
            });
        }
    }
    for rule_id in &event.rule_ids {
        if rule_id.is_empty()
            || rule_id.len() > 128
            || !rule_id
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-'))
        {
            return Err(HistoryError::InvalidRecord {
                line,
                reason: "rule_ids must contain only bounded rule identifiers".into(),
            });
        }
    }
    for fingerprint in &event.finding_fingerprints {
        if !is_hex_digest(fingerprint) {
            return Err(HistoryError::InvalidRecord {
                line,
                reason: "finding_fingerprints must be hexadecimal digests".into(),
            });
        }
    }
    for finding in &event.findings {
        if finding.rule_id.trim().is_empty()
            || finding.pattern_id.trim().is_empty()
            || finding.action.trim().is_empty()
        {
            return Err(HistoryError::InvalidRecord {
                line,
                reason: "finding metadata must include rule_id, pattern_id and action".into(),
            });
        }
        if !is_hex_digest(&finding.fingerprint)
            || (!finding.occurrence_fingerprint.is_empty()
                && !is_hex_digest(&finding.occurrence_fingerprint))
        {
            return Err(HistoryError::InvalidRecord {
                line,
                reason: "finding fingerprints must be hexadecimal digests".into(),
            });
        }
        if finding.rule_id.len() > 128
            || !finding
                .rule_id
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-'))
            || !valid_pattern_id(&finding.pattern_id)
            || finding.action.len() > 128
            || finding
                .action
                .chars()
                .any(|character| character.is_control() || matches!(character, '/' | '\\'))
        {
            return Err(HistoryError::InvalidRecord {
                line,
                reason: "finding metadata contains disallowed characters".into(),
            });
        }
    }
    Ok(())
}

fn valid_pattern_id(value: &str) -> bool {
    value.len() <= 256
        && !value.starts_with('/')
        && !value.contains("..")
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '/')
        })
}

fn is_hex_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn set_private_permissions(file: &File) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = file.metadata() {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            let _ = file.set_permissions(permissions);
        }
    }
    #[cfg(not(unix))]
    let _ = file;
}

fn set_private_directory_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o700);
            let _ = fs::set_permissions(path, permissions);
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

struct HistoryLock {
    file: File,
}

impl HistoryLock {
    fn acquire(history_path: &Path) -> Result<Self, HistoryError> {
        let lock_path = history_path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
            set_private_directory_permissions(parent);
        }
        if fs::symlink_metadata(&lock_path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(HistoryError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "history lock must not be a symlink: {}",
                    lock_path.display()
                ),
            )));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        if !try_lock(&file) {
            return Err(HistoryError::Locked(lock_path));
        }
        set_private_permissions(&file);
        Ok(Self { file })
    }
}

impl Drop for HistoryLock {
    fn drop(&mut self) {
        unlock(&self.file);
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

#[cfg(not(windows))]
fn atomic_replace(temp_path: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temp_path, destination)
}

#[cfg(windows)]
fn atomic_replace(temp_path: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let source = temp_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
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
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Opaque project identity.  The installation key prevents the canonical
/// absolute path from being reversible from exported metadata.
pub fn project_hash(project_root: &Path) -> String {
    let mut hasher = blake3::Hasher::new_keyed(&installation_key());
    hasher.update(project_root.to_string_lossy().as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Legacy fingerprint retained for consumers that explicitly request v1.
pub fn fingerprint(rule_id: &str, path: &str, byte: usize, message: &str) -> String {
    let input = format!("v1|{rule_id}|{path}|{byte}|{message}");
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

/// Stable, keyed occurrence fingerprint that does not depend on byte offsets
/// or user-facing messages.
pub fn stable_fingerprint(
    project_root: &Path,
    rule_id: &str,
    path: &str,
    semantic_pattern: &str,
    scope: &str,
    ordinal: usize,
) -> String {
    let mut hasher = blake3::Hasher::new_keyed(&installation_key());
    hasher.update(b"v2|occurrence|");
    hasher.update(project_hash(project_root).as_bytes());
    hasher.update(b"|");
    hasher.update(rule_id.as_bytes());
    hasher.update(b"|");
    #[cfg(windows)]
    let stable_path = path.replace('\\', "/");
    #[cfg(not(windows))]
    let stable_path = path.to_owned();
    hasher.update(stable_path.as_bytes());
    hasher.update(b"|");
    hasher.update(semantic_pattern.as_bytes());
    hasher.update(b"|");
    hasher.update(scope.as_bytes());
    hasher.update(b"|");
    hasher.update(ordinal.to_string().as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Portable project-baseline identity. Unlike the local history occurrence
/// fingerprint, this digest is intentionally unkeyed so a checked-in
/// baseline matches on every machine. Only semantic identity components are
/// included; offsets, messages and source text are never serialized.
pub fn baseline_fingerprint(
    rule_id: &str,
    semantic_pattern: &str,
    path: &str,
    semantic_anchor: &str,
    statement_digest: &str,
    ordinal: usize,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"rbx-heal-baseline-v1\0");
    let normalized_path = path.replace('\\', "/");
    for value in [
        rule_id,
        semantic_pattern,
        normalized_path.as_str(),
        semantic_anchor,
        statement_digest,
    ] {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update(&ordinal.to_le_bytes());
    hasher.finalize().to_hex().to_string()
}

pub fn pattern_id(rule_id: &str, semantic_pattern: Option<&str>) -> String {
    semantic_pattern
        .filter(|pattern| !pattern.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{rule_id}/unknown/v1"))
}

pub fn run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{nanos}", std::process::id())
}

pub fn event_from_summary(
    summary: &RunSummary,
    root: &Path,
    action: &str,
    rule_ids: Vec<String>,
    fingerprints: Vec<String>,
    verification_status: &str,
) -> HistoryEvent {
    HistoryEvent {
        schema_version: 1,
        project_hash: project_hash(root),
        engine_version: env!("CARGO_PKG_VERSION").into(),
        rule_pack_version: env!("CARGO_PKG_VERSION").into(),
        command: summary.command.clone(),
        action: action.into(),
        rule_ids,
        finding_fingerprints: fingerprints,
        duration_ms: summary.duration_ms,
        verification_status: verification_status.into(),
        fingerprint_version: 2,
        project_hash_version: 2,
        timestamp_utc_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        run_id: run_id(),
        counts: HistoryCounts {
            findings: summary.findings,
            unsuppressed_findings: summary.unsuppressed_findings,
            safe_fixes: summary.safe_fixes,
            baseline_matched: summary
                .baseline
                .as_ref()
                .map(|baseline| baseline.matched)
                .unwrap_or_default(),
            baseline_new: summary
                .baseline
                .as_ref()
                .map(|baseline| baseline.new)
                .unwrap_or_default(),
            baseline_stale: summary
                .baseline
                .as_ref()
                .map(|baseline| baseline.stale)
                .unwrap_or_default(),
            ..Default::default()
        },
        findings: Vec::new(),
    }
}

pub fn event_from_summary_with_findings(
    summary: &RunSummary,
    root: &Path,
    action: &str,
    findings: &[Finding],
    verification_status: &str,
) -> HistoryEvent {
    let mut rule_ids = findings
        .iter()
        .filter(|finding| !finding.suppressed)
        .map(|finding| finding.rule_id.clone())
        .collect::<Vec<_>>();
    rule_ids.sort();
    rule_ids.dedup();
    let mut ordinals = BTreeMap::<(String, String, String, String), usize>::new();
    // Recreate the engine's semantic ordering instead of trusting caller
    // order. This keeps occurrence ordinals stable when messages change or a
    // caller supplies findings from a different rule traversal order.
    let mut order = (0..findings.len()).collect::<Vec<_>>();
    order.sort_by_key(|index| {
        let finding = &findings[*index];
        (
            finding.path.clone(),
            finding.range.start.byte,
            finding.range.end.byte,
            finding.rule_id.clone(),
        )
    });
    let mut records = Vec::with_capacity(findings.len());
    for index in order {
        let finding = &findings[index];
        let pattern = pattern_id(&finding.rule_id, finding.semantic_pattern.as_deref());
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
        let ordinal = ordinals.entry(key).or_default();
        let occurrence = finding.occurrence_id.clone().unwrap_or_else(|| {
            stable_fingerprint(
                root,
                &finding.rule_id,
                &finding.path,
                &pattern,
                &scope,
                *ordinal,
            )
        });
        *ordinal += 1;
        records.push(HistoryFinding {
            fingerprint: occurrence.clone(),
            occurrence_fingerprint: occurrence,
            pattern_id: pattern,
            rule_id: finding.rule_id.clone(),
            action: action.into(),
            severity: finding.severity,
            confidence: finding.confidence,
            fixability: finding.fixability,
            suppressed: finding.suppressed,
        });
    }
    let mut event = event_from_summary(
        summary,
        root,
        action,
        rule_ids,
        records
            .iter()
            .map(|finding| finding.fingerprint.clone())
            .collect(),
        verification_status,
    );
    event.counts.errors = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Error)
        .count();
    event.counts.warnings = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Warning)
        .count();
    event.counts.infos = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Info)
        .count();
    event.counts.suppressed_findings = findings.iter().filter(|finding| finding.suppressed).count();
    if let Some(baseline) = &summary.baseline {
        event.counts.baseline_matched = baseline.matched;
        event.counts.baseline_new = baseline.new;
        event.counts.baseline_stale = baseline.stale;
    }
    for finding in findings {
        *event
            .counts
            .severity_counts
            .entry(finding.severity.to_string())
            .or_default() += 1;
        *event
            .counts
            .confidence_counts
            .entry(finding.confidence.to_string())
            .or_default() += 1;
        *event
            .counts
            .fixability_counts
            .entry(finding.fixability.to_string())
            .or_default() += 1;
    }
    event.findings = records;
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Position, Range};
    use std::path::PathBuf;

    fn summary() -> RunSummary {
        RunSummary {
            schema_version: 1,
            command: "check".into(),
            findings: 1,
            unsuppressed_findings: 1,
            fingerprint_version: 2,
            ..Default::default()
        }
    }

    fn finding(message: &str, byte: usize) -> Finding {
        Finding::new(
            "RBX-SEC-001",
            "security",
            Severity::Error,
            Confidence::High,
            "src/server/Economy.luau",
            Range {
                start: Position {
                    line: 2,
                    column: 1,
                    byte,
                },
                end: Position {
                    line: 2,
                    column: 8,
                    byte: byte + 7,
                },
            },
            message,
        )
        .with_semantic_pattern("remote_arg_to_sensitive_sink/v1")
    }

    #[test]
    fn stable_occurrence_fingerprint_ignores_message_and_byte_offset() {
        let root = PathBuf::from("C:/projects/game");
        let first = finding("old message", 10);
        let second = finding("rewritten message", 240);
        let a = stable_fingerprint(
            &root,
            &first.rule_id,
            &first.path,
            first.semantic_pattern.as_deref().unwrap(),
            "Server",
            0,
        );
        let b = stable_fingerprint(
            &root,
            &second.rule_id,
            &second.path,
            second.semantic_pattern.as_deref().unwrap(),
            "Server",
            0,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn portable_baseline_fingerprint_is_independent_of_installation_and_separators() {
        let a = baseline_fingerprint(
            "RBX-SEC-001",
            "remote_arg_to_sensitive_sink/v2",
            "src/server\\Economy.luau",
            "function:Anonymous:header",
            "statement-digest",
            0,
        );
        let b = baseline_fingerprint(
            "RBX-SEC-001",
            "remote_arg_to_sensitive_sink/v2",
            "src/server/Economy.luau",
            "function:Anonymous:header",
            "statement-digest",
            0,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn exported_event_does_not_contain_source_path_or_message() {
        let root = PathBuf::from("C:/private/project");
        let source_message = "client_secret_source_text";
        let event = event_from_summary_with_findings(
            &summary(),
            &root,
            "scan",
            &[finding(source_message, 10)],
            "not_run",
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains(&root.to_string_lossy().to_string()));
        assert!(!json.contains(source_message));
        assert!(json.contains("remote_arg_to_sensitive_sink/v1"));
        assert!(json.contains("\"fingerprint_version\":2"));
    }

    #[test]
    fn history_never_persists_portable_baseline_ids() {
        let root = PathBuf::from("C:/private/project");
        let mut item = finding("source message", 10);
        item.baseline_id =
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
        let event = event_from_summary_with_findings(&summary(), &root, "scan", &[item], "not_run");
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("baseline_id"));
        assert!(!json.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn export_fails_closed_without_replacing_destination() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("history.jsonl");
        let destination = dir.path().join("export.jsonl");
        fs::write(&destination, "keep this exact destination\n").unwrap();
        fs::write(
            &source,
            "{\"schema_version\":1,\"project_hash\":\"p\",\"engine_version\":\"0.8.0\",\"rule_pack_version\":\"0.8.0\",\"command\":\"check\",\"action\":\"scan\",\"rule_ids\":[],\"finding_fingerprints\":[],\"duration_ms\":0,\"verification_status\":\"not_run\",\"fingerprint_version\":99}\n",
        )
        .unwrap();
        let error = export_from(&source, &destination).unwrap_err();
        assert!(matches!(error, HistoryError::InvalidRecord { .. }));
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            "keep this exact destination\n"
        );
    }

    #[test]
    fn export_allowlists_unknown_and_sensitive_fields() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("history.jsonl");
        let destination = dir.path().join("export.jsonl");
        let event = event_from_summary_with_findings(
            &summary(),
            Path::new("C:/private/project"),
            "scan",
            &[finding("source text must not escape", 12)],
            "passed",
        );
        let json = serde_json::to_string(&event).unwrap();
        let json = format!(
            "{},\"source\":\"secret source\",\"message\":\"secret message\",\"diff\":\"secret diff\",\"verifier_output\":\"secret output\"}}\n",
            json.trim_end_matches('}')
        );
        fs::write(&source, json).unwrap();
        export_from(&source, &destination).unwrap();
        let exported = fs::read_to_string(destination).unwrap();
        assert!(!exported.contains("secret source"));
        assert!(!exported.contains("secret message"));
        assert!(!exported.contains("secret diff"));
        assert!(!exported.contains("secret output"));
        assert!(!exported.contains("C:/private/project"));
        assert!(exported.contains("remote_arg_to_sensitive_sink/v1"));
    }

    #[cfg(unix)]
    #[test]
    fn export_rejects_symlinked_history_source() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("history.jsonl");
        let outside = dir.path().join("outside.jsonl");
        let destination = dir.path().join("export.jsonl");
        fs::write(&outside, b"sensitive\n").unwrap();
        symlink(&outside, &source).unwrap();
        fs::write(&destination, b"keep\n").unwrap();
        assert!(export_from(&source, &destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"keep\n");
    }
}
