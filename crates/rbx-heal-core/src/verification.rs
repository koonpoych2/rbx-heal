use crate::{
    config::{VerifyCommand, VerifyConfig, VerifyKind},
    hashing::sha256_hex,
    model::VerificationStep,
};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread::JoinHandle,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Default)]
pub struct VerificationReport {
    pub passed: bool,
    pub steps: Vec<VerificationStep>,
    pub rollback_status: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct PreparedVerification {
    pub report: VerificationReport,
    commands: Vec<PreparedCommand>,
}

#[derive(Clone, Debug)]
struct PreparedCommand {
    command: VerifyCommand,
    program: Option<PathBuf>,
    identity: Option<String>,
    error: Option<String>,
}

pub fn run_verification(
    project_root: &Path,
    config: &VerifyConfig,
    changed: &[PathBuf],
) -> VerificationReport {
    let project_root = match crate::path::canonical_project_root(project_root) {
        Ok(root) => root,
        Err(error) => return failed_path_report(error.to_string()),
    };
    let changed = match canonical_changed_paths(&project_root, changed) {
        Ok(changed) => changed,
        Err(error) => return failed_path_report(error),
    };
    let prepared = prepare_verification(config);
    run_prepared_verification(&project_root, config, &changed, &prepared)
}

pub fn prepare_verification(config: &VerifyConfig) -> PreparedVerification {
    let mut prepared = PreparedVerification {
        report: VerificationReport {
            passed: true,
            steps: Vec::new(),
            rollback_status: None,
        },
        commands: Vec::new(),
    };
    for command in &config.commands {
        let resolved = resolved_program(&command.program);
        let (identity, identity_error) = resolved
            .as_deref()
            .map(probe_identity)
            .unwrap_or((None, Some("executable not found".into())));
        let mut error = identity_error;
        if let (Some(expected), Some(actual)) = (&command.expected_version, &identity) {
            if !actual.contains(expected) {
                error = Some(format!(
                    "expected verifier version `{expected}`, got `{actual}`"
                ));
            }
        }
        if let (Some(expected), Some(path)) = (&command.expected_sha256, resolved.as_deref()) {
            match fs::read(path) {
                Ok(bytes) => {
                    let actual = sha256_hex(&bytes);
                    if !actual.eq_ignore_ascii_case(expected) {
                        error = Some(format!(
                            "expected verifier SHA-256 `{expected}`, got `{actual}`"
                        ));
                    }
                }
                Err(read_error) => error = Some(read_error.to_string()),
            }
        }
        let status = if resolved.is_some() && error.is_none() {
            "available"
        } else if command.required {
            prepared.report.passed = false;
            if resolved.is_some() {
                "identity_mismatch"
            } else {
                "missing"
            }
        } else {
            "skipped"
        };
        prepared.report.steps.push(VerificationStep {
            name: command.name.clone(),
            status: status.into(),
            error,
            // Reports are a public JSON surface. Keep executable identity
            // useful for agents without leaking the host's absolute path.
            program: resolved.as_deref().map(program_label),
            identity: identity.clone(),
            ..Default::default()
        });
        prepared.commands.push(PreparedCommand {
            command: command.clone(),
            program: resolved,
            identity,
            error: prepared
                .report
                .steps
                .last()
                .and_then(|step| step.error.clone()),
        });
    }
    prepared
}

pub fn run_prepared_verification(
    project_root: &Path,
    config: &VerifyConfig,
    changed: &[PathBuf],
    prepared: &PreparedVerification,
) -> VerificationReport {
    // Keep this public helper safe even when a caller did not first pass its
    // root through `run_verification` or the transaction layer.  Verifier
    // arguments and changed-file checks must always use one canonical root.
    let project_root = match crate::path::canonical_project_root(project_root) {
        Ok(root) => root,
        Err(error) => return failed_path_report(error.to_string()),
    };
    let changed = match canonical_changed_paths(&project_root, changed) {
        Ok(changed) => changed,
        Err(error) => return failed_path_report(error),
    };
    let Some(temp_dir) = tempfile::tempdir().ok() else {
        return VerificationReport {
            passed: false,
            steps: vec![VerificationStep {
                name: "tempdir".into(),
                status: "failed".into(),
                error: Some("could not create temporary verification directory".into()),
                ..Default::default()
            }],
            rollback_status: None,
        };
    };
    let mut report = VerificationReport {
        passed: true,
        steps: Vec::new(),
        rollback_status: None,
    };
    for prepared_command in &prepared.commands {
        let step = match prepared_command.program.as_deref() {
            Some(program) if prepared_command.error.is_none() => run_command(
                &project_root,
                temp_dir.as_ref(),
                &changed,
                config,
                &prepared_command.command,
                program,
                prepared_command.identity.as_deref(),
            ),
            Some(program) => VerificationStep {
                name: prepared_command.command.name.clone(),
                status: if prepared_command.command.required {
                    "failed".into()
                } else {
                    "skipped".into()
                },
                error: prepared_command.error.clone(),
                program: Some(program_label(program)),
                identity: prepared_command.identity.clone(),
                ..Default::default()
            },
            None => VerificationStep {
                name: prepared_command.command.name.clone(),
                status: if prepared_command.command.required {
                    "missing".into()
                } else {
                    "skipped".into()
                },
                error: prepared_command.error.clone(),
                ..Default::default()
            },
        };
        if matches!(
            step.status.as_str(),
            "failed" | "timeout" | "identity_mismatch"
        ) || (step.status == "missing" && prepared_command.command.required)
        {
            report.passed = false;
        }
        report.steps.push(step);
        if !report.passed {
            break;
        }
    }
    report
}

fn canonical_changed_paths(
    project_root: &Path,
    changed: &[PathBuf],
) -> Result<Vec<PathBuf>, String> {
    let mut canonical = Vec::with_capacity(changed.len());
    for path in changed {
        let validated = crate::path::validate_existing_file(project_root, path)
            .map_err(|error| format!("changed verifier path is outside the project: {error}"))?;
        canonical.push(validated.into_absolute());
    }
    Ok(canonical)
}

fn failed_path_report(error: String) -> VerificationReport {
    VerificationReport {
        passed: false,
        steps: vec![VerificationStep {
            name: "changed-paths".into(),
            status: "failed".into(),
            error: Some(error),
            ..Default::default()
        }],
        rollback_status: None,
    }
}

/// Check required verifier executables before a transaction writes anything.
/// Optional tools are represented as skipped steps and do not block a commit.
pub fn preflight_verification(config: &VerifyConfig) -> VerificationReport {
    prepare_verification(config).report
}

#[derive(Default)]
struct CapturedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn run_command(
    project_root: &Path,
    temp_dir: &Path,
    changed: &[PathBuf],
    config: &VerifyConfig,
    command: &VerifyCommand,
    program: &Path,
    identity: Option<&str>,
) -> VerificationStep {
    let started = Instant::now();
    let args = command_args(project_root, temp_dir, changed, command);
    let mut command_builder = Command::new(program);
    command_builder
        .args(&args)
        .current_dir(project_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut command_builder);
    let mut child = match command_builder.spawn() {
        Ok(child) => child,
        Err(error) => {
            return VerificationStep {
                name: command.name.clone(),
                status: "missing".into(),
                duration_ms: started.elapsed().as_millis(),
                error: Some(error.to_string()),
                program: Some(program_label(program)),
                identity: identity.map(str::to_owned),
                ..Default::default()
            }
        }
    };

    let limit = config.max_output_bytes.clamp(1, 32 * 1024);
    let stdout_reader = child
        .stdout
        .take()
        .map(|stdout| spawn_capture(stdout, limit));
    let stderr_reader = child
        .stderr
        .take()
        .map(|stderr| spawn_capture(stderr, limit));
    let process_tree = attach_process_tree(&child);
    #[cfg(windows)]
    if process_tree.is_none() {
        let mut child = child;
        terminate_process_tree(None, &mut child);
        let _ = child.wait();
        let _ = join_capture(stdout_reader);
        let _ = join_capture(stderr_reader);
        return VerificationStep {
            name: command.name.clone(),
            status: "failed".into(),
            duration_ms: started.elapsed().as_millis(),
            error: Some("could not attach verifier process to a Windows Job Object".into()),
            program: Some(program_label(program)),
            identity: identity.map(str::to_owned),
            ..Default::default()
        };
    }
    #[cfg(windows)]
    if !resume_suspended_process(&child) {
        terminate_process_tree(process_tree.as_ref(), &mut child);
        let _ = child.wait();
        let _ = join_capture(stdout_reader);
        let _ = join_capture(stderr_reader);
        return VerificationStep {
            name: command.name.clone(),
            status: "failed".into(),
            duration_ms: started.elapsed().as_millis(),
            error: Some("could not resume verifier process after Job Object attach".into()),
            program: Some(program_label(program)),
            identity: identity.map(str::to_owned),
            ..Default::default()
        };
    }
    let timeout = Duration::from_millis(command.timeout_ms.unwrap_or(config.default_timeout_ms));

    let (status, exit_code, error) = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                break (
                    if status.success() { "passed" } else { "failed" },
                    status.code(),
                    (!status.success()).then(|| format!("verification exited with {status}")),
                )
            }
            Ok(None) if started.elapsed() >= timeout => {
                terminate_process_tree(process_tree.as_ref(), &mut child);
                break (
                    "timeout",
                    None,
                    Some(format!("timed out after {} ms", timeout.as_millis())),
                );
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                terminate_process_tree(process_tree.as_ref(), &mut child);
                break ("failed", None, Some(error.to_string()));
            }
        }
    };
    if status == "timeout" {
        let _ = child.wait();
    }
    let stdout = join_capture(stdout_reader);
    let stderr = join_capture(stderr_reader);
    let output_truncated = stdout.truncated || stderr.truncated;
    VerificationStep {
        name: command.name.clone(),
        status: status.into(),
        exit_code,
        duration_ms: started.elapsed().as_millis(),
        error,
        stdout: (!stdout.bytes.is_empty())
            .then(|| String::from_utf8_lossy(&stdout.bytes).into_owned()),
        stderr: (!stderr.bytes.is_empty())
            .then(|| String::from_utf8_lossy(&stderr.bytes).into_owned()),
        output_truncated,
        program: Some(program_label(program)),
        identity: identity.map(str::to_owned),
    }
}

fn spawn_capture<R>(mut reader: R, limit: usize) -> JoinHandle<CapturedOutput>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut captured = CapturedOutput::default();
        let mut buffer = [0u8; 8 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    let available = limit.saturating_sub(captured.bytes.len());
                    if captured.bytes.len() < limit {
                        captured
                            .bytes
                            .extend_from_slice(&buffer[..read.min(available)]);
                    }
                    if read > available {
                        captured.truncated = true;
                    }
                }
                Err(_) => {
                    captured.truncated = true;
                    break;
                }
            }
        }
        captured
    })
}

fn join_capture(handle: Option<JoinHandle<CapturedOutput>>) -> CapturedOutput {
    handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default()
}

fn command_args(
    project_root: &Path,
    temp_dir: &Path,
    changed: &[PathBuf],
    command: &VerifyCommand,
) -> Vec<String> {
    let mut args = expand_args(&command.args, project_root, temp_dir, changed);
    let has_changed_placeholder = command.args.iter().any(|arg| arg.contains("{changed}"));
    if matches!(command.kind, VerifyKind::RojoBuild) {
        let output = temp_dir.join("rbx-heal-rojo-output.rbxlx");
        let output_text = output.to_string_lossy().into_owned();
        let mut found_output = false;
        let mut index = 0;
        while index < args.len() {
            if matches!(args[index].as_str(), "-o" | "--output") {
                found_output = true;
                if let Some(value) = args.get_mut(index + 1) {
                    *value = output_text.clone();
                } else {
                    args.push(output_text.clone());
                }
                index += 2;
            } else {
                index += 1;
            }
        }
        for arg in &mut args {
            if arg.starts_with("--output=") || arg.starts_with("-o=") {
                *arg = format!("--output={output_text}");
                found_output = true;
            }
        }
        if !found_output {
            args.push("-o".into());
            args.push(output_text);
        }
    }
    if matches!(command.kind, VerifyKind::StyluaCheck)
        && !args
            .iter()
            .any(|arg| matches!(arg.as_str(), "--check" | "--verify"))
    {
        // StyLua must remain a check-only verifier. Never let a configured
        // adapter accidentally format the project in place.
        args.insert(0, "--check".into());
    }
    if matches!(
        command.kind,
        VerifyKind::LuauAnalyze | VerifyKind::StyluaCheck
    ) && !has_changed_placeholder
        && !changed.is_empty()
        && !changed.iter().all(|path| {
            args.iter()
                .any(|arg| arg == &relative_arg(project_root, path))
        })
    {
        args.extend(changed.iter().map(|path| relative_arg(project_root, path)));
    }
    args
}

fn expand_args(
    args: &[String],
    project_root: &Path,
    temp_dir: &Path,
    changed: &[PathBuf],
) -> Vec<String> {
    let changed_args = changed
        .iter()
        .map(|path| relative_arg(project_root, path))
        .collect::<Vec<_>>();
    let mut expanded = Vec::new();
    for arg in args {
        if arg == "{changed}" {
            expanded.extend(changed_args.iter().cloned());
        } else if arg.contains("{changed}") {
            // Preserve the no-shell argv contract even for an embedded
            // placeholder such as `--file={changed}`: one configured token
            // becomes one argv entry per changed file, never a joined string.
            if changed_args.is_empty() {
                expanded.push(replace_scalar_placeholders(arg, "", project_root, temp_dir));
            } else {
                expanded.extend(changed_args.iter().map(|changed| {
                    replace_scalar_placeholders(arg, changed, project_root, temp_dir)
                }));
            }
        } else {
            expanded.push(replace_scalar_placeholders(
                arg,
                changed_args.first().map(String::as_str).unwrap_or_default(),
                project_root,
                temp_dir,
            ));
        }
    }
    expanded
}

fn replace_scalar_placeholders(
    arg: &str,
    changed: &str,
    project_root: &Path,
    temp_dir: &Path,
) -> String {
    arg.replace("{project}", &project_root.to_string_lossy())
        .replace("{temp}", &temp_dir.to_string_lossy())
        .replace("{changed}", changed)
}

fn relative_arg(project_root: &Path, path: &Path) -> String {
    crate::path::relative_utf8(project_root, path)
        .unwrap_or_else(|_| "<invalid-project-path>".into())
}

fn resolved_program(program: &str) -> Option<PathBuf> {
    if program.trim().is_empty() {
        return None;
    }
    if Path::new(program).components().count() > 1 {
        let resolved = fs::canonicalize(program).ok()?;
        return resolved.is_file().then_some(resolved);
    }
    let lookup = if cfg!(windows) { "where.exe" } else { "which" };
    let output = Command::new(lookup).arg(program).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()?
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && Path::new(line).is_file())
        .and_then(|line| fs::canonicalize(line).ok())
}

const IDENTITY_TIMEOUT: Duration = Duration::from_secs(5);
const IDENTITY_OUTPUT_LIMIT: usize = 32 * 1024;

/// Probe a resolved verifier directly, without invoking a shell.  The probe
/// is deliberately bounded because it runs before a write transaction starts.
fn probe_version(program: &Path) -> Result<String, String> {
    probe_argument(program, "--version", "version probe")
}

fn probe_argument(program: &Path, argument: &str, label: &str) -> Result<String, String> {
    let started = Instant::now();
    let mut command_builder = Command::new(program);
    command_builder
        .arg(argument)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut command_builder);
    let mut child = command_builder.spawn().map_err(|error| error.to_string())?;
    let stdout_reader = child
        .stdout
        .take()
        .map(|stdout| spawn_capture(stdout, IDENTITY_OUTPUT_LIMIT));
    let stderr_reader = child
        .stderr
        .take()
        .map(|stderr| spawn_capture(stderr, IDENTITY_OUTPUT_LIMIT));
    let process_tree = attach_process_tree(&child);
    #[cfg(windows)]
    if process_tree.is_none() {
        let mut child = child;
        terminate_process_tree(None, &mut child);
        let _ = child.wait();
        let _ = join_capture(stdout_reader);
        let _ = join_capture(stderr_reader);
        return Err(format!("could not attach {label} to a Windows Job Object"));
    }
    #[cfg(windows)]
    if !resume_suspended_process(&child) {
        terminate_process_tree(process_tree.as_ref(), &mut child);
        let _ = child.wait();
        let _ = join_capture(stdout_reader);
        let _ = join_capture(stderr_reader);
        return Err(format!(
            "could not resume process after {label} Job Object attach"
        ));
    }
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() >= IDENTITY_TIMEOUT => {
                timed_out = true;
                terminate_process_tree(process_tree.as_ref(), &mut child);
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                terminate_process_tree(process_tree.as_ref(), &mut child);
                let _ = child.wait();
                return Err(error.to_string());
            }
        }
    };
    let stdout = join_capture(stdout_reader);
    let stderr = join_capture(stderr_reader);
    if timed_out {
        return Err(format!("{label} timed out after 5000 ms"));
    }
    let Some(status) = status else {
        return Err(format!("{label} did not return a process status"));
    };
    let mut bytes = stdout.bytes;
    bytes.extend_from_slice(&stderr.bytes);
    bytes.truncate(IDENTITY_OUTPUT_LIMIT);
    let text = String::from_utf8_lossy(&bytes).trim().to_owned();
    if !status.success() {
        return Err(format!("{label} exited with {status}"));
    }
    if text.is_empty() {
        return Err(format!("{label} returned no identity"));
    }
    Ok(text)
}

fn probe_identity(program: &Path) -> (Option<String>, Option<String>) {
    let executable = program
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    let path_is_aftman_shim = program.components().any(|component| {
        component
            .as_os_str()
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains("aftman")
    });
    // Aftman can fail before printing a version (for example when its tool
    // manifest is absent).  The path itself is still enough to distinguish a
    // shim from the official binary in doctor/preflight output.
    if executable.eq_ignore_ascii_case("rojo") && path_is_aftman_shim {
        return (
            None,
            Some("resolved executable is an Aftman shim, not an official Rojo binary".into()),
        );
    }
    let version_text = match probe_version(program) {
        Ok(text) => text,
        Err(error)
            if executable.eq_ignore_ascii_case("luau-analyze")
                || executable.eq_ignore_ascii_case("luau-compile") =>
        {
            // Luau's standalone tools do not expose a stable --version flag
            // in all official releases.  Their help banner is still a
            // bounded, executable-identity check; configured expected_version
            // or expected_sha256 constraints remain authoritative when used.
            match probe_argument(program, "--help", "Luau tool help probe") {
                Ok(help) => format!("help banner (version flag unsupported): {help}"),
                Err(help_error) => return (None, Some(format!("{error}; {help_error}"))),
            }
        }
        Err(error) => return (None, Some(error)),
    };
    if executable.eq_ignore_ascii_case("rojo")
        && (path_is_aftman_shim || version_text.to_ascii_lowercase().contains("aftman"))
    {
        return (
            None,
            Some("resolved executable is an Aftman shim, not an official Rojo binary".into()),
        );
    }
    let version = version_text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("available");
    (Some(format!("{}: {version}", program_label(program))), None)
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: `pre_exec` runs between fork and exec and only calls the
    // async-signal-safe setpgid syscall. No Rust allocation or locking occurs
    // in the child process.
    unsafe {
        command.pre_exec(|| {
            if setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(windows)]
fn configure_process_group(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
    command.creation_flags(CREATE_SUSPENDED);
}

#[cfg(not(any(unix, windows)))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
unsafe extern "C" {
    fn setpgid(pid: i32, pgid: i32) -> i32;
    fn kill(pid: i32, signal: i32) -> i32;
}

#[cfg(unix)]
const SIGKILL: i32 = 9;

/// Return a small executable identity for doctor output. The identity is
/// informational and is never persisted in history.
pub fn command_identity(program: &str) -> String {
    let Some(resolved) = resolved_program(program) else {
        return "missing".into();
    };
    let (identity, error) = probe_identity(&resolved);
    match (identity, error) {
        (Some(identity), _) => identity,
        (None, Some(error)) if error.contains("Aftman shim") => "aftman_shim".into(),
        (None, Some(error)) => format!("{}: unavailable ({error})", program_label(&resolved)),
        (None, None) => format!("{}: unavailable", program_label(&resolved)),
    }
}

fn program_label(program: &Path) -> String {
    program
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .unwrap_or_else(|| "verifier".into())
}

/// Resolve and probe a command without executing a shell.  This is used by
/// `doctor` and intentionally treats an identity probe failure as unavailable.
pub fn command_available(program: &str) -> bool {
    let Some(resolved) = resolved_program(program) else {
        return false;
    };
    let (identity, error) = probe_identity(&resolved);
    identity.is_some() && error.is_none()
}

#[cfg(windows)]
mod windows_process_tree {
    use std::{mem::size_of, os::windows::io::AsRawHandle, process::Child, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
    };

    pub struct WindowsProcessTree {
        job: HANDLE,
    }

    impl WindowsProcessTree {
        pub fn attach(child: &Child) -> Option<Self> {
            unsafe {
                let job = CreateJobObjectW(null_mut(), core::ptr::null());
                if job.is_null() {
                    return None;
                }
                let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                        LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let ok = SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &mut info as *mut _ as *mut _,
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                if ok == 0 || AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) == 0 {
                    CloseHandle(job);
                    return None;
                }
                Some(Self { job })
            }
        }

        pub fn terminate(&self, child: &mut Child) {
            unsafe {
                let _ = TerminateJobObject(self.job, 1);
            }
            let _ = child.kill();
        }
    }

    impl Drop for WindowsProcessTree {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.job);
            }
        }
    }
}

#[cfg(windows)]
fn resume_suspended_process(child: &Child) -> bool {
    use std::mem::size_of;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD,
                THREADENTRY32,
            },
            Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME},
        },
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut entry = THREADENTRY32 {
            dwSize: size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let mut found = false;
        if Thread32First(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32OwnerProcessID == child.id() {
                    let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                    if !thread.is_null() {
                        found = ResumeThread(thread) != u32::MAX;
                        CloseHandle(thread);
                        if found {
                            break;
                        }
                    }
                }
                if Thread32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        found
    }
}

#[cfg(windows)]
fn attach_process_tree(child: &Child) -> Option<windows_process_tree::WindowsProcessTree> {
    windows_process_tree::WindowsProcessTree::attach(child)
}

#[cfg(unix)]
struct UnixProcessTree {
    process_group: i32,
}

#[cfg(unix)]
fn attach_process_tree(child: &Child) -> Option<UnixProcessTree> {
    Some(UnixProcessTree {
        process_group: child.id() as i32,
    })
}

#[cfg(not(any(unix, windows)))]
fn attach_process_tree(_child: &Child) -> Option<()> {
    None
}

#[cfg(windows)]
fn terminate_process_tree(
    tree: Option<&windows_process_tree::WindowsProcessTree>,
    child: &mut Child,
) {
    if let Some(tree) = tree {
        tree.terminate(child);
    } else {
        let _ = child.kill();
    }
}

#[cfg(unix)]
fn terminate_process_tree(tree: Option<&UnixProcessTree>, child: &mut Child) {
    if let Some(tree) = tree {
        // Negative pid sends SIGKILL to the complete process group.
        unsafe {
            let _ = kill(-tree.process_group, SIGKILL);
        }
    }
    let _ = child.kill();
}

#[cfg(not(any(unix, windows)))]
fn terminate_process_tree(_: Option<&()>, child: &mut Child) {
    let _ = child.kill();
}

#[cfg(test)]
mod tests {
    use super::{command_args, command_available, expand_args};
    use crate::config::{VerifyCommand, VerifyConfig, VerifyKind};
    use std::path::{Path, PathBuf};

    #[test]
    fn missing_verifier_is_reported_unavailable() {
        assert!(!command_available("rbx-heal-command-that-does-not-exist"));
    }

    #[test]
    fn changed_placeholder_expands_without_shell_joining() {
        let args = expand_args(
            &["--flag".into(), "{changed}".into(), "{temp}/out".into()],
            Path::new("C:/project"),
            Path::new("C:/temp"),
            &[
                PathBuf::from("C:/project/a.luau"),
                PathBuf::from("C:/project/b file.luau"),
            ],
        );
        assert_eq!(args, vec!["--flag", "a.luau", "b file.luau", "C:/temp/out"]);
    }

    #[test]
    fn embedded_changed_placeholder_expands_to_one_argv_per_file() {
        let args = expand_args(
            &["--file={changed}".into()],
            Path::new("C:/project"),
            Path::new("C:/temp"),
            &[
                PathBuf::from("C:/project/a.luau"),
                PathBuf::from("C:/project/b file.luau"),
            ],
        );
        assert_eq!(args, vec!["--file=a.luau", "--file=b file.luau"]);
    }

    #[test]
    fn rojo_output_is_forced_into_verification_temp_directory() {
        let args = command_args(
            Path::new("C:/project"),
            Path::new("C:/temp"),
            &[PathBuf::from("C:/project/a.luau")],
            &VerifyCommand {
                kind: VerifyKind::RojoBuild,
                name: "rojo".into(),
                program: "rojo".into(),
                args: vec!["build".into(), "-o".into(), "project.rbxlx".into()],
                timeout_ms: None,
                required: false,
                ..Default::default()
            },
        );
        assert!(args
            .windows(2)
            .any(|pair| { pair[0] == "-o" && pair[1].starts_with("C:/temp") }));
        assert!(!args.iter().any(|arg| arg == "project.rbxlx"));

        let equals_args = command_args(
            Path::new("C:/project"),
            Path::new("C:/temp"),
            &[],
            &VerifyCommand {
                kind: VerifyKind::RojoBuild,
                name: "rojo".into(),
                program: "rojo".into(),
                args: vec!["build".into(), "--output=project.rbxlx".into()],
                timeout_ms: None,
                required: false,
                ..Default::default()
            },
        );
        assert!(equals_args
            .iter()
            .any(|arg| arg.starts_with("--output=C:/temp")));
    }

    #[test]
    fn stylua_adapter_is_check_only() {
        let args = command_args(
            Path::new("C:/project"),
            Path::new("C:/temp"),
            &[],
            &VerifyCommand {
                kind: VerifyKind::StyluaCheck,
                name: "stylua".into(),
                program: "stylua".into(),
                args: Vec::new(),
                timeout_ms: None,
                required: false,
                ..Default::default()
            },
        );
        assert_eq!(args.first().map(String::as_str), Some("--check"));
    }

    #[test]
    fn required_verifier_hash_mismatch_fails_preflight() {
        let report = super::preflight_verification(&VerifyConfig {
            commands: vec![VerifyCommand {
                kind: VerifyKind::Generic,
                name: "pinned".into(),
                program: if cfg!(windows) {
                    "cmd.exe".into()
                } else {
                    "sh".into()
                },
                args: Vec::new(),
                timeout_ms: Some(1_000),
                required: true,
                expected_sha256: Some("0".repeat(64)),
                ..Default::default()
            }],
            ..Default::default()
        });
        assert!(!report.passed);
        assert_eq!(report.steps[0].status, "identity_mismatch");
    }

    #[cfg(windows)]
    #[test]
    fn captures_bounded_output_and_marks_truncation() {
        let report = super::run_verification(
            Path::new("C:/"),
            &crate::config::VerifyConfig {
                max_output_bytes: 8,
                commands: vec![VerifyCommand {
                    kind: VerifyKind::Generic,
                    name: "output".into(),
                    program: "cmd.exe".into(),
                    args: vec!["/C".into(), "echo 12345678901234567890".into()],
                    timeout_ms: Some(5_000),
                    required: true,
                    ..Default::default()
                }],
                ..Default::default()
            },
            &[],
        );
        assert!(report.passed);
        assert!(report.steps[0].output_truncated);
        assert!(report.steps[0]
            .stdout
            .as_deref()
            .is_some_and(|stdout| stdout.len() <= 8));
    }
}
