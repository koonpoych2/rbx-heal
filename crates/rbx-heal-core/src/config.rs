use crate::model::Severity;
use crate::path::{
    canonical_project_root, validate_existing_file, validate_relative_input, PathError,
};
use globset::Glob;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read config {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid config {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("config validation failed: {0}")]
    Validation(String),
    #[error("could not write config {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid config path: {0}")]
    Path(#[from] PathError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub version: u32,
    pub scan: ScanConfig,
    pub scope: ScopeConfig,
    pub architecture: ArchitectureConfig,
    pub rules: BTreeMap<String, RuleOverride>,
    pub suppressions: Vec<PathSuppression>,
    pub verify: VerifyConfig,
    pub policy: PolicyConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub roots: Vec<String>,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ScopeConfig {
    pub server: Vec<String>,
    pub client: Vec<String>,
    pub shared: Vec<String>,
    pub production: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    Server,
    Client,
    Shared,
    Production,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchitectureConfig {
    pub datastore_owners: Vec<String>,
    /// Calls which establish a local error boundary around DataStore access.
    /// The default matches the Roblox guidance to use `pcall`/`xpcall`.
    pub datastore_protectors: Vec<String>,
    pub currency_owners: Vec<String>,
    pub protected_fields: Vec<String>,
    pub sensitive_sinks: Vec<String>,
    pub remote_guards: Vec<String>,
    pub lifecycle_signals: Vec<String>,
    pub frame_signals: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleOverride {
    pub enabled: Option<bool>,
    pub severity: Option<Severity>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PathSuppression {
    pub rule: String,
    pub path: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct VerifyConfig {
    pub commands: Vec<VerifyCommand>,
    pub default_timeout_ms: u64,
    pub max_output_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyKind {
    #[default]
    Generic,
    RojoBuild,
    LuauAnalyze,
    StyluaCheck,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// Findings at or above this severity make check/fix return exit code 1.
    pub fail_on: Severity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct VerifyCommand {
    #[serde(default)]
    pub kind: VerifyKind,
    pub name: String,
    pub program: String,
    pub args: Vec<String>,
    pub timeout_ms: Option<u64>,
    pub required: bool,
    /// Optional exact version string expected from `program --version`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<String>,
    /// Optional SHA-256 of the resolved executable, for pinned CI tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            scan: ScanConfig::default(),
            scope: ScopeConfig::default(),
            architecture: ArchitectureConfig::default(),
            rules: BTreeMap::new(),
            suppressions: Vec::new(),
            verify: VerifyConfig::default(),
            policy: PolicyConfig::default(),
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            roots: vec!["src".into()],
            include: vec!["**/*.luau".into(), "**/*.lua".into()],
            exclude: vec![
                ".git/**".into(),
                "build/**".into(),
                "node_modules/**".into(),
                "Packages/**".into(),
                "ServerPackages/**".into(),
                "**/generated/**".into(),
                "**/*.generated.lua".into(),
                "**/*.generated.luau".into(),
            ],
        }
    }
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            server: vec![
                "**/server/**".into(),
                "**/*.server.lua".into(),
                "**/*.server.luau".into(),
            ],
            client: vec![
                "**/client/**".into(),
                "**/*.client.lua".into(),
                "**/*.client.luau".into(),
            ],
            shared: vec!["**/shared/**".into()],
            production: vec!["**/*.lua".into(), "**/*.luau".into()],
        }
    }
}

impl Default for ArchitectureConfig {
    fn default() -> Self {
        Self {
            datastore_owners: vec![
                "**/*DataService*.lua".into(),
                "**/*DataService*.luau".into(),
            ],
            datastore_protectors: vec!["pcall".into(), "xpcall".into()],
            currency_owners: vec![
                "**/*EconomyService*.lua".into(),
                "**/*EconomyService*.luau".into(),
            ],
            protected_fields: vec![
                "money".into(),
                "Money".into(),
                "cash".into(),
                "Cash".into(),
                "coins".into(),
                "Coins".into(),
                "currency".into(),
                "Currency".into(),
                "pendingCash".into(),
            ],
            sensitive_sinks: vec![
                "AddMoney".into(),
                "GiveMoney".into(),
                "AddCurrency".into(),
                "GrantReward".into(),
                "GiveReward".into(),
                "GrantItem".into(),
            ],
            remote_guards: vec![
                "RateLimiter".into(),
                "RateLimit".into(),
                "canTouch".into(),
                "Cooldown".into(),
                "Debounce".into(),
            ],
            lifecycle_signals: vec![
                "PlayerAdded".into(),
                "CharacterAdded".into(),
                "OnClientEvent".into(),
                "OnServerEvent".into(),
            ],
            frame_signals: vec![
                "Heartbeat".into(),
                "RenderStepped".into(),
                "Stepped".into(),
                "PreSimulation".into(),
                "PostSimulation".into(),
            ],
        }
    }
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            commands: Vec::new(),
            default_timeout_ms: 30_000,
            max_output_bytes: 32 * 1024,
        }
    }
}

impl Default for VerifyCommand {
    fn default() -> Self {
        Self {
            kind: VerifyKind::Generic,
            name: "verification".into(),
            program: String::new(),
            args: Vec::new(),
            timeout_ms: None,
            required: true,
            expected_version: None,
            expected_sha256: None,
        }
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            fail_on: Severity::Warning,
        }
    }
}

impl Config {
    pub fn sample() -> Self {
        let mut config = Self::default();
        config.scan.roots = vec!["src".into()];
        config.verify.commands.push(VerifyCommand {
            kind: VerifyKind::RojoBuild,
            name: "rojo-build".into(),
            program: "rojo".into(),
            args: vec![
                "build".into(),
                "default.project.json".into(),
                "-o".into(),
                "{temp}/rbx-heal-verify.rbxlx".into(),
            ],
            timeout_ms: Some(60_000),
            required: false,
            ..Default::default()
        });
        config
    }

    pub fn load(
        project_root: &Path,
        explicit: Option<&Path>,
    ) -> Result<(Self, Option<PathBuf>), ConfigError> {
        let display_root = project_root.to_path_buf();
        let project_root = canonical_project_root(project_root)?;
        let path: Option<PathBuf> = match explicit {
            Some(path) => {
                let candidate = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    validate_relative_input(path)?;
                    display_root.join(path)
                };
                Some(validate_existing_file(&project_root, &candidate).map(|_| candidate)?)
            }
            None => {
                let candidate = display_root.join("rbx-heal.toml");
                match fs::symlink_metadata(&candidate) {
                    Ok(_) => {
                        Some(validate_existing_file(&project_root, &candidate).map(|_| candidate)?)
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => {
                        return Err(ConfigError::Read {
                            path: candidate,
                            source: error,
                        })
                    }
                }
            }
        };
        let Some(path) = path else {
            return Ok((Self::default(), None));
        };
        let text = fs::read_to_string(&path).map_err(|source| ConfigError::Read {
            path: path.clone(),
            source,
        })?;
        let config: Self = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.clone(),
            source,
        })?;
        config.validate()?;
        Ok((config, Some(path)))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::Validation(format!(
                "unsupported config version {}",
                self.version
            )));
        }
        if self.scan.include.is_empty() {
            return Err(ConfigError::Validation(
                "scan.include must not be empty".into(),
            ));
        }
        for root in &self.scan.roots {
            validate_relative_input(Path::new(root)).map_err(|error| {
                ConfigError::Validation(format!("scan.roots must be project-relative: {error}"))
            })?;
        }
        if self.verify.default_timeout_ms == 0 {
            return Err(ConfigError::Validation(
                "verify.default_timeout_ms must be positive".into(),
            ));
        }
        if self.verify.max_output_bytes == 0 {
            return Err(ConfigError::Validation(
                "verify.max_output_bytes must be positive".into(),
            ));
        }
        for (name, patterns) in [
            ("scan.include", &self.scan.include),
            ("scan.exclude", &self.scan.exclude),
            ("scope.server", &self.scope.server),
            ("scope.client", &self.scope.client),
            ("scope.shared", &self.scope.shared),
            ("scope.production", &self.scope.production),
            (
                "architecture.datastore_owners",
                &self.architecture.datastore_owners,
            ),
            (
                "architecture.currency_owners",
                &self.architecture.currency_owners,
            ),
        ] {
            for pattern in patterns {
                if let Err(error) = Glob::new(pattern) {
                    return Err(ConfigError::Validation(format!(
                        "invalid {name} glob `{pattern}`: {error}"
                    )));
                }
            }
        }
        for suppression in &self.suppressions {
            if suppression.rule.trim().is_empty()
                || suppression.path.trim().is_empty()
                || suppression.reason.trim().is_empty()
            {
                return Err(ConfigError::Validation(
                    "suppressions require rule, path and non-empty reason".into(),
                ));
            }
            if let Err(error) = Glob::new(&suppression.path) {
                return Err(ConfigError::Validation(format!(
                    "invalid suppression path glob `{}`: {error}",
                    suppression.path
                )));
            }
            validate_relative_input(Path::new(&suppression.path)).map_err(|error| {
                ConfigError::Validation(format!(
                    "suppression paths must be project-relative: {error}"
                ))
            })?;
        }
        for command in &self.verify.commands {
            if command.name.trim().is_empty() || command.program.trim().is_empty() {
                return Err(ConfigError::Validation(
                    "verification commands require name and program".into(),
                ));
            }
            if command.timeout_ms == Some(0) {
                return Err(ConfigError::Validation(format!(
                    "verification command `{}` timeout must be positive",
                    command.name
                )));
            }
            if command
                .expected_version
                .as_deref()
                .is_some_and(|version| version.trim().is_empty())
            {
                return Err(ConfigError::Validation(format!(
                    "verification command `{}` expected_version must not be empty",
                    command.name
                )));
            }
            if let Some(expected) = command.expected_sha256.as_deref() {
                if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(ConfigError::Validation(format!(
                        "verification command `{}` expected_sha256 must be 64 hexadecimal characters",
                        command.name
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn write_sample(path: &Path) -> Result<(), ConfigError> {
        // `Path::exists` follows links and returns false for a dangling
        // symlink. Inspect the directory entry itself so `init` can never
        // write through a pre-existing link to an external target.
        if fs::symlink_metadata(path).is_ok() {
            return Err(ConfigError::Validation(format!(
                "refusing to overwrite existing {}",
                path.display()
            )));
        }
        let text = toml::to_string_pretty(&Self::sample()).expect("sample config is serializable");
        fs::write(path, text).map_err(|source| ConfigError::Write {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn rule_override(&self, id: &str) -> RuleOverride {
        self.rules.get(id).cloned().unwrap_or_default()
    }

    pub fn severity_for(&self, id: &str, fallback: Severity) -> Severity {
        self.rule_override(id).severity.unwrap_or(fallback)
    }

    pub fn is_enabled(&self, id: &str) -> bool {
        self.rule_override(id).enabled.unwrap_or(true)
    }

    pub fn scope_for_path(&self, path: &str) -> ScopeKind {
        let matches = |patterns: &[String]| {
            patterns.iter().any(|pattern| {
                Glob::new(pattern)
                    .ok()
                    .is_some_and(|glob| glob.compile_matcher().is_match(path))
            })
        };
        if matches(&self.scope.server) {
            ScopeKind::Server
        } else if matches(&self.scope.client) {
            ScopeKind::Client
        } else if matches(&self.scope.shared) {
            ScopeKind::Shared
        } else if matches(&self.scope.production) {
            ScopeKind::Production
        } else {
            ScopeKind::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn sample_round_trips_and_does_not_overwrite() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rbx-heal.toml");
        Config::write_sample(&path).unwrap();
        let (loaded, loaded_path) = Config::load(dir.path(), None).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded_path, Some(path.clone()));
        assert!(Config::write_sample(&path).is_err());
    }

    #[test]
    fn rejects_empty_suppression_reason() {
        let mut config = Config::default();
        config.suppressions.push(PathSuppression {
            rule: "RBX-SEC-001".into(),
            path: "src/**".into(),
            reason: String::new(),
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_invalid_suppression_glob() {
        let mut config = Config::default();
        config.suppressions.push(PathSuppression {
            rule: "RBX-SEC-001".into(),
            path: "[".into(),
            reason: "intentional".into(),
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn resolves_configured_scope_by_relative_path() {
        let config = Config::default();
        assert_eq!(
            config.scope_for_path("src/server/Main.server.luau"),
            ScopeKind::Server
        );
        assert_eq!(
            config.scope_for_path("src/client/Hud.client.luau"),
            ScopeKind::Client
        );
        assert_eq!(
            config.scope_for_path("src/shared/Types.luau"),
            ScopeKind::Shared
        );
        assert_eq!(
            config.scope_for_path("src/Module.luau"),
            ScopeKind::Production
        );
    }

    #[test]
    fn policy_and_verifier_limits_round_trip_additively() {
        let mut config = Config::default();
        config.policy.fail_on = Severity::Error;
        config.verify.max_output_bytes = 128;
        let text = toml::to_string(&config).unwrap();
        let parsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(parsed.policy.fail_on, Severity::Error);
        assert_eq!(parsed.verify.max_output_bytes, 128);
    }

    #[test]
    fn rejects_zero_verifier_output_limit() {
        let mut config = Config::default();
        config.verify.max_output_bytes = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_scan_root_escape() {
        let mut config = Config::default();
        config.scan.roots = vec!["../outside".into()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn verifier_identity_pins_round_trip_and_validate() {
        let mut config = Config::default();
        config.verify.commands.push(VerifyCommand {
            name: "luau".into(),
            program: "luau-analyze".into(),
            expected_version: Some("0.735".into()),
            expected_sha256: Some("a".repeat(64)),
            required: true,
            ..Default::default()
        });
        config.validate().unwrap();
        let parsed: Config = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
        assert_eq!(
            parsed.verify.commands[0].expected_version.as_deref(),
            Some("0.735")
        );
        let expected_sha256 = "a".repeat(64);
        assert_eq!(
            parsed.verify.commands[0].expected_sha256.as_deref(),
            Some(expected_sha256.as_str())
        );
    }

    #[cfg(unix)]
    #[test]
    fn init_refuses_dangling_symlink_instead_of_following_it() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let destination = dir.path().join("rbx-heal.toml");
        symlink(dir.path().join("outside.toml"), &destination).unwrap();
        assert!(Config::write_sample(&destination).is_err());
        assert!(!dir.path().join("outside.toml").exists());
    }
}
