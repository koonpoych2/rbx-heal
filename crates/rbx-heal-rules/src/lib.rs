//! Built-in Roblox/Luau rules for the Healer MVP.

use globset::{Glob, GlobSetBuilder};
use rbx_heal_core::{
    engine::{Rule, RuleContext, RuleExample, RuleMetadata},
    model::{Confidence, Edit, Finding, Fixability, Severity},
    parser::{LexKind, LexToken, ParsedFile},
    semantic::{BindingId, FunctionId, TaintState},
};

pub fn built_in_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(RemoteSensitiveWrite),
        Box::new(RemoteWithoutGuard),
        Box::new(DataStoreOutsideOwner),
        Box::new(DefaultOnLoadFailure),
        Box::new(DataStoreWithoutProtection),
        Box::new(ProtectedMutation),
        Box::new(FrameTraversal),
        Box::new(LifecycleConnection),
        Box::new(MissingStrict),
        Box::new(LegacyTask),
        Box::new(LegacySignalAlias),
        Box::new(LegacyServiceAlias),
    ]
}

const ALL_SCOPES: &[rbx_heal_core::config::ScopeKind] = &[
    rbx_heal_core::config::ScopeKind::Server,
    rbx_heal_core::config::ScopeKind::Client,
    rbx_heal_core::config::ScopeKind::Shared,
    rbx_heal_core::config::ScopeKind::Production,
];
const SERVER_SCOPES: &[rbx_heal_core::config::ScopeKind] = &[
    rbx_heal_core::config::ScopeKind::Server,
    rbx_heal_core::config::ScopeKind::Shared,
];
static EXAMPLES_SEC_001: &[RuleExample] = &[
    RuleExample {
        label: "positive",
        source: "Remote.OnServerEvent:Connect(function(player, amount) data.Money = amount end)",
    },
    RuleExample {
        label: "negative",
        source: "Remote.OnServerEvent:Connect(function(player) data.Money = 10 end)",
    },
];
static EXAMPLES_NET_001: &[RuleExample] = &[
    RuleExample {
        label: "positive",
        source: "Remote.OnServerEvent:Connect(function(player) grant(player) end)",
    },
    RuleExample {
        label: "negative",
        source: "Remote.OnServerEvent:Connect(function(player) RateLimiter:Check(player) end)",
    },
];
static EXAMPLES_DATA_001: &[RuleExample] = &[
    RuleExample {
        label: "positive",
        source: "local store = DSS:GetDataStore(\"Players\")\nstore:GetAsync(key)",
    },
    RuleExample {
        label: "negative",
        source: "-- DataService.luau\nstore:GetAsync(key)",
    },
];
static EXAMPLES_DATA_002: &[RuleExample] = &[
    RuleExample {
        label: "positive",
        source: "local ok, data = pcall(load)\nif not ok then return {} end",
    },
    RuleExample {
        label: "negative",
        source: "local ok, data = pcall(load)\nif not ok then return nil end",
    },
];
static EXAMPLES_DATA_003: &[RuleExample] = &[
    RuleExample {
        label: "positive",
        source: "local store = DSS:GetDataStore(\"Players\")\nlocal data = store:GetAsync(key)",
    },
    RuleExample {
        label: "negative",
        source: "local ok, data = pcall(function() return store:GetAsync(key) end)",
    },
];
static EXAMPLES_ARCH_001: &[RuleExample] = &[
    RuleExample {
        label: "positive",
        source: "profile.Money = amount",
    },
    RuleExample {
        label: "negative",
        source: "-- EconomyService.luau\nprofile.Money = amount",
    },
];
static EXAMPLES_PERF_001: &[RuleExample] = &[
    RuleExample {
        label: "positive",
        source: "RunService.Heartbeat:Connect(function() workspace:GetDescendants() end)",
    },
    RuleExample {
        label: "negative",
        source: "local refs = workspace:GetDescendants()\nRunService.Heartbeat:Connect(function() print(#refs) end)",
    },
];
static EXAMPLES_LIFE_001: &[RuleExample] = &[
    RuleExample {
        label: "positive",
        source: "Players.PlayerAdded:Connect(function() part.Touched:Connect(onTouch) end)",
    },
    RuleExample {
        label: "negative",
        source: "Players.PlayerAdded:Connect(function() table.insert(connections, part.Touched:Connect(onTouch)) end)",
    },
];
static EXAMPLES_TYPE_001: &[RuleExample] = &[
    RuleExample {
        label: "positive",
        source: "local function production() return true end",
    },
    RuleExample {
        label: "negative",
        source: "--!strict\nlocal function production() return true end",
    },
];
static EXAMPLES_TASK_001: &[RuleExample] = &[
    RuleExample {
        label: "positive",
        source: "wait(1)",
    },
    RuleExample {
        label: "negative",
        source: "task.wait(1)",
    },
];
static EXAMPLES_API_001: &[RuleExample] = &[
    RuleExample {
        label: "positive",
        source: "signal:connect(handler)",
    },
    RuleExample {
        label: "negative",
        source: "signal:Connect(handler)",
    },
];
static EXAMPLES_API_002: &[RuleExample] = &[
    RuleExample {
        label: "positive",
        source: "game:service(\"Players\")",
    },
    RuleExample {
        label: "negative",
        source: "game:GetService(\"Players\")",
    },
];

static META_SEC_001: RuleMetadata = RuleMetadata {
    id: "RBX-SEC-001",
    category: "security",
    default_severity: Severity::Error,
    default_confidence: Confidence::High,
    fixability: Fixability::None,
    applicable_scopes: SERVER_SCOPES,
    summary: "A client-controlled remote argument reaches a sensitive mutation sink.",
    rationale: "RemoteEvent arguments are untrusted and must not directly choose currency, reward, or state mutations.",
    remediation: "Derive the authoritative value on the server and validate the requested action against server state.",
    examples: EXAMPLES_SEC_001,
    semantic_pattern: "remote_arg_to_sensitive_sink/v2",
};
static META_NET_001: RuleMetadata = RuleMetadata {
    id: "RBX-NET-001",
    category: "network",
    default_severity: Severity::Warning,
    default_confidence: Confidence::Medium,
    fixability: Fixability::None,
    applicable_scopes: SERVER_SCOPES,
    summary: "A server remote handler has no configured anti-spam guard.",
    rationale:
        "Server remotes are public entry points and can be invoked faster than intended by clients.",
    remediation:
        "Add a configured rate limiter, cooldown, or debounce before expensive or mutating work.",
    examples: EXAMPLES_NET_001,
    semantic_pattern: "server_remote_without_guard/v2",
};
static META_DATA_001: RuleMetadata = RuleMetadata {
    id: "RBX-DATA-001",
    category: "data",
    default_severity: Severity::Error,
    default_confidence: Confidence::High,
    fixability: Fixability::None,
    applicable_scopes: SERVER_SCOPES,
    summary: "DataStore access is outside configured persistence owner paths.",
    rationale: "Centralized persistence ownership prevents inconsistent retries, schemas, and shutdown handling.",
    remediation: "Move DataStore access behind the configured DataService or persistence owner.",
    examples: EXAMPLES_DATA_001,
    semantic_pattern: "datastore_outside_owner/v1",
};
static META_DATA_002: RuleMetadata = RuleMetadata {
    id: "RBX-DATA-002",
    category: "data",
    default_severity: Severity::Error,
    default_confidence: Confidence::High,
    fixability: Fixability::None,
    applicable_scopes: SERVER_SCOPES,
    summary: "A persistence load failure appears to return a fresh default profile.",
    rationale: "Treating a failed load as a new profile can overwrite a player's existing data.",
    remediation: "Distinguish load failure from a successful nil/new-profile result and retry or fail safely.",
    examples: EXAMPLES_DATA_002,
    semantic_pattern: "load_failure_returns_default/v1",
};
static META_DATA_003: RuleMetadata = RuleMetadata {
    id: "RBX-DATA-003",
    category: "data",
    default_severity: Severity::Warning,
    default_confidence: Confidence::Medium,
    fixability: Fixability::None,
    applicable_scopes: SERVER_SCOPES,
    summary: "A proven DataStore network call is not inside a local error boundary.",
    rationale: "DataStore calls can fail transiently and should be protected so failures are handled explicitly.",
    remediation: "Wrap the access in a configured pcall/xpcall boundary and handle the failure result.",
    examples: EXAMPLES_DATA_003,
    semantic_pattern: "datastore_call_without_local_error_boundary/v1",
};
static META_ARCH_001: RuleMetadata = RuleMetadata {
    id: "RBX-ARCH-001",
    category: "architecture",
    default_severity: Severity::Warning,
    default_confidence: Confidence::Medium,
    fixability: Fixability::None,
    applicable_scopes: ALL_SCOPES,
    summary: "A protected domain field is mutated outside its owner service.",
    rationale: "Domain ownership keeps currency and profile invariants in one auditable service.",
    remediation:
        "Call the configured owner service API instead of assigning the protected field directly.",
    examples: EXAMPLES_ARCH_001,
    semantic_pattern: "protected_field_outside_owner/v1",
};
static META_PERF_001: RuleMetadata = RuleMetadata {
    id: "RBX-PERF-001",
    category: "performance",
    default_severity: Severity::Warning,
    default_confidence: Confidence::High,
    fixability: Fixability::None,
    applicable_scopes: ALL_SCOPES,
    summary: "Hierarchy traversal occurs inside a per-frame callback.",
    rationale: "Repeated hierarchy traversal can allocate and scan a large tree every frame.",
    remediation: "Cache references and update them from instance lifecycle events.",
    examples: EXAMPLES_PERF_001,
    semantic_pattern: "hierarchy_traversal_in_frame_callback/v1",
};
static META_LIFE_001: RuleMetadata = RuleMetadata {
    id: "RBX-LIFE-001",
    category: "lifecycle",
    default_severity: Severity::Warning,
    default_confidence: Confidence::Low,
    fixability: Fixability::None,
    applicable_scopes: ALL_SCOPES,
    summary:
        "A connection is created inside a repeatable lifecycle callback without an obvious owner.",
    rationale:
        "Repeated lifecycle callbacks can leak connections when ownership and cleanup are implicit.",
    remediation: "Store the connection with the owning object and disconnect it during cleanup.",
    examples: EXAMPLES_LIFE_001,
    semantic_pattern: "lifecycle_connection_without_cleanup/v1",
};
static META_TYPE_001: RuleMetadata = RuleMetadata {
    id: "RBX-TYPE-001",
    category: "type_safety",
    default_severity: Severity::Info,
    default_confidence: Confidence::High,
    fixability: Fixability::None,
    applicable_scopes: ALL_SCOPES,
    summary: "A production Luau module does not opt into strict mode.",
    rationale: "Strict mode catches type mismatches before they become runtime defects.",
    remediation: "Add --!strict after addressing the type errors it reveals.",
    examples: EXAMPLES_TYPE_001,
    semantic_pattern: "production_module_without_strict/v1",
};
static META_TASK_001: RuleMetadata = RuleMetadata {
    id: "RBX-TASK-001",
    category: "api",
    default_severity: Severity::Warning,
    default_confidence: Confidence::High,
    fixability: Fixability::Suggested,
    applicable_scopes: ALL_SCOPES,
    summary: "A legacy scheduler global is used.",
    rationale:
        "Legacy scheduler functions have timing and error semantics that differ from task.* APIs.",
    remediation: "Review a task.* migration manually and verify timing behavior.",
    examples: EXAMPLES_TASK_001,
    semantic_pattern: "legacy_scheduler_global/v1",
};
static META_API_001: RuleMetadata = RuleMetadata {
    id: "RBX-API-001",
    category: "api",
    default_severity: Severity::Warning,
    default_confidence: Confidence::High,
    fixability: Fixability::Safe,
    applicable_scopes: ALL_SCOPES,
    summary: "A proven Roblox signal or connection uses a legacy lowercase alias.",
    rationale: "Canonical method spelling is supported by Roblox APIs and avoids legacy aliases.",
    remediation: "Use Connect or Disconnect with the canonical capitalization.",
    examples: EXAMPLES_API_001,
    semantic_pattern: "legacy_signal_method_alias/v1",
};
static META_API_002: RuleMetadata = RuleMetadata {
    id: "RBX-API-002",
    category: "api",
    default_severity: Severity::Warning,
    default_confidence: Confidence::High,
    fixability: Fixability::Safe,
    applicable_scopes: ALL_SCOPES,
    summary: "The deprecated game:service alias is used with a literal service name.",
    rationale:
        "GetService is the canonical Roblox service lookup and is explicit about the API call.",
    remediation: "Replace game:service(\"Name\") with game:GetService(\"Name\").",
    examples: EXAMPLES_API_002,
    semantic_pattern: "legacy_game_service_alias/v1",
};

struct RemoteSensitiveWrite;
struct RemoteWithoutGuard;
struct DataStoreOutsideOwner;
struct DefaultOnLoadFailure;
struct DataStoreWithoutProtection;
struct ProtectedMutation;
struct FrameTraversal;
struct LifecycleConnection;
struct MissingStrict;
struct LegacyTask;
struct LegacySignalAlias;
struct LegacyServiceAlias;

impl Rule for RemoteSensitiveWrite {
    fn metadata(&self) -> &'static RuleMetadata {
        &META_SEC_001
    }
    fn analyze(&self, context: &RuleContext<'_>, findings: &mut Vec<Finding>) {
        let file = context.file;
        let config = context.config;
        for handler in handlers(file, &config.architecture.frame_signals) {
            if !is_server_remote(&handler.signal_name) {
                continue;
            }
            let params = handler.params.iter().skip(1).cloned().collect::<Vec<_>>();
            if params.is_empty() {
                continue;
            }
            let source_bindings = handler
                .param_bindings
                .iter()
                .skip(1)
                .copied()
                .collect::<Vec<_>>();
            for (index, token) in handler.body.iter().enumerate() {
                let Some(token_index) = handler.body_raw.get(index).copied() else {
                    continue;
                };
                if file.semantic.enclosing_function(token_index) != Some(handler.function_id) {
                    continue;
                }
                let sensitive_field =
                    if is_protected_field(token, &config.architecture.protected_fields)
                        && handler
                            .body
                            .get(index + 1)
                            .is_some_and(|next| is_assignment_operator(next))
                    {
                        handler
                            .body_raw
                            .get(index + 1)
                            .copied()
                            .and_then(|operator_index| {
                                file.semantic
                                    .significant_position(operator_index)
                                    .map(|operator_position| (operator_index, operator_position))
                            })
                            .is_some_and(|(_, operator_position)| {
                                let end = expression_end(
                                    file,
                                    operator_position + 1,
                                    handler.function_id,
                                );
                                matches!(
                                    file.semantic.expression_taint(
                                        handler.function_id,
                                        operator_position + 1,
                                        end,
                                        &source_bindings,
                                        &file.tokens,
                                        &file.significant,
                                    ),
                                    TaintState::RemoteTainted
                                )
                            })
                    } else {
                        false
                    };
                let sink_call = file
                    .semantic
                    .calls
                    .iter()
                    .find(|call| call.token_index == token_index)
                    .filter(|call| {
                        call.function == Some(handler.function_id)
                            && config
                                .architecture
                                .sensitive_sinks
                                .iter()
                                .any(|sink| sink == &call.name)
                    })
                    .is_some_and(|call| {
                        let Some(open_position) =
                            file.semantic.significant_position(call.open_paren_index)
                        else {
                            return false;
                        };
                        let Some(close_position) = matching_paren_position(file, open_position)
                        else {
                            return false;
                        };
                        matches!(
                            file.semantic.expression_taint(
                                handler.function_id,
                                open_position + 1,
                                close_position,
                                &source_bindings,
                                &file.tokens,
                                &file.significant,
                            ),
                            TaintState::RemoteTainted
                        )
                    });
                if sensitive_field || sink_call {
                    let kind = if sensitive_field {
                        "protected state"
                    } else {
                        "sensitive sink"
                    };
                    findings.push(
                        finding(
                            file,
                            self,
                            token,
                            format!(
                                "remote input flows into a {kind}; derive the value on the server"
                            ),
                        )
                        .with_evidence([
                            "handler is reachable from a server remote endpoint",
                            "argument is used without a proven server-side derivation",
                        ]),
                    );
                }
            }
        }
    }
}

impl Rule for RemoteWithoutGuard {
    fn metadata(&self) -> &'static RuleMetadata {
        &META_NET_001
    }
    fn analyze(&self, context: &RuleContext<'_>, findings: &mut Vec<Finding>) {
        let file = context.file;
        let config = context.config;
        for handler in handlers(file, &config.architecture.frame_signals) {
            if !is_server_remote(&handler.signal_name) {
                continue;
            }
            let guarded = config.architecture.remote_guards.iter().any(|guard| {
                file.semantic.calls.iter().any(|call| {
                    call.function == Some(handler.function_id)
                        && (call.name == *guard
                            || call.receiver_token.is_some_and(|receiver| {
                                file.tokens
                                    .get(receiver)
                                    .is_some_and(|token| token.text == *guard)
                            }))
                })
            });
            if !guarded {
                findings.push(finding(file, self, handler.signal, "server remote handler has no configured rate-limit, cooldown, or debounce guard")
                    .with_evidence(["server remote handlers are public untrusted APIs", "no configured guard symbol occurs in this handler"]));
            }
        }
    }
}

impl Rule for DataStoreOutsideOwner {
    fn metadata(&self) -> &'static RuleMetadata {
        &META_DATA_001
    }
    fn analyze(&self, context: &RuleContext<'_>, findings: &mut Vec<Finding>) {
        let file = context.file;
        let config = context.config;
        if matches_any(&file.relative_path, &config.architecture.datastore_owners) {
            return;
        }
        for call in file.semantic.calls.iter().filter(|call| {
            matches!(
                call.name.as_str(),
                "GetDataStore"
                    | "GetOrderedDataStore"
                    | "GetAsync"
                    | "SetAsync"
                    | "UpdateAsync"
                    | "RemoveAsync"
            ) && is_datastore_call(file, call)
        }) {
            let Some(token) = file.tokens.get(call.token_index) else {
                continue;
            };
            findings.push(
                finding(
                    file,
                    self,
                    token,
                    "DataStore access must be owned by a configured DataService/persistence module",
                )
                .with_evidence([format!(
                    "persistence API `{}` found outside owner path",
                    token.text
                )]),
            );
        }
    }
}

impl Rule for DataStoreWithoutProtection {
    fn metadata(&self) -> &'static RuleMetadata {
        &META_DATA_003
    }

    fn analyze(&self, context: &RuleContext<'_>, findings: &mut Vec<Finding>) {
        let file = context.file;
        let protectors = &context.config.architecture.datastore_protectors;
        for call in file.semantic.calls.iter().filter(|call| {
            matches!(
                call.name.as_str(),
                "GetAsync"
                    | "SetAsync"
                    | "UpdateAsync"
                    | "RemoveAsync"
                    | "IncrementAsync"
                    | "GetSortedAsync"
                    | "GetVersionAsync"
                    | "GetVersionAtTimeAsync"
                    | "RemoveVersionAsync"
                    | "ListKeysAsync"
                    | "ListVersionsAsync"
                    | "ListDataStoresAsync"
            ) && is_datastore_call(file, call)
        }) {
            if datastore_call_has_boundary(file, call, protectors) {
                continue;
            }
            let Some(token) = file.tokens.get(call.token_index) else {
                continue;
            };
            findings.push(
                finding(
                    file,
                    self,
                    token,
                    "DataStore network call has no configured local error boundary",
                )
                .with_evidence([
                    format!("proven DataStore API `{}` is called directly", call.name),
                    "no enclosing configured pcall/xpcall protector was found".to_string(),
                ]),
            );
        }
    }
}

impl Rule for DefaultOnLoadFailure {
    fn metadata(&self) -> &'static RuleMetadata {
        &META_DATA_002
    }
    fn analyze(&self, context: &RuleContext<'_>, findings: &mut Vec<Finding>) {
        let file = context.file;
        let sig = significant(file);
        for index in 0..sig.len().saturating_sub(4) {
            if sig[index].text != "if"
                || sig[index + 1].text != "not"
                || !matches!(sig[index + 2].text.as_str(), "ok" | "success")
                || sig[index + 3].text != "then"
            {
                continue;
            }
            let Some(end_index) = matching_control_end(&sig, index) else {
                continue;
            };
            let Some(if_token_index) = file
                .significant
                .iter()
                .copied()
                .find(|token_index| file.tokens[*token_index].range == sig[index].range)
            else {
                continue;
            };
            let Some(function_id) = file.semantic.enclosing_function(if_token_index) else {
                continue;
            };
            let Some(ok_token_index) = file
                .significant
                .iter()
                .copied()
                .find(|token_index| file.tokens[*token_index].range == sig[index + 2].range)
            else {
                continue;
            };
            let Some(ok_binding) = file.semantic.binding_for_token(ok_token_index) else {
                continue;
            };
            let Some(assignment) = file.semantic.assignments.iter().find(|assignment| {
                assignment.function == Some(function_id)
                    && assignment.target == Some(ok_binding)
                    && assignment.operator_token < if_token_index
            }) else {
                continue;
            };
            let Some(pcall) = file.semantic.calls.iter().find(|call| {
                call.name == "pcall"
                    && call.function == Some(function_id)
                    && call.token_index > assignment.operator_token
                    && call.token_index < if_token_index
            }) else {
                continue;
            };
            let Some(pcall_open_position) =
                file.semantic.significant_position(pcall.open_paren_index)
            else {
                continue;
            };
            let Some(pcall_close) = matching_paren_position(file, pcall_open_position) else {
                continue;
            };
            let wraps_get_async = file.semantic.calls.iter().any(|call| {
                call.name == "GetAsync"
                    && is_datastore_call(file, call)
                    && file
                        .semantic
                        .significant_position(call.token_index)
                        .is_some_and(|position| {
                            position > pcall_open_position && position < pcall_close
                        })
            });
            if !wraps_get_async {
                continue;
            }
            if let Some(return_index) = (index + 4..end_index).find(|candidate| {
                sig[*candidate].text == "return"
                    && sig.get(*candidate + 1).is_some_and(|next| next.text == "{")
            }) {
                findings.push(finding(file, self, sig[return_index], "load failure returns default data; distinguish failed loads from a genuinely new profile")
                    .with_evidence(["pcall wraps GetAsync", "failure branch returns a table/default profile"]));
            }
        }
    }
}

impl Rule for ProtectedMutation {
    fn metadata(&self) -> &'static RuleMetadata {
        &META_ARCH_001
    }
    fn analyze(&self, context: &RuleContext<'_>, findings: &mut Vec<Finding>) {
        let file = context.file;
        let config = context.config;
        if matches_any(&file.relative_path, &config.architecture.currency_owners) {
            return;
        }
        let sig = significant(file);
        for window in sig.windows(3) {
            if window[0].text == "."
                && is_protected_field(window[1], &config.architecture.protected_fields)
                && is_assignment_operator(window[2])
            {
                findings.push(finding(file, self, window[1], "protected currency/domain state is mutated outside its configured owner service")
                    .with_evidence(vec![format!("field `{}` is assigned directly", window[1].text), "use the owning service API for controlled mutation".to_string()]));
            }
        }
    }
}

impl Rule for FrameTraversal {
    fn metadata(&self) -> &'static RuleMetadata {
        &META_PERF_001
    }
    fn analyze(&self, context: &RuleContext<'_>, findings: &mut Vec<Finding>) {
        let file = context.file;
        let config = context.config;
        for handler in handlers(file, &config.architecture.frame_signals) {
            if !config
                .architecture
                .frame_signals
                .iter()
                .any(|signal| signal == &handler.signal_name)
            {
                continue;
            }
            if handler.signal_name.eq_ignore_ascii_case("OnServerEvent") {
                continue;
            }
            if let Some((_index, token)) = handler.body.iter().enumerate().find(|(index, token)| {
                handler
                    .body_raw
                    .get(*index)
                    .and_then(|token| file.semantic.enclosing_function(*token))
                    == Some(handler.function_id)
                    && matches!(token.text.as_str(), "GetDescendants" | "GetChildren")
            }) {
                findings.push(finding(file, self, token, "hierarchy traversal runs inside a frame callback; cache or update references on events")
                    .with_evidence([format!("frame signal `{}` contains `{}`", handler.signal_name, token.text)]));
            }
        }
    }
}

impl Rule for LifecycleConnection {
    fn metadata(&self) -> &'static RuleMetadata {
        &META_LIFE_001
    }
    fn analyze(&self, context: &RuleContext<'_>, findings: &mut Vec<Finding>) {
        let file = context.file;
        let config = context.config;
        let handlers = handlers(file, &config.architecture.lifecycle_signals);
        for outer in handlers {
            if !config
                .architecture
                .lifecycle_signals
                .iter()
                .any(|signal| signal == &outer.signal_name)
            {
                continue;
            }
            let nested = file.semantic.calls.iter().find(|call| {
                call.function.is_some_and(|function| {
                    function == outer.function_id
                        || file
                            .semantic
                            .function(function)
                            .zip(file.semantic.function(outer.function_id))
                            .is_some_and(|(candidate, parent)| {
                                candidate.range.start.byte >= parent.range.start.byte
                                    && candidate.range.end.byte <= parent.range.end.byte
                            })
                }) && matches!(call.name.as_str(), "Connect" | "connect")
            });
            if let Some(call) = nested {
                let Some(connection_token) = file.tokens.get(call.token_index) else {
                    continue;
                };
                let has_retention = outer
                    .body
                    .iter()
                    .any(|token| token.text == "connections" || token.text == "Connection")
                    || outer.body.windows(4).any(|window| {
                        window[0].text == "table"
                            && window[1].text == "."
                            && window[2].text == "insert"
                            && window[3].text == "("
                    });
                if !has_retention {
                    findings.push(
                        finding(
                            file,
                            self,
                            connection_token,
                            "lifecycle-created connection is not obviously retained for cleanup",
                        )
                        .with_evidence(vec![
                            format!("nested in `{}` lifecycle callback", outer.signal_name),
                            "store and disconnect resources with the owning object".to_string(),
                        ]),
                    );
                }
            }
        }
    }
}

impl Rule for MissingStrict {
    fn metadata(&self) -> &'static RuleMetadata {
        &META_TYPE_001
    }
    fn analyze(&self, context: &RuleContext<'_>, findings: &mut Vec<Finding>) {
        let file = context.file;
        let config = context.config;
        if !matches_any(&file.relative_path, &config.scope.production) || file.has_strict_directive
        {
            return;
        }
        let token = file
            .significant
            .first()
            .and_then(|index| file.tokens.get(*index));
        if let Some(token) = token {
            findings.push(
                finding(
                    file,
                    self,
                    token,
                    "production Luau module has no --!strict directive",
                )
                .with_evidence([
                    "strict mode is required by the project policy",
                    "add --!strict after confirming type errors are addressed",
                ]),
            );
        }
    }
}

impl Rule for LegacyTask {
    fn metadata(&self) -> &'static RuleMetadata {
        &META_TASK_001
    }
    fn analyze(&self, context: &RuleContext<'_>, findings: &mut Vec<Finding>) {
        let file = context.file;
        let sig = significant(file);
        for (index, token) in sig.iter().enumerate() {
            if !matches!(token.text.as_str(), "wait" | "spawn" | "delay")
                || sig.get(index + 1).is_none_or(|next| next.text != "(")
            {
                continue;
            }
            if index > 0 && matches!(sig[index - 1].text.as_str(), "." | ":") {
                continue;
            }
            if shadowed_global(file, token.text.as_str(), token.range.start.byte) {
                continue;
            }
            findings.push(
                finding(
                    file,
                    self,
                    token,
                    format!(
                        "legacy `{}` scheduler call; review before migrating to task.*",
                        token.text
                    ),
                )
                .suggested(format!(
                    "review `task.{}` migration; timing and error behavior can differ",
                    token.text
                )),
            );
        }
    }
}

impl Rule for LegacySignalAlias {
    fn metadata(&self) -> &'static RuleMetadata {
        &META_API_001
    }
    fn analyze(&self, context: &RuleContext<'_>, findings: &mut Vec<Finding>) {
        let file = context.file;
        let sig = significant(file);
        for (index, token) in sig.iter().enumerate() {
            let replacement = match token.text.as_str() {
                "connect" => "Connect",
                "disconnect" => "Disconnect",
                _ => continue,
            };
            if index == 0 || !matches!(sig[index - 1].text.as_str(), "." | ":") {
                continue;
            }
            if token.text == "connect"
                && !looks_like_signal_receiver(file, &sig, index.saturating_sub(1))
            {
                continue;
            }
            if token.text == "disconnect"
                && !looks_like_connection_receiver(file, &sig, index.saturating_sub(1))
            {
                continue;
            }
            let mut result = finding(
                file,
                self,
                token,
                format!("use Roblox `{replacement}` method spelling"),
            );
            result.fixability = Fixability::Safe;
            result.fix_description = Some(format!("rename `{}` to `{replacement}`", token.text));
            findings.push(result);
        }
    }

    fn safe_fix(&self, context: &RuleContext<'_>, finding: &Finding) -> Option<Vec<Edit>> {
        let expected = context.file.source_slice(finding.range);
        let replacement = match expected {
            "connect" => "Connect",
            "disconnect" => "Disconnect",
            _ => return None,
        };
        Some(vec![Edit::new(finding.range, expected, replacement)])
    }
}

impl Rule for LegacyServiceAlias {
    fn metadata(&self) -> &'static RuleMetadata {
        &META_API_002
    }
    fn analyze(&self, context: &RuleContext<'_>, findings: &mut Vec<Finding>) {
        let file = context.file;
        let sig = significant(file);
        for index in 0..sig.len().saturating_sub(3) {
            if sig[index].text == "game"
                && !shadowed_global(file, "game", sig[index].range.start.byte)
                && sig[index + 1].text == ":"
                && sig[index + 2].text == "service"
                && sig[index + 3].text == "("
                && sig
                    .get(index + 4)
                    .is_some_and(|token| token.kind == LexKind::String)
            {
                let mut result = finding(
                    file,
                    self,
                    sig[index + 2],
                    "use game:GetService for Roblox service lookup",
                );
                result.fixability = Fixability::Safe;
                result.fix_description = Some("rename game:service to game:GetService".into());
                findings.push(result);
            }
        }
    }

    fn safe_fix(&self, context: &RuleContext<'_>, finding: &Finding) -> Option<Vec<Edit>> {
        let expected = context.file.source_slice(finding.range);
        (expected == "service").then(|| vec![Edit::new(finding.range, expected, "GetService")])
    }
}

#[derive(Clone)]
struct Handler<'a> {
    signal: &'a LexToken,
    signal_name: String,
    params: Vec<String>,
    param_bindings: Vec<BindingId>,
    body: Vec<&'a LexToken>,
    body_raw: Vec<usize>,
    function_id: FunctionId,
}

fn is_server_remote(signal: &str) -> bool {
    signal.eq_ignore_ascii_case("OnServerEvent") || signal.eq_ignore_ascii_case("OnServerInvoke")
}

fn handlers<'a>(file: &'a ParsedFile, signals: &[String]) -> Vec<Handler<'a>> {
    let mut result = Vec::new();
    for endpoint in &file.semantic.remote_endpoints {
        let Some(function) = file.semantic.function(endpoint.function_id) else {
            continue;
        };
        let signal_name = endpoint.signal_name.as_str();
        if !signals.iter().any(|signal| signal == signal_name)
            && !matches!(
                signal_name,
                "OnServerEvent"
                    | "OnServerInvoke"
                    | "OnClientEvent"
                    | "Heartbeat"
                    | "RenderStepped"
                    | "Stepped"
                    | "PlayerAdded"
                    | "CharacterAdded"
            )
        {
            continue;
        }
        let signal_raw = endpoint.signal_token;
        let Some(signal) = file.tokens.get(signal_raw) else {
            continue;
        };
        let params = function
            .parameters
            .iter()
            .filter_map(|binding| {
                file.semantic
                    .binding(*binding)
                    .map(|fact| fact.name.clone())
            })
            .collect::<Vec<_>>();
        let body_positions = function.body_tokens.clone().collect::<Vec<_>>();
        let body_raw = body_positions
            .iter()
            .filter_map(|position| file.significant.get(*position))
            .copied()
            .collect::<Vec<_>>();
        let body = body_raw
            .iter()
            .filter_map(|token_index| file.tokens.get(*token_index))
            .collect::<Vec<_>>();
        result.push(Handler {
            signal,
            signal_name: signal_name.to_owned(),
            params,
            param_bindings: function.parameters.clone(),
            body,
            body_raw,
            function_id: function.id,
        });
    }
    result
}

fn significant(file: &ParsedFile) -> Vec<&LexToken> {
    file.significant
        .iter()
        .filter_map(|index| file.tokens.get(*index))
        .filter(|token| !token.text.is_empty())
        .collect()
}

fn expression_end(file: &ParsedFile, start: usize, function: FunctionId) -> usize {
    let limit = file
        .semantic
        .function(function)
        .map(|function| function.body_tokens.end)
        .unwrap_or(file.significant.len());
    let mut depth = 0usize;
    for position in start.min(limit)..limit {
        let token = &file.tokens[file.significant[position]];
        match token.text.as_str() {
            "(" | "{" | "[" => depth += 1,
            ")" | "}" | "]" => depth = depth.saturating_sub(1),
            ";" | "end" | "else" | "elseif" | "until" if depth == 0 => return position,
            _ if depth == 0
                && position > start
                && token.range.start.line
                    > file.tokens[file.significant[start.saturating_sub(1)]]
                        .range
                        .start
                        .line
                && !matches!(
                    file.tokens[file.significant[position - 1]].text.as_str(),
                    "," | "." | ":"
                ) =>
            {
                return position;
            }
            _ => {}
        }
    }
    limit
}

fn matching_paren_position(file: &ParsedFile, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for position in open..file.significant.len() {
        match file.tokens[file.significant[position]].text.as_str() {
            "(" => depth += 1,
            ")" => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(position);
                }
            }
            _ => {}
        }
    }
    None
}

fn matching_control_end(tokens: &[&LexToken], if_index: usize) -> Option<usize> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Block {
        Function,
        If,
        For,
        While,
        Do,
        Repeat,
    }
    let mut stack = vec![Block::If];
    for (index, token) in tokens.iter().enumerate().skip(if_index + 1) {
        match token.text.as_str() {
            "function" => stack.push(Block::Function),
            "if" => stack.push(Block::If),
            "for" => stack.push(Block::For),
            "while" => stack.push(Block::While),
            "repeat" => stack.push(Block::Repeat),
            "do" => {
                if !matches!(stack.last(), Some(Block::For | Block::While)) {
                    stack.push(Block::Do);
                }
            }
            "end" => {
                stack.pop();
                if stack.is_empty() {
                    return Some(index);
                }
            }
            "until" => {
                if stack.last() == Some(&Block::Repeat) {
                    stack.pop();
                    if stack.is_empty() {
                        return Some(index);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn is_protected_field(token: &LexToken, fields: &[String]) -> bool {
    token.kind == LexKind::Identifier && fields.iter().any(|field| field == &token.text)
}
fn is_assignment_operator(token: &LexToken) -> bool {
    matches!(
        token.text.as_str(),
        "=" | "+=" | "-=" | "*=" | "/=" | "//=" | "%=" | "^=" | "..="
    )
}

fn looks_like_signal_receiver(file: &ParsedFile, sig: &[&LexToken], dot_index: usize) -> bool {
    let receiver = sig
        .get(dot_index.saturating_sub(1))
        .map(|token| token.text.as_str())
        .unwrap_or_default();
    if let Some(receiver_token) = sig.get(dot_index.saturating_sub(1)) {
        // A local binding with a generic signal-looking name is not enough to
        // prove Roblox's signal type; only unshadowed API symbols or a known
        // signal-producing method chain are safe-fix candidates.
        if file
            .semantic
            .is_shadowed_at(receiver, receiver_token.range.start.byte)
        {
            return false;
        }
    }
    matches!(
        receiver,
        "Event"
            | "Touched"
            | "Heartbeat"
            | "RenderStepped"
            | "Stepped"
            | "OnServerEvent"
            | "OnClientEvent"
            | "AncestryChanged"
            | "Changed"
            | "ChildAdded"
            | "ChildRemoved"
            | "DescendantAdded"
            | "DescendantRemoving"
            | "MouseButton1Click"
            | "MouseButton1Down"
            | "MouseButton1Up"
            | "RBXScriptSignal"
    ) || sig[..dot_index.min(sig.len())]
        .iter()
        .rev()
        .take(8)
        .any(|token| {
            matches!(
                token.text.as_str(),
                "GetPropertyChangedSignal" | "GetInstanceAddedSignal" | "GetInstanceRemovedSignal"
            )
        })
}

fn looks_like_connection_receiver(file: &ParsedFile, sig: &[&LexToken], dot_index: usize) -> bool {
    let receiver = sig
        .get(dot_index.saturating_sub(1))
        .map(|token| token.text.as_str())
        .unwrap_or_default();
    if let Some(receiver_token) = sig.get(dot_index.saturating_sub(1)) {
        // A generic local named `conn` is not proof of a Roblox connection;
        // declining here avoids an unsafe capitalization fix on user types.
        if file
            .semantic
            .is_shadowed_at(receiver, receiver_token.range.start.byte)
        {
            return false;
        }
    }
    receiver == "RBXScriptConnection"
        || receiver == "connection"
        || receiver == "conn"
        || receiver == "Connect"
}

fn shadowed_global(file: &ParsedFile, name: &str, byte: usize) -> bool {
    file.semantic.is_shadowed_at(name, byte)
}

fn is_datastore_call(file: &ParsedFile, call: &rbx_heal_core::semantic::SemanticCallFact) -> bool {
    if matches!(call.name.as_str(), "GetDataStore" | "GetOrderedDataStore") {
        // GetDataStore is a Roblox method, not a free-standing helper. A
        // shadowed/global function with the same spelling is deliberately not
        // treated as persistence access.
        return call
            .receiver_token
            .is_some_and(|receiver| datastore_service_receiver(file, call, receiver));
    }
    let Some(receiver) = call.receiver_token else {
        return false;
    };
    if file.tokens.get(receiver).is_none() {
        return false;
    }
    // A chained expression such as
    // `game:GetService("DataStoreService"):GetDataStore("Players"):GetAsync`
    // has a closing parenthesis as the receiver token. Resolve that call
    // structurally instead of requiring an intermediate local assignment.
    if let Some(source) = call_ending_at(file, receiver) {
        if matches!(source.name.as_str(), "GetDataStore" | "GetOrderedDataStore")
            && source.function == call.function
            && is_datastore_call(file, source)
        {
            return true;
        }
    }
    let call_function = call.function;
    // Prove a local receiver was initialized from GetDataStore in the same
    // lexical function. Dynamic require/metatable flows intentionally decline.
    file.semantic.calls.iter().any(|source| {
        matches!(source.name.as_str(), "GetDataStore" | "GetOrderedDataStore")
            && source.receiver_token.is_some()
            && datastore_service_receiver(
                file,
                source,
                source.receiver_token.expect("checked above"),
            )
            && (source.function == call_function || source.function.is_none())
            && source.token_index < call.token_index
            && file.semantic.assignments.iter().any(|assignment| {
                (assignment.function == call_function || assignment.function.is_none())
                    && assignment.target.is_some_and(|target| {
                        file.semantic
                            .binding_for_token(receiver)
                            .is_some_and(|receiver_binding| target == receiver_binding)
                    })
                    && assignment_contains_call(file, assignment, source)
            })
    })
}

fn datastore_service_receiver(
    file: &ParsedFile,
    call: &rbx_heal_core::semantic::SemanticCallFact,
    receiver: usize,
) -> bool {
    let Some(token) = file.tokens.get(receiver) else {
        return false;
    };
    let name = token.text.to_ascii_lowercase();
    let Some(receiver_binding) = file.semantic.binding_for_token(receiver) else {
        // A chained GetService expression has a closing parenthesis as its
        // receiver token. It is safe only when that chain visibly requests
        // DataStoreService.
        if token.text == ")" {
            return call_ending_at(file, receiver).is_some_and(|source| {
                source.name == "GetService"
                    && source.function == call.function
                    && get_service_is_datastore(file, source)
            });
        }
        // Unbound conventional globals are accepted as a small compatibility
        // escape hatch (`DSS:GetDataStore(...)`). A resolved local with one of
        // these names must still be proven to come from GetService below.
        return name.contains("datastoreservice") || name == "dss";
    };

    // A local service binding is accepted only when its defining assignment
    // is itself a literal GetService("DataStoreService") call. Arbitrary
    // locals with a store-like name remain unknown and are declined.
    let result = file.semantic.assignments.iter().any(|assignment| {
        assignment.target == Some(receiver_binding)
            && file.semantic.calls.iter().any(|source| {
                source.name == "GetService"
                    && source.token_index > assignment.operator_token
                    && source.token_index < call.token_index
                    && assignment_contains_call(file, assignment, source)
                    && get_service_is_datastore(file, source)
            })
    });
    result
}

/// Prove that a call belongs to the right-hand side of one particular
/// assignment.  Merely seeing a `GetDataStore` somewhere earlier in a
/// function is not enough: an unrelated assignment must not turn an unknown
/// local into a trusted persistence handle.
fn assignment_contains_call(
    file: &ParsedFile,
    assignment: &rbx_heal_core::semantic::SemanticAssignmentFact,
    call: &rbx_heal_core::semantic::SemanticCallFact,
) -> bool {
    if assignment.function != call.function || assignment.operator_token >= call.token_index {
        return false;
    }
    let Some(operator_position) = file
        .semantic
        .significant_position(assignment.operator_token)
    else {
        return false;
    };
    let Some(call_position) = file.semantic.significant_position(call.token_index) else {
        return false;
    };
    let limit = file
        .semantic
        .function(call.function.unwrap_or(FunctionId(usize::MAX)))
        .map(|function| function.body_tokens.end)
        .unwrap_or(file.significant.len());
    assignment_rhs_segments(
        file,
        operator_position + 1,
        limit.min(file.significant.len()),
    )
    .get(assignment.target_ordinal)
    .is_some_and(|segment| segment.start <= call_position && call_position < segment.end)
}

fn assignment_rhs_segments(
    file: &ParsedFile,
    start: usize,
    function_end: usize,
) -> Vec<std::ops::Range<usize>> {
    let end = statement_end_for_assignment(file, start, function_end);
    if start >= end {
        return Vec::new();
    }
    let mut segments = Vec::new();
    let mut segment_start = start;
    let mut nesting = 0usize;
    for position in start..end {
        match file.tokens[file.significant[position]].text.as_str() {
            "(" | "{" | "[" => nesting += 1,
            ")" | "}" | "]" => nesting = nesting.saturating_sub(1),
            "," if nesting == 0 => {
                segments.push(segment_start..position);
                segment_start = position + 1;
            }
            _ => {}
        }
    }
    segments.push(segment_start..end);
    segments
}

fn statement_end_for_assignment(file: &ParsedFile, start: usize, function_end: usize) -> usize {
    let mut depth = 0usize;
    let mut position = start;
    while position < function_end {
        let token = &file.tokens[file.significant[position]];
        match token.text.as_str() {
            "(" | "{" | "[" => depth += 1,
            ")" | "}" | "]" => depth = depth.saturating_sub(1),
            ";" | "end" | "else" | "elseif" | "until" if depth == 0 => return position,
            _ if depth == 0
                && position > start
                && token.range.start.line
                    > file.tokens[file.significant[position - 1]].range.end.line
                && !assignment_continues_after(
                    &file.tokens[file.significant[position - 1]].text,
                )
                && !assignment_continues_before(&token.text) =>
            {
                return position;
            }
            _ => {}
        }
        position += 1;
    }
    function_end
}

fn assignment_continues_after(token: &str) -> bool {
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

fn assignment_continues_before(token: &str) -> bool {
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

fn get_service_is_datastore(
    file: &ParsedFile,
    call: &rbx_heal_core::semantic::SemanticCallFact,
) -> bool {
    let Some(open) = file.semantic.significant_position(call.open_paren_index) else {
        return false;
    };
    let Some(close) = matching_paren_position(file, open) else {
        return false;
    };
    (open + 1..close).any(|position| {
        file.significant
            .get(position)
            .and_then(|token| file.tokens.get(*token))
            .is_some_and(|token| {
                token.kind == LexKind::String
                    && token.text.to_ascii_lowercase().contains("datastoreservice")
            })
    })
}

fn datastore_call_has_boundary(
    file: &ParsedFile,
    call: &rbx_heal_core::semantic::SemanticCallFact,
    protectors: &[String],
) -> bool {
    let Some(call_position) = file.semantic.significant_position(call.token_index) else {
        return false;
    };
    file.semantic.calls.iter().any(|protector| {
        if !protectors.iter().any(|name| name == &protector.name) {
            return false;
        }
        if matches!(protector.name.as_str(), "pcall" | "xpcall")
            && file.semantic.is_shadowed_at(
                &protector.name,
                file.tokens[protector.token_index].range.start.byte,
            )
        {
            // A local function named `pcall`/`xpcall` is not the Roblox/Luau
            // error boundary.  Treating it as one would turn an unprotected
            // DataStore access into a false negative.
            return false;
        }
        let Some(open_position) = file
            .semantic
            .significant_position(protector.open_paren_index)
        else {
            return false;
        };
        let Some(close_position) = matching_paren_position(file, open_position) else {
            return false;
        };
        call_position > open_position
            && call_position < close_position
            && functions_are_nested_or_same(file, protector.function, call.function)
    })
}

fn call_ending_at(
    file: &ParsedFile,
    receiver_token: usize,
) -> Option<&rbx_heal_core::semantic::SemanticCallFact> {
    let close_position = file.semantic.significant_position(receiver_token)?;
    file.semantic.calls.iter().find(|candidate| {
        file.semantic
            .significant_position(candidate.open_paren_index)
            .and_then(|open| matching_paren_position(file, open))
            == Some(close_position)
    })
}

fn functions_are_nested_or_same(
    file: &ParsedFile,
    outer: Option<FunctionId>,
    inner: Option<FunctionId>,
) -> bool {
    match (outer, inner) {
        (None, _) => true,
        (Some(outer), Some(inner)) if outer == inner => true,
        (Some(outer), Some(inner)) => {
            let Some(outer) = file.semantic.function(outer) else {
                return false;
            };
            let Some(inner) = file.semantic.function(inner) else {
                return false;
            };
            outer.range.start.byte <= inner.range.start.byte
                && outer.range.end.byte >= inner.range.end.byte
        }
        (Some(_), None) => false,
    }
}

fn matches_any(path: &str, patterns: &[String]) -> bool {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        if let Ok(glob) = Glob::new(pattern) {
            builder.add(glob);
        }
    }
    builder.build().is_ok_and(|set| set.is_match(path))
}

fn finding(
    file: &ParsedFile,
    rule: &dyn Rule,
    token: &LexToken,
    message: impl Into<String>,
) -> Finding {
    Finding::new(
        rule.id(),
        rule.category(),
        rule.default_severity(),
        rule.default_confidence(),
        file.relative_path.clone(),
        token.range,
        message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbx_heal_core::parser::parse_source_with_path;
    use rbx_heal_core::Config;
    use std::path::PathBuf;

    fn scan_fixture(source: &str) -> Vec<Finding> {
        scan_fixture_at(source, "src/server/fixture.server.luau")
    }

    fn scan_fixture_at(source: &str, relative_path: &str) -> Vec<Finding> {
        let file = parse_source_with_path(
            PathBuf::from("fixture.luau"),
            relative_path.into(),
            source.into(),
        )
        .unwrap();
        let config = Config::default();
        let mut findings = Vec::new();
        let scope = config.scope_for_path(relative_path);
        for rule in built_in_rules() {
            if !rule.metadata().applicable_scopes.is_empty()
                && !rule.metadata().applicable_scopes.contains(&scope)
            {
                continue;
            }
            let before = findings.len();
            rule.analyze(
                &rbx_heal_core::RuleContext {
                    file: &file,
                    config: &config,
                },
                &mut findings,
            );
            for finding in findings[before..].iter_mut() {
                if finding.fixability == Fixability::Safe {
                    if let Some(edits) = rule.safe_fix(
                        &rbx_heal_core::RuleContext {
                            file: &file,
                            config: &config,
                        },
                        finding,
                    ) {
                        finding.edit = (edits.len() == 1).then(|| edits[0].clone());
                        finding.edits = edits;
                    }
                }
            }
        }
        findings
    }

    #[test]
    fn detects_remote_sensitive_write() {
        let findings = scan_fixture("local R = {}\nR.OnServerEvent:Connect(function(player, amount)\n data.cash += amount\nend)\n");
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-SEC-001"));
    }

    #[test]
    fn does_not_flag_traversal_outside_frame_callback() {
        let findings = scan_fixture("local refs = workspace:GetDescendants()\nRunService.RenderStepped:Connect(function()\n print(#refs)\nend)\n");
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-PERF-001"));
    }

    #[test]
    fn does_not_treat_lifecycle_callbacks_as_frame_callbacks() {
        let findings = scan_fixture(
            "Players.PlayerAdded:Connect(function(player)\n local refs = player:GetDescendants()\nend)\n",
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-PERF-001"));
    }

    #[test]
    fn creates_safe_service_edit() {
        let findings = scan_fixture("local Players = game:service(\"Players\")\n");
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "RBX-API-002")
            .unwrap();
        assert_eq!(finding.fixability, Fixability::Safe);
        assert_eq!(finding.edit.as_ref().unwrap().replacement, "GetService");
    }

    #[test]
    fn declines_shadowed_or_dynamic_aliases() {
        let findings = scan_fixture(
            "local game = {}\ngame:service(name)\nlocal other = {}\nother:connect(function() end)\nlocal customSignal = {}\ncustomSignal:connect(function() end)\nlocal function shadowed(game)\n return game:service(\"Players\")\nend\n",
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-API-002" || finding.rule_id == "RBX-API-001"));
    }

    #[test]
    fn follows_simple_remote_aliases_but_not_shadowed_scheduler() {
        let findings = scan_fixture(
            "local R = {}\nR.OnServerEvent:Connect(function(player, amount)\n local value = amount\n data.cash = value\nend)\nlocal wait = function() end\nwait()\n",
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-SEC-001"));
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-TASK-001"));
    }

    #[test]
    fn analyzes_legacy_lowercase_remote_handlers_before_fixing_them() {
        let findings = scan_fixture(
            "local R = {}\nR.OnServerEvent:connect(function(player, amount)\n data.cash += amount\nend)\n",
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-SEC-001"));
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-NET-001"));
    }

    #[test]
    fn finds_named_server_event_and_invoke_handlers() {
        let findings = scan_fixture(
            "local R = {}\nlocal function onEvent(player, amount)\n data.cash = amount\nend\nR.OnServerEvent:Connect(onEvent)\nlocal function onInvoke(player, amount)\n data.cash = amount\nend\nR.OnServerInvoke = onInvoke\n",
        );
        assert!(
            findings
                .iter()
                .filter(|finding| finding.rule_id == "RBX-SEC-001")
                .count()
                >= 2
        );
        assert!(
            findings
                .iter()
                .filter(|finding| finding.rule_id == "RBX-NET-001")
                .count()
                >= 2
        );
    }

    #[test]
    fn finds_inline_server_invoke_handler() {
        let findings = scan_fixture(
            "local Remote = {}\nRemote.OnServerInvoke = function(player, amount)\n data.cash = amount\nend\n",
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-SEC-001"));
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-NET-001"));
    }

    #[test]
    fn declines_global_handler_when_a_local_value_shadows_its_name() {
        let findings = scan_fixture(
            "function handler(player, amount)\n data.cash = amount\nend\nlocal handler = function() end\nlocal Remote = {}\nRemote.OnServerEvent:Connect(handler)\n",
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-SEC-001"));
    }

    #[test]
    fn declines_forward_named_handler_reference() {
        let findings = scan_fixture(
            "local Remote = {}\nRemote.OnServerEvent:Connect(handler)\nfunction handler(player, amount)\n data.cash = amount\nend\n",
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-SEC-001" || finding.rule_id == "RBX-NET-001"));
    }

    #[test]
    fn protects_datastore_calls_inside_configured_error_boundary() {
        let unprotected = scan_fixture(
            "local service = game:GetService(\"DataStoreService\")\nlocal store = service:GetDataStore(\"Players\")\nlocal data = store:GetAsync(\"key\")\n",
        );
        assert!(unprotected
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-003"));
        let protected = scan_fixture(
            "local service = game:GetService(\"DataStoreService\")\nlocal store = service:GetDataStore(\"Players\")\nlocal ok, data = pcall(function()\n return store:GetAsync(\"key\")\nend)\n",
        );
        assert!(!protected
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-003"));
    }

    #[test]
    fn recognizes_direct_datastore_service_call_chains() {
        let findings = scan_fixture(
            "local data = game:GetService(\"DataStoreService\"):GetDataStore(\"Players\"):GetAsync(\"key\")\n",
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-001"));
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-003"));
    }

    #[test]
    fn recognizes_ordered_datastore_aliases() {
        let findings = scan_fixture(
            "local service = game:GetService(\"DataStoreService\")\nlocal store = service:GetOrderedDataStore(\"Leaderboard\")\nlocal value = store:GetAsync(\"key\")\n",
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-001"));
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-003"));
    }

    #[test]
    fn recognizes_protection_when_pcall_wraps_nested_function() {
        let findings = scan_fixture(
            "local service = game:GetService(\"DataStoreService\")\nlocal store = service:GetDataStore(\"Players\")\nlocal function load()\n return pcall(function() return store:GetAsync(\"key\") end)\nend\n",
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-003"));
    }

    #[test]
    fn handles_typed_luau_parameters_and_aliases() {
        let findings = scan_fixture(
            "local R = {}\nR.OnServerEvent:Connect(function(player: Player, amount: number)\n local value: number = amount\n data.cash = value\nend)\n",
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-SEC-001"));
    }

    #[test]
    fn clean_overwrite_clears_remote_taint() {
        let findings = scan_fixture(
            "local R = {}\nR.OnServerEvent:Connect(function(player, amount)\n local value = amount\n value = 10\n data.cash = value\nend)\n",
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-SEC-001"));
    }

    #[test]
    fn joins_remote_taint_across_branches() {
        let findings = scan_fixture(
            "local R = {}\nR.OnServerEvent:Connect(function(player, amount)\n local value = 0\n if player then\n  value = amount\n else\n  value = 10\n end\n data.cash = value\nend)\n",
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-SEC-001"));
    }

    #[test]
    fn declines_remote_value_used_only_inside_nested_function() {
        let findings = scan_fixture(
            "local R = {}\nR.OnServerEvent:Connect(function(player, amount)\n local callback = function() return amount end\n data.cash = callback\nend)\n",
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-SEC-001"));
    }

    #[test]
    fn declines_unproven_get_async_receiver() {
        let findings = scan_fixture("local cache = {}\nlocal value = cache:GetAsync(key)\n");
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-001"));
    }

    #[test]
    fn declines_shadowed_datastore_service_receiver() {
        let findings = scan_fixture(
            "local fake = {}\nlocal store = fake:GetDataStore(\"Players\")\nreturn store:GetAsync(\"key\")\n",
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-001"));
    }

    #[test]
    fn proves_top_level_datastore_alias_before_get_async() {
        let findings = scan_fixture(
            "local service = game:GetService(\"DataStoreService\")\nlocal store = service:GetDataStore(\"Players\")\nreturn store:GetAsync(\"key\")\n",
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-001"));
    }

    #[test]
    fn maps_datastore_multi_assignment_to_the_matching_rhs_only() {
        let findings = scan_fixture(
            "local service = game:GetService(\"DataStoreService\")\nlocal store, other = service:GetDataStore(\"Players\"), {}\nlocal value = other:GetAsync(\"key\")\n",
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-003"));

        let findings = scan_fixture(
            "local service = game:GetService(\"DataStoreService\")\nlocal other, store = {}, service:GetDataStore(\"Players\")\nlocal value = store:GetAsync(\"key\")\n",
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-001"));
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-003"));
    }

    #[test]
    fn does_not_treat_shadowed_pcall_as_a_datastore_boundary() {
        let findings = scan_fixture(
            "local service = game:GetService(\"DataStoreService\")\nlocal store = service:GetDataStore(\"Players\")\nlocal pcall = function(callback) return callback() end\nlocal ok, value = pcall(function() return store:GetAsync(\"key\") end)\n",
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-003"));
    }

    #[test]
    fn declines_unrelated_datastore_assignment_before_source_call() {
        let findings = scan_fixture_at(
            "local store = 1\nlocal real = game:GetService(\"DataStoreService\"):GetDataStore(\"Players\")\nreturn store:GetAsync(\"key\")\n",
            "src/server/DataService.server.luau",
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-001"));
    }

    #[test]
    fn declines_unrelated_pcall_default_branch() {
        let findings = scan_fixture(
            "local store = game:GetService(\"DataStoreService\"):GetDataStore(\"Players\")\nlocal function load()\n local ok = pcall(function() return true end)\n if not ok then return {} end\n return store:GetAsync(\"key\")\nend\n",
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-002"));
    }

    #[test]
    fn declines_lowercase_connect_on_shadowed_event_name() {
        let findings = scan_fixture("local Event = {}\nEvent:connect(function() end)\n");
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-API-001"));
    }

    #[test]
    fn server_only_rules_do_not_run_in_client_scope() {
        let findings = scan_fixture_at(
            "local store = {}\nstore:GetAsync(key)\n",
            "src/client/cache.client.luau",
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "RBX-DATA-001"));
    }
}
