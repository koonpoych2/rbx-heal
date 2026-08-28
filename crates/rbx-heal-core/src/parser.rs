use crate::{
    model::{Position, Range},
    path::{validate_existing_file, validate_relative_input, PathError},
    semantic::{collect_ast_semantic_facts, FunctionKind, SemanticIndex},
};
use full_moon::{
    ast::LuaVersion,
    parse_fallible,
    tokenizer::{Lexer, LexerResult, TokenType},
};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::{Condvar, Mutex, OnceLock},
};
use thiserror::Error;

type AstSemanticFacts = (
    Vec<(Range, Range, FunctionKind)>,
    Vec<crate::semantic::AstControlFact>,
);

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("could not read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Luau parse failed: {0}")]
    Syntax(String),
    #[error("Luau tokenization failed: {0}")]
    Tokens(String),
    #[error("invalid source path: {0}")]
    Path(#[from] PathError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LexKind {
    Identifier,
    String,
    Number,
    Symbol,
    Comment,
    Whitespace,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LexToken {
    pub kind: LexKind,
    pub text: String,
    pub range: Range,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallFact {
    pub callee: String,
    pub token_index: usize,
    pub open_paren_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignmentFact {
    pub target: String,
    pub target_index: usize,
    pub operator_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackFact {
    pub signal: String,
    pub signal_index: usize,
    pub function_index: usize,
}

/// Per-file indexes built once after parsing so rules can reuse lexical facts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexedFacts {
    pub calls: Vec<CallFact>,
    pub assignments: Vec<AssignmentFact>,
    pub callbacks: Vec<CallbackFact>,
    pub api_symbols: BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub struct ParsedFile {
    pub path: PathBuf,
    pub relative_path: String,
    pub source: String,
    pub tokens: Vec<LexToken>,
    pub significant: Vec<usize>,
    pub facts: IndexedFacts,
    /// AST-derived scope, binding, callback and data-flow facts.
    pub semantic: SemanticIndex,
    pub has_strict_directive: bool,
}

impl ParsedFile {
    pub fn token(&self, index: usize) -> Option<&LexToken> {
        self.tokens.get(index)
    }

    pub fn significant_token(&self, index: usize) -> Option<&LexToken> {
        self.significant
            .get(index)
            .and_then(|i| self.tokens.get(*i))
    }

    pub fn source_slice(&self, range: Range) -> &str {
        &self.source[range.start.byte..range.end.byte]
    }

    pub fn line_text(&self, line: usize) -> Option<&str> {
        self.source.lines().nth(line.saturating_sub(1))
    }
}

pub fn parse_path(path: &Path, project_root: &Path) -> Result<ParsedFile, ParseError> {
    let validated = validate_existing_file(project_root, path)?;
    let source = fs::read_to_string(validated.absolute()).map_err(|source| ParseError::Read {
        path: validated.absolute().to_path_buf(),
        source,
    })?;
    parse_source_with_path(
        validated.absolute().to_path_buf(),
        validated.relative().to_owned(),
        source,
    )
}

pub fn parse_source(source: &str) -> Result<(), ParseError> {
    parse_ast_semantic_facts(source).map(|_| ())
}

fn parse_ast_semantic_facts(source: &str) -> Result<AstSemanticFacts, ParseError> {
    let _permit = parser_pool().acquire();
    let owned = source.to_owned();
    let handle = std::thread::Builder::new()
        .name("rbx-heal-parser".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let result = parse_fallible(&owned, LuaVersion::luau());
            if result.errors().is_empty() {
                Ok(collect_ast_semantic_facts(&result.into_ast()))
            } else {
                Err(result
                    .errors()
                    .iter()
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>()
                    .join("; "))
            }
        })
        .map_err(|error| ParseError::Syntax(format!("could not start parser worker: {error}")))?;
    match handle.join() {
        Ok(Ok(facts)) => Ok(facts),
        Ok(Err(message)) => Err(ParseError::Syntax(message)),
        Err(_) => Err(ParseError::Syntax(
            "Luau parser worker panicked (possibly due to malformed input)".into(),
        )),
    }
}

/// Parsing Luau can require a large stack for deeply nested expressions.  A
/// small process-wide permit pool keeps parallel discovery from allocating one
/// 16 MiB worker per file while preserving the existing stack size.
struct ParserPool {
    available: Mutex<usize>,
    wake: Condvar,
}

struct ParserPermit<'a> {
    pool: &'a ParserPool,
}

impl ParserPool {
    fn acquire(&self) -> ParserPermit<'_> {
        let mut available = self.available.lock().expect("parser pool poisoned");
        while *available == 0 {
            available = self.wake.wait(available).expect("parser pool poisoned");
        }
        *available -= 1;
        ParserPermit { pool: self }
    }
}

impl Drop for ParserPermit<'_> {
    fn drop(&mut self) {
        let mut available = self.pool.available.lock().expect("parser pool poisoned");
        *available += 1;
        self.pool.wake.notify_one();
    }
}

fn parser_pool() -> &'static ParserPool {
    static POOL: OnceLock<ParserPool> = OnceLock::new();
    POOL.get_or_init(|| {
        let capacity = std::thread::available_parallelism()
            .map(|parallelism| parallelism.get().clamp(1, 8))
            .unwrap_or(4);
        ParserPool {
            available: Mutex::new(capacity),
            wake: Condvar::new(),
        }
    })
}

pub fn parse_source_with_path(
    path: PathBuf,
    relative_path: String,
    source: String,
) -> Result<ParsedFile, ParseError> {
    validate_relative_input(Path::new(&relative_path))?;
    let (ast_functions, ast_controls) = parse_ast_semantic_facts(&source)?;

    let lexer = Lexer::new(&source, LuaVersion::luau());
    let raw_tokens = match lexer.collect() {
        LexerResult::Ok(tokens) => tokens,
        LexerResult::Recovered(_, errors) | LexerResult::Fatal(errors) => {
            return Err(ParseError::Tokens(
                errors
                    .into_iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; "),
            ))
        }
    };

    let tokens = raw_tokens
        .into_iter()
        .map(|token| {
            let token_type = token.token_type();
            let kind = match token_type {
                TokenType::Identifier { .. } => LexKind::Identifier,
                TokenType::StringLiteral { .. } => LexKind::String,
                TokenType::Number { .. } => LexKind::Number,
                TokenType::Symbol { .. } => LexKind::Symbol,
                TokenType::SingleLineComment { .. } | TokenType::MultiLineComment { .. } => {
                    LexKind::Comment
                }
                TokenType::Whitespace { .. } => LexKind::Whitespace,
                _ => LexKind::Other,
            };
            let start = token.start_position();
            let end = token.end_position();
            LexToken {
                kind,
                text: token.to_string(),
                range: Range {
                    start: Position {
                        line: start.line(),
                        column: start.character(),
                        byte: start.bytes(),
                    },
                    end: Position {
                        line: end.line(),
                        column: end.character(),
                        byte: end.bytes(),
                    },
                },
            }
        })
        .collect::<Vec<_>>();

    let significant = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| {
            (!token.text.is_empty()
                && !matches!(token.kind, LexKind::Whitespace | LexKind::Comment))
            .then_some(index)
        })
        .collect::<Vec<_>>();
    let facts = build_facts(&tokens, &significant);
    let semantic =
        SemanticIndex::build_with_controls(&ast_functions, &ast_controls, &tokens, &significant);
    let has_strict_directive = source.lines().take(4).any(|line| {
        let trimmed = line.trim_start_matches('\u{feff}').trim();
        trimmed == "--!strict" || trimmed.starts_with("--!strict ")
    });

    Ok(ParsedFile {
        path,
        relative_path,
        source,
        tokens,
        significant,
        facts,
        semantic,
        has_strict_directive,
    })
}

fn build_facts(tokens: &[LexToken], significant: &[usize]) -> IndexedFacts {
    let mut facts = IndexedFacts::default();
    for (position, token_index) in significant.iter().copied().enumerate() {
        let token = &tokens[token_index];
        if token.kind == LexKind::Identifier {
            facts.api_symbols.insert(token.text.clone());
        }
        if token.kind == LexKind::Identifier
            && significant
                .get(position + 1)
                .is_some_and(|next| tokens[*next].text == "(")
        {
            facts.calls.push(CallFact {
                callee: token.text.clone(),
                token_index,
                open_paren_index: significant[position + 1],
            });
        }
        if is_assignment_token(token)
            && position > 0
            && tokens[significant[position - 1]].kind == LexKind::Identifier
        {
            facts.assignments.push(AssignmentFact {
                target: tokens[significant[position - 1]].text.clone(),
                target_index: significant[position - 1],
                operator_index: token_index,
            });
        }
        let callback_function = (position + 1..significant.len().min(position + 6))
            .find(|candidate| {
                matches!(
                    tokens[significant[*candidate]].text.as_str(),
                    "Connect" | "connect"
                )
            })
            .and_then(|connect| {
                (connect + 1..significant.len().min(connect + 4))
                    .find(|candidate| tokens[significant[*candidate]].text == "function")
            });
        if let Some(function_position) = callback_function {
            facts.callbacks.push(CallbackFact {
                signal: token.text.clone(),
                signal_index: token_index,
                function_index: significant[function_position],
            });
        }
    }
    facts
}

fn is_assignment_token(token: &LexToken) -> bool {
    matches!(
        token.text.as_str(),
        "=" | "+=" | "-=" | "*=" | "/=" | "//=" | "%=" | "^=" | "..="
    )
}

pub fn token_is_identifier(token: &LexToken, name: &str) -> bool {
    token.kind == LexKind::Identifier && token.text == name
}

pub fn token_is_symbol(token: &LexToken, symbol: &str) -> bool {
    token.kind == LexKind::Symbol && token.text == symbol
}

pub fn is_comment(token: &LexToken) -> bool {
    token.kind == LexKind::Comment
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic;
    use std::path::PathBuf;

    #[test]
    fn parses_nested_anonymous_function_on_large_stack() {
        let source = "function load(player)\n local ok = pcall(function()\n  return player.Name\n end)\nend\n";
        let file = parse_source_with_path(
            PathBuf::from("load.luau"),
            "load.luau".into(),
            source.into(),
        )
        .unwrap();
        assert!(file.tokens.iter().any(|token| token.text == "pcall"));
        assert!(file.facts.calls.iter().any(|call| call.callee == "pcall"));
    }

    #[test]
    fn records_exact_byte_ranges_and_strict_directive() {
        let source = "--!strict\nlocal value = 1\n";
        let file = parse_source_with_path(
            PathBuf::from("strict.luau"),
            "strict.luau".into(),
            source.into(),
        )
        .unwrap();
        assert!(file.has_strict_directive);
        let value = file
            .tokens
            .iter()
            .find(|token| token.text == "value")
            .unwrap();
        assert_eq!(
            &source[value.range.start.byte..value.range.end.byte],
            "value"
        );
        assert!(file
            .facts
            .assignments
            .iter()
            .any(|assignment| assignment.target == "value"));
    }

    #[test]
    fn rejects_absolute_relative_source_paths() {
        let error = parse_source_with_path(
            PathBuf::from("fixture.luau"),
            if cfg!(windows) {
                "C:/outside/fixture.luau".into()
            } else {
                "/outside/fixture.luau".into()
            },
            "return 1\n".into(),
        )
        .unwrap_err();
        assert!(matches!(error, ParseError::Path(_)));
    }

    #[test]
    fn builds_ast_callbacks_and_scope_aware_bindings() {
        let source = "local Remote = {}\nRemote.OnServerEvent:Connect(function(player: Player, amount: number)\n  local game = {}\n  local value: number = amount\n  game:service(\"Players\")\n  data.cash = value\nend)\ngame:service(\"Players\")\n";
        let file = parse_source_with_path(
            PathBuf::from("semantic.luau"),
            "src/server/semantic.server.luau".into(),
            source.into(),
        )
        .unwrap();
        assert_eq!(file.semantic.functions.len(), 1);
        let function = &file.semantic.functions[0];
        assert_eq!(function.callback_signal.as_deref(), Some("OnServerEvent"));
        assert_eq!(function.parameters.len(), 2);
        let game_tokens = file
            .tokens
            .iter()
            .filter(|token| token.text == "game")
            .collect::<Vec<_>>();
        assert_eq!(game_tokens.len(), 3);
        assert!(file
            .semantic
            .is_shadowed_at("game", game_tokens[1].range.start.byte));
        assert!(!file
            .semantic
            .is_shadowed_at("game", game_tokens[2].range.start.byte));
        let value = file
            .semantic
            .bindings
            .iter()
            .find(|binding| binding.name == "value")
            .expect("typed local binding");
        let source_binding = function.parameters[1];
        let tainted = file.semantic.tainted_bindings(
            function.id,
            &[source_binding],
            &file.tokens,
            &file.significant,
        );
        assert!(tainted.contains(&source_binding));
        assert!(tainted.contains(&value.id));
    }

    #[test]
    fn associates_named_remote_endpoints_and_server_invoke_assignments() {
        let source = "local Remote = {}\nlocal function onEvent(player, amount)\n return amount\nend\nRemote.OnServerEvent:Connect(onEvent)\nlocal function onInvoke(player, amount)\n return amount\nend\nRemote.OnServerInvoke = onInvoke\n";
        let file = parse_source_with_path(
            PathBuf::from("endpoints.luau"),
            "src/server/endpoints.server.luau".into(),
            source.into(),
        )
        .unwrap();
        assert_eq!(file.semantic.remote_endpoints.len(), 2);
        assert!(file
            .semantic
            .remote_endpoints
            .iter()
            .any(|endpoint| endpoint.signal_name == "OnServerEvent"));
        assert!(file
            .semantic
            .remote_endpoints
            .iter()
            .any(|endpoint| endpoint.signal_name == "OnServerInvoke"));
    }

    #[test]
    fn does_not_associate_bare_on_server_invoke_identifier() {
        let source =
            "local function handler(player)\n return player\nend\nOnServerInvoke = handler\n";
        let file = parse_source_with_path(
            PathBuf::from("bare-invoke.luau"),
            "src/server/bare-invoke.server.luau".into(),
            source.into(),
        )
        .unwrap();
        assert!(file.semantic.remote_endpoints.is_empty());
    }

    #[test]
    fn does_not_associate_bare_on_server_event_identifier() {
        let source =
            "local function handler(player)\n return player\nend\nOnServerEvent:Connect(handler)\n";
        let file = parse_source_with_path(
            PathBuf::from("bare-event.luau"),
            "src/server/bare-event.server.luau".into(),
            source.into(),
        )
        .unwrap();
        assert!(file.semantic.remote_endpoints.is_empty());
    }

    #[test]
    fn cfg_fixed_point_preserves_remote_taint_across_branches_and_loops() {
        let source = r#"Remote.OnServerEvent:Connect(function(player, amount)
    local alias = 0
    if player then
        alias = amount
    else
        alias = 1
    end
    while player do
        local nested = alias
        alias = nested
        break
    end
    data.Money = alias
end)
"#;
        let file = parse_source_with_path(
            PathBuf::from("cfg.luau"),
            "src/server/cfg.server.luau".into(),
            source.into(),
        )
        .unwrap();
        let function = &file.semantic.functions[0];
        let source_binding = function.parameters[1];
        let alias = file
            .semantic
            .bindings
            .iter()
            .find(|binding| binding.name == "alias")
            .map(|binding| binding.id)
            .unwrap();
        assert!(file
            .semantic
            .ast_controls
            .iter()
            .any(|control| matches!(control.kind, semantic::AstControlKind::If)));
        assert!(file
            .semantic
            .ast_controls
            .iter()
            .any(|control| matches!(control.kind, semantic::AstControlKind::Loop)));
        assert!(file
            .semantic
            .tainted_bindings(
                function.id,
                &[source_binding],
                &file.tokens,
                &file.significant,
            )
            .contains(&alias));
    }

    #[test]
    fn unknown_call_return_is_not_proven_clean() {
        let source = r#"function load(player, amount)
    local alias = sanitize(amount)
    return alias
end
"#;
        let file = parse_source_with_path(
            PathBuf::from("unknown.luau"),
            "unknown.luau".into(),
            source.into(),
        )
        .unwrap();
        let function = &file.semantic.functions[0];
        let source_binding = function.parameters[1];
        let alias = file
            .semantic
            .bindings
            .iter()
            .find(|binding| binding.name == "alias")
            .map(|binding| binding.id)
            .unwrap();
        assert_eq!(
            file.semantic.binding_taint_before(
                function.id,
                alias,
                function.body_tokens.end,
                &[source_binding],
                &file.tokens,
                &file.significant,
            ),
            semantic::TaintState::Unknown
        );
    }

    #[test]
    fn multi_assignment_maps_each_rhs_to_its_target() {
        let source = r#"function load(amount)
    local clean, tainted = 0, amount
    return clean, tainted
end
"#;
        let file = parse_source_with_path(
            PathBuf::from("multi.luau"),
            "multi.luau".into(),
            source.into(),
        )
        .unwrap();
        let function = &file.semantic.functions[0];
        let source_binding = function.parameters[0];
        let bindings = file
            .semantic
            .bindings
            .iter()
            .filter(|binding| matches!(binding.name.as_str(), "clean" | "tainted"))
            .map(|binding| (binding.name.as_str(), binding.id))
            .collect::<std::collections::HashMap<_, _>>();
        let tainted = file.semantic.tainted_bindings(
            function.id,
            &[source_binding],
            &file.tokens,
            &file.significant,
        );
        assert!(!tainted.contains(&bindings["clean"]));
        assert!(tainted.contains(&bindings["tainted"]));
    }
}
