//! Semantic facts derived from the lossless Luau AST and token stream.
//!
//! The semantic index is deliberately conservative.  It resolves lexical
//! bindings and performs a small, intra-procedural data-flow pass, but never
//! guesses across function boundaries, dynamic requires, metatables, or
//! runtime reflection.

use crate::{
    config::ScopeKind,
    model::{Position, Range},
    parser::{LexKind, LexToken},
};
use full_moon::{
    ast::{
        AnonymousFunction, Do, ElseIf, FunctionDeclaration, GenericFor, If, LocalFunction,
        NumericFor, Repeat, Return, While,
    },
    node::Node,
    visitors::Visitor,
};
use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    ops::Range as StdRange,
};

/// Stable identifier for a lexical scope.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScopeId(pub usize);

/// Stable identifier for a binding declaration.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BindingId(pub usize);

/// Stable identifier for a function body.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FunctionId(pub usize);

/// The kind of lexical scope represented by a [`ScopeFact`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LexicalScopeKind {
    File,
    Function,
    Block,
}

/// A lexical scope interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeFact {
    pub id: ScopeId,
    pub parent: Option<ScopeId>,
    pub kind: LexicalScopeKind,
    pub range: Range,
    pub function: Option<FunctionId>,
}

/// The origin of a resolved binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingKind {
    Local,
    LocalFunction,
    Parameter,
    LoopVariable,
}

/// A declaration known to the resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingFact {
    pub id: BindingId,
    pub name: String,
    pub kind: BindingKind,
    pub declaration_token: usize,
    pub declaration: Range,
    pub scope: ScopeId,
    pub function: Option<FunctionId>,
}

/// A reference resolved to a lexical binding, if one exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceFact {
    pub token_index: usize,
    pub name: String,
    pub range: Range,
    pub scope: ScopeId,
    pub binding: Option<BindingId>,
    pub function: Option<FunctionId>,
}

/// How an AST function was declared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FunctionKind {
    Named,
    Local,
    Anonymous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AstControlKind {
    If,
    ElseIf,
    Do,
    Loop,
    Repeat,
    Return,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AstControlFact {
    pub kind: AstControlKind,
    pub range: Range,
}

/// A function body and its callback context, if any.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionFact {
    pub id: FunctionId,
    pub kind: FunctionKind,
    pub range: Range,
    pub body_range: Range,
    pub function_token: usize,
    pub body_tokens: StdRange<usize>,
    pub parameters: Vec<BindingId>,
    pub callback_signal: Option<String>,
    pub callback_signal_token: Option<usize>,
    pub callback_method: Option<String>,
}

impl FunctionFact {
    pub fn is_callback(&self) -> bool {
        self.callback_signal.is_some()
    }
}

/// A remotely reachable callback endpoint.  Keeping this separate from the
/// function fact allows one named function to be connected to more than one
/// signal without losing either association.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteEndpointFact {
    pub signal_name: String,
    pub method: String,
    pub function_id: FunctionId,
    pub signal_token: usize,
    pub handler_token: usize,
}

/// A call with enough structure for rules to reason about its receiver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticCallFact {
    pub name: String,
    pub token_index: usize,
    pub open_paren_index: usize,
    pub receiver_token: Option<usize>,
    pub method_style: bool,
    pub function: Option<FunctionId>,
    pub scope: ScopeId,
}

/// An assignment tied to its resolved target and enclosing function.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticAssignmentFact {
    pub target_token: usize,
    pub operator_token: usize,
    pub target: Option<BindingId>,
    /// Zero-based position of this target in a multi-assignment.  Keeping
    /// this fact lets data-flow map `local clean, tainted = 0, remote` to the
    /// right RHS expression instead of conservatively copying one value to
    /// every target.
    pub target_ordinal: usize,
    pub target_count: usize,
    pub function: Option<FunctionId>,
    pub scope: ScopeId,
}

/// Conservative data-flow state for one expression or binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaintState {
    Clean,
    RemoteTainted,
    Unknown,
}

impl TaintState {
    fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::RemoteTainted, _) | (_, Self::RemoteTainted) => Self::RemoteTainted,
            _ => Self::Clean,
        }
    }

    pub fn is_tainted(self) -> bool {
        matches!(self, Self::RemoteTainted)
    }
}

#[derive(Clone, Debug, Default)]
struct FunctionCfg {
    start: usize,
    end: usize,
    successors: Vec<Vec<usize>>,
}

#[derive(Clone, Debug)]
enum CfgBlockKind {
    If { branches: Vec<CfgBranch> },
    Loop { header: usize, body_start: usize },
    Repeat { header: usize, body_start: usize },
    Do,
}

#[derive(Clone, Debug)]
struct CfgBlock {
    kind: CfgBlockKind,
    end: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
struct CfgBranch {
    marker: usize,
    body_start: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AstFunctionKind {
    Named,
    Local,
    Anonymous,
}

#[derive(Clone, Debug)]
struct AstFunctionSeed {
    kind: AstFunctionKind,
    range: Range,
    body_range: Range,
}

#[derive(Default)]
struct AstCollector {
    functions: Vec<AstFunctionSeed>,
    controls: Vec<AstControlFact>,
}

impl Visitor for AstCollector {
    fn visit_function_declaration(&mut self, node: &FunctionDeclaration) {
        if let (Some(range), Some(body_range)) = (node.range(), node.body().range()) {
            self.functions.push(AstFunctionSeed {
                kind: AstFunctionKind::Named,
                range: to_range(range),
                body_range: to_range(body_range),
            });
        }
    }

    fn visit_local_function(&mut self, node: &LocalFunction) {
        if let (Some(range), Some(body_range)) = (node.range(), node.body().range()) {
            self.functions.push(AstFunctionSeed {
                kind: AstFunctionKind::Local,
                range: to_range(range),
                body_range: to_range(body_range),
            });
        }
    }

    fn visit_anonymous_function(&mut self, node: &AnonymousFunction) {
        if let (Some(range), Some(body_range)) = (node.range(), node.body().range()) {
            self.functions.push(AstFunctionSeed {
                kind: AstFunctionKind::Anonymous,
                range: to_range(range),
                body_range: to_range(body_range),
            });
        }
    }

    fn visit_if(&mut self, node: &If) {
        if let Some(range) = node.range() {
            self.controls.push(AstControlFact {
                kind: AstControlKind::If,
                range: to_range(range),
            });
        }
    }

    fn visit_else_if(&mut self, node: &ElseIf) {
        if let Some(range) = node.range() {
            self.controls.push(AstControlFact {
                kind: AstControlKind::ElseIf,
                range: to_range(range),
            });
        }
    }

    fn visit_do(&mut self, node: &Do) {
        if let Some(range) = node.range() {
            self.controls.push(AstControlFact {
                kind: AstControlKind::Do,
                range: to_range(range),
            });
        }
    }

    fn visit_generic_for(&mut self, node: &GenericFor) {
        if let Some(range) = node.range() {
            self.controls.push(AstControlFact {
                kind: AstControlKind::Loop,
                range: to_range(range),
            });
        }
    }

    fn visit_numeric_for(&mut self, node: &NumericFor) {
        if let Some(range) = node.range() {
            self.controls.push(AstControlFact {
                kind: AstControlKind::Loop,
                range: to_range(range),
            });
        }
    }

    fn visit_repeat(&mut self, node: &Repeat) {
        if let Some(range) = node.range() {
            self.controls.push(AstControlFact {
                kind: AstControlKind::Repeat,
                range: to_range(range),
            });
        }
    }

    fn visit_while(&mut self, node: &While) {
        if let Some(range) = node.range() {
            self.controls.push(AstControlFact {
                kind: AstControlKind::Loop,
                range: to_range(range),
            });
        }
    }

    fn visit_return(&mut self, node: &Return) {
        if let Some(range) = node.range() {
            self.controls.push(AstControlFact {
                kind: AstControlKind::Return,
                range: to_range(range),
            });
        }
    }
}

/// Run the AST visitor used by the parser worker.  Keeping this separate lets
/// `parse_source` validate syntax without retaining a full Moon AST in the
/// public `ParsedFile`.
pub fn collect_ast_functions(ast: &full_moon::ast::Ast) -> Vec<(Range, Range, FunctionKind)> {
    let mut collector = AstCollector::default();
    collector.visit_ast(ast);
    collector
        .functions
        .into_iter()
        .map(|seed| {
            let kind = match seed.kind {
                AstFunctionKind::Named => FunctionKind::Named,
                AstFunctionKind::Local => FunctionKind::Local,
                AstFunctionKind::Anonymous => FunctionKind::Anonymous,
            };
            (seed.range, seed.body_range, kind)
        })
        .collect()
}

pub fn collect_ast_semantic_facts(
    ast: &full_moon::ast::Ast,
) -> (Vec<(Range, Range, FunctionKind)>, Vec<AstControlFact>) {
    let mut collector = AstCollector::default();
    collector.visit_ast(ast);
    let functions = collector
        .functions
        .into_iter()
        .map(|seed| {
            let kind = match seed.kind {
                AstFunctionKind::Named => FunctionKind::Named,
                AstFunctionKind::Local => FunctionKind::Local,
                AstFunctionKind::Anonymous => FunctionKind::Anonymous,
            };
            (seed.range, seed.body_range, kind)
        })
        .collect();
    (functions, collector.controls)
}

/// Per-file semantic facts.  All ranges are lossless source ranges and all
/// token indexes refer to the significant-token projection supplied by the
/// parser.
#[derive(Clone, Debug, Default)]
pub struct SemanticIndex {
    pub scopes: Vec<ScopeFact>,
    pub bindings: Vec<BindingFact>,
    pub references: Vec<ReferenceFact>,
    pub functions: Vec<FunctionFact>,
    pub remote_endpoints: Vec<RemoteEndpointFact>,
    pub calls: Vec<SemanticCallFact>,
    pub assignments: Vec<SemanticAssignmentFact>,
    pub ast_controls: Vec<AstControlFact>,
    token_bindings: HashMap<usize, BindingId>,
    token_scopes: Vec<ScopeId>,
    token_positions: HashMap<usize, usize>,
    function_by_token: HashMap<usize, FunctionId>,
    declaration_tokens: HashSet<usize>,
    cfgs: HashMap<FunctionId, FunctionCfg>,
}

impl SemanticIndex {
    /// Build the index from AST-derived function ranges and the lossless
    /// lexer projection.  The AST has already been parsed exactly once by the
    /// parser worker.
    pub fn build(
        ast_functions: &[(Range, Range, FunctionKind)],
        tokens: &[LexToken],
        significant: &[usize],
    ) -> Self {
        Self::build_with_controls(ast_functions, &[], tokens, significant)
    }

    pub fn build_with_controls(
        ast_functions: &[(Range, Range, FunctionKind)],
        ast_controls: &[AstControlFact],
        tokens: &[LexToken],
        significant: &[usize],
    ) -> Self {
        let mut index = Self {
            ast_controls: ast_controls.to_vec(),
            ..Self::default()
        };
        index.build_scopes(ast_functions, tokens, significant);
        index.build_functions(ast_functions, tokens, significant);
        index.build_bindings(tokens, significant);
        index.build_references(tokens, significant);
        index.build_calls(tokens, significant);
        index.build_assignments(tokens, significant);
        index.build_cfgs(tokens, significant);
        index.associate_callbacks(tokens, significant);
        index
    }

    pub fn file_scope(&self) -> ScopeId {
        ScopeId(0)
    }

    pub fn scope_at_byte(&self, byte: usize) -> ScopeId {
        self.scopes
            .iter()
            .filter(|scope| scope.range.start.byte <= byte && byte <= scope.range.end.byte)
            .min_by_key(|scope| {
                (
                    scope.range.end.byte.saturating_sub(scope.range.start.byte),
                    match scope.kind {
                        LexicalScopeKind::Function => 0usize,
                        LexicalScopeKind::Block => 1,
                        LexicalScopeKind::File => 2,
                    },
                )
            })
            .map(|scope| scope.id)
            .unwrap_or_else(|| self.file_scope())
    }

    pub fn scope_at_token(&self, token_index: usize) -> ScopeId {
        self.token_scopes
            .get(token_index)
            .copied()
            .unwrap_or_else(|| self.file_scope())
    }

    pub fn function_at_token(&self, token_index: usize) -> Option<FunctionId> {
        self.function_by_token.get(&token_index).copied()
    }

    pub fn function(&self, id: FunctionId) -> Option<&FunctionFact> {
        self.functions.get(id.0)
    }

    pub fn binding(&self, id: BindingId) -> Option<&BindingFact> {
        self.bindings.get(id.0)
    }

    pub fn binding_for_token(&self, token_index: usize) -> Option<BindingId> {
        self.token_bindings.get(&token_index).copied()
    }

    pub fn significant_position(&self, token_index: usize) -> Option<usize> {
        self.token_positions.get(&token_index).copied()
    }

    pub fn reference_for_token(&self, token_index: usize) -> Option<&ReferenceFact> {
        self.references
            .iter()
            .find(|reference| reference.token_index == token_index)
    }

    /// Resolve a name at a source byte.  Resolution is lexical and flow
    /// independent: a declaration only becomes visible at its declaration
    /// token, except function parameters which are visible for the body.
    pub fn resolve_name(&self, name: &str, byte: usize) -> Option<BindingId> {
        let scope = self.scope_at_byte(byte);
        let mut candidates = self
            .bindings
            .iter()
            .filter(|binding| {
                binding.name == name
                    && binding.declaration.start.byte <= byte
                    && self.is_scope_inside(scope, binding.scope)
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|binding| {
            let depth = self.scope_depth(binding.scope);
            (
                std::cmp::Reverse(depth),
                std::cmp::Reverse(binding.declaration.start.byte),
            )
        });
        candidates.first().map(|binding| binding.id)
    }

    pub fn is_shadowed_at(&self, name: &str, byte: usize) -> bool {
        self.resolve_name(name, byte).is_some()
    }

    /// Return the function containing a token, walking through block scopes
    /// when the token is not itself a function declaration.
    pub fn enclosing_function(&self, token_index: usize) -> Option<FunctionId> {
        let mut scope = self.scope_at_token(token_index);
        loop {
            let fact = self.scopes.get(scope.0)?;
            if let Some(function) = fact.function {
                return Some(function);
            }
            scope = fact.parent?;
        }
    }

    /// Compute the state of a function binding immediately before a token.
    /// Assignments in alternate branches join conservatively, so a remote
    /// origin is never silently discarded.
    pub fn taint_state_before(
        &self,
        function: FunctionId,
        token_index: usize,
        sources: &[BindingId],
        tokens: &[LexToken],
        significant: &[usize],
    ) -> TaintState {
        let Some(function_fact) = self.function(function) else {
            return TaintState::Unknown;
        };
        // Callers naturally have a raw token index here, while the data-flow
        // graph is indexed by significant-token positions. Normalize both
        // forms so comments/whitespace cannot shift the requested state.
        let end = significant
            .iter()
            .position(|candidate| *candidate == token_index)
            .unwrap_or(token_index)
            .min(function_fact.body_tokens.end);
        let states = self.flow_states_before(function, end, sources, tokens, significant);
        if states
            .values()
            .any(|state| *state == TaintState::RemoteTainted)
        {
            TaintState::RemoteTainted
        } else if states.values().any(|state| *state == TaintState::Unknown) {
            TaintState::Unknown
        } else {
            TaintState::Clean
        }
    }

    /// Evaluate an expression range using the flow state immediately before
    /// it.  The range is expressed in significant-token positions.
    pub fn expression_taint(
        &self,
        function: FunctionId,
        start: usize,
        end: usize,
        sources: &[BindingId],
        tokens: &[LexToken],
        significant: &[usize],
    ) -> TaintState {
        let states = self.flow_states_before(function, start, sources, tokens, significant);
        self.expression_state(function, start, end, &states, tokens, significant)
    }

    /// Resolve a binding's state immediately before a significant-token
    /// position.
    pub fn binding_taint_before(
        &self,
        function: FunctionId,
        binding: BindingId,
        token_position: usize,
        sources: &[BindingId],
        tokens: &[LexToken],
        significant: &[usize],
    ) -> TaintState {
        self.flow_states_before(function, token_position, sources, tokens, significant)
            .get(&binding)
            .copied()
            .unwrap_or(TaintState::Clean)
    }

    fn flow_states_before(
        &self,
        function: FunctionId,
        end: usize,
        sources: &[BindingId],
        tokens: &[LexToken],
        significant: &[usize],
    ) -> HashMap<BindingId, TaintState> {
        let Some(cfg) = self.cfgs.get(&function) else {
            return HashMap::new();
        };
        if cfg.successors.is_empty() {
            return sources
                .iter()
                .copied()
                .map(|source| (source, TaintState::RemoteTainted))
                .collect();
        }
        let initial = sources
            .iter()
            .copied()
            .map(|source| (source, TaintState::RemoteTainted))
            .collect::<HashMap<_, _>>();
        let body_len = cfg.successors.len();
        // Keep one extra slot for the synthetic function-exit node.
        let mut states_at = vec![None::<HashMap<BindingId, TaintState>>; body_len + 1];
        states_at[0] = Some(initial);
        let mut worklist = VecDeque::from([0usize]);
        let mut assignment_positions = HashMap::<usize, Vec<usize>>::new();
        for (index, assignment) in self.assignments.iter().enumerate() {
            if assignment.function != Some(function) {
                continue;
            }
            if let Some(position) = significant
                .iter()
                .position(|token| *token == assignment.operator_token)
            {
                assignment_positions
                    .entry(position)
                    .or_default()
                    .push(index);
            }
        }
        let requested = end.clamp(cfg.start, cfg.end);
        while let Some(local) = worklist.pop_front() {
            let Some(mut state) = states_at[local].clone() else {
                continue;
            };
            let body_len = cfg.end.saturating_sub(cfg.start);
            // The terminal slot aggregates all paths that leave the
            // function. It has no statement to transfer, but still needs to
            // be reachable so a later branch can join its state.
            if local >= body_len {
                continue;
            }
            let position = cfg.start + local;
            if let Some(assignment_indices) = assignment_positions.get(&position) {
                for assignment_index in assignment_indices {
                    let assignment = &self.assignments[*assignment_index];
                    let rhs_segments =
                        assignment_rhs_segments(significant, tokens, position + 1, cfg.end);
                    // A call can return multiple values, so assigning a
                    // missing RHS to a later target is not proof of a clean
                    // value. Unknown is the safe state for that case.
                    let rhs_state = rhs_segments
                        .get(assignment.target_ordinal)
                        .map(|segment| {
                            self.expression_state(
                                function,
                                segment.start,
                                segment.end,
                                &state,
                                tokens,
                                significant,
                            )
                        })
                        .unwrap_or(TaintState::Unknown);
                    if let Some(target) = assignment.target {
                        let value =
                            if matches!(tokens[assignment.operator_token].text.as_str(), "=") {
                                rhs_state
                            } else {
                                state
                                    .get(&target)
                                    .copied()
                                    .unwrap_or(TaintState::Clean)
                                    .join(rhs_state)
                            };
                        state.insert(target, value);
                    }
                }
            }
            for successor in &cfg.successors[local] {
                if *successor > body_len {
                    continue;
                }
                let slot = &mut states_at[*successor];
                let merged = match slot {
                    Some(previous) => join_into(previous, &state),
                    None => {
                        *slot = Some(state.clone());
                        true
                    }
                };
                if merged {
                    worklist.push_back(*successor);
                }
            }
            if cfg.successors[local].is_empty() {
                // `return` and other terminal statements have no explicit
                // successor. Join their post-transfer state into the same
                // synthetic exit slot used by normal fallthrough.
                if let Some(exit) = states_at.get_mut(body_len) {
                    join_into(exit.get_or_insert_with(HashMap::new), &state);
                }
            }
        }
        states_at
            .get(requested.saturating_sub(cfg.start))
            .and_then(Option::clone)
            .unwrap_or_default()
    }

    fn expression_state(
        &self,
        function: FunctionId,
        start: usize,
        end: usize,
        states: &HashMap<BindingId, TaintState>,
        tokens: &[LexToken],
        significant: &[usize],
    ) -> TaintState {
        let mut result = TaintState::Clean;
        for position in start.min(significant.len())..end.min(significant.len()) {
            let Some(rhs_token_index) = significant.get(position).copied() else {
                continue;
            };
            // A nested function is a separate data-flow graph. Do not infer
            // that merely mentioning an outer parameter inside its closure
            // proves the outer expression itself is remote-tainted.
            if self
                .enclosing_function(rhs_token_index)
                .is_some_and(|owner| owner != function)
            {
                continue;
            }
            let rhs_token = &tokens[rhs_token_index];
            if rhs_token.kind != LexKind::Identifier {
                continue;
            }
            if matches!(rhs_token.text.as_str(), "true" | "false" | "nil") {
                continue;
            }
            if let Some(binding) = self.binding_for_token(rhs_token_index) {
                result = result.join(states.get(&binding).copied().unwrap_or(TaintState::Clean));
            } else if !is_keyword(rhs_token.text.as_str())
                && !is_known_global(rhs_token.text.as_str())
            {
                result = result.join(TaintState::Unknown);
            }
            // A call whose return value is not modeled is an unknown source,
            // even when the callee itself is a local binding.  This prevents
            // an unmodeled helper from being mistaken for a clean sanitizer.
            if significant
                .get(position + 1)
                .is_some_and(|next| tokens[*next].text == "(")
            {
                result = result.join(TaintState::Unknown);
            }
        }
        result
    }

    /// Return all bindings that are tainted by the supplied source bindings
    /// in a function.  This is useful for rules that inspect several sinks.
    pub fn tainted_bindings(
        &self,
        function: FunctionId,
        sources: &[BindingId],
        tokens: &[LexToken],
        significant: &[usize],
    ) -> BTreeSet<BindingId> {
        self.flow_states_before(
            function,
            self.function(function)
                .map(|fact| fact.body_tokens.end)
                .unwrap_or_default(),
            sources,
            tokens,
            significant,
        )
        .into_iter()
        .filter_map(|(binding, state)| state.is_tainted().then_some(binding))
        .collect()
    }

    fn build_scopes(
        &mut self,
        ast_functions: &[(Range, Range, FunctionKind)],
        tokens: &[LexToken],
        significant: &[usize],
    ) {
        self.scopes.push(ScopeFact {
            id: ScopeId(0),
            parent: None,
            kind: LexicalScopeKind::File,
            range: Range {
                start: Position {
                    line: 1,
                    column: 1,
                    byte: 0,
                },
                end: tokens
                    .last()
                    .map(|token| token.range.end)
                    .unwrap_or(Position {
                        line: 1,
                        column: 1,
                        byte: 0,
                    }),
            },
            function: None,
        });

        for (range, _, _) in ast_functions {
            self.scopes.push(ScopeFact {
                id: ScopeId(self.scopes.len()),
                parent: None,
                kind: LexicalScopeKind::Function,
                range: *range,
                function: None,
            });
        }

        let mut function_ranges = ast_functions
            .iter()
            .map(|(range, _, _)| (range.start.byte, range.end.byte))
            .collect::<Vec<_>>();
        function_ranges.sort_by_key(|(start, end)| (*start, std::cmp::Reverse(*end)));
        // Keep an independent block stack for each lexical function. Without
        // this, the `end` token closing a nested function could accidentally
        // close an `if`/loop belonging to its parent function.
        let mut stacks = HashMap::<Option<usize>, Vec<(usize, &'static str)>>::new();
        let mut function_cursor = 0usize;
        let mut active_functions = Vec::<usize>::new();
        for (position, token_index) in significant.iter().copied().enumerate() {
            let token = &tokens[token_index];
            while active_functions
                .last()
                .is_some_and(|index| function_ranges[*index].1 < token.range.start.byte)
            {
                active_functions.pop();
            }
            while function_cursor < function_ranges.len()
                && function_ranges[function_cursor].0 <= token.range.start.byte
            {
                if function_ranges[function_cursor].1 >= token.range.end.byte {
                    active_functions.push(function_cursor);
                }
                function_cursor += 1;
            }
            let owner = active_functions.last().copied();
            let stack = stacks.entry(owner).or_default();
            match token.text.as_str() {
                "if" | "for" | "while" | "repeat" => {
                    stack.push((position, token.text.as_str()));
                }
                "do" if !stack
                    .last()
                    .is_some_and(|(_, kind)| matches!(*kind, "for" | "while")) =>
                {
                    stack.push((position, "do"));
                }
                "end" => {
                    if let Some((start, kind)) = stack.pop() {
                        let start_token = &tokens[significant[start]];
                        let range = Range {
                            start: start_token.range.start,
                            end: token.range.end,
                        };
                        if !matches!(kind, "function") {
                            self.scopes.push(ScopeFact {
                                id: ScopeId(self.scopes.len()),
                                parent: None,
                                kind: LexicalScopeKind::Block,
                                range,
                                function: None,
                            });
                        }
                    }
                }
                "until" => {
                    if let Some((start, kind)) = stack.last().copied() {
                        if kind == "repeat" {
                            stack.pop();
                            let start_token = &tokens[significant[start]];
                            self.scopes.push(ScopeFact {
                                id: ScopeId(self.scopes.len()),
                                parent: None,
                                kind: LexicalScopeKind::Block,
                                range: Range {
                                    start: start_token.range.start,
                                    end: token.range.end,
                                },
                                function: None,
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        let mut order = (1..self.scopes.len()).collect::<Vec<_>>();
        order.sort_by_key(|index| {
            let scope = &self.scopes[*index];
            (
                scope.range.start.byte,
                std::cmp::Reverse(scope.range.end.byte),
            )
        });
        for index in order {
            let (start, end) = {
                let scope = &self.scopes[index];
                (scope.range.start.byte, scope.range.end.byte)
            };
            let parent = self
                .scopes
                .iter()
                .filter(|candidate| {
                    candidate.id != ScopeId(index)
                        && candidate.range.start.byte <= start
                        && candidate.range.end.byte >= end
                })
                .min_by_key(|candidate| {
                    candidate
                        .range
                        .end
                        .byte
                        .saturating_sub(candidate.range.start.byte)
                })
                .map(|candidate| candidate.id)
                .or(Some(self.file_scope()));
            self.scopes[index].parent = parent;
        }
        self.token_scopes = vec![self.file_scope(); tokens.len()];
        self.token_positions = significant
            .iter()
            .copied()
            .enumerate()
            .map(|(position, token_index)| {
                self.token_scopes[token_index] =
                    self.scope_at_byte(tokens[token_index].range.start.byte);
                (token_index, position)
            })
            .collect();
    }

    fn build_functions(
        &mut self,
        ast_functions: &[(Range, Range, FunctionKind)],
        tokens: &[LexToken],
        significant: &[usize],
    ) {
        let mut sorted = ast_functions.to_vec();
        sorted.sort_by_key(|(range, _, _)| (range.start.byte, range.end.byte));
        for (range, body_range, kind) in sorted {
            let Some((function_position, function_token)) = significant
                .iter()
                .copied()
                .enumerate()
                .find(|(_, token_index)| {
                    let token = &tokens[*token_index];
                    token.text == "function"
                        && token.range.start.byte >= range.start.byte
                        && token.range.end.byte <= range.end.byte
                })
            else {
                continue;
            };
            let Some(open_position) = (function_position + 1..significant.len()).find(|position| {
                let token = &tokens[significant[*position]];
                token.text == "(" && token.range.start.byte < body_range.end.byte
            }) else {
                continue;
            };
            let Some(close_position) =
                matching_symbol(tokens, significant, open_position, "(", ")")
            else {
                continue;
            };
            let end_position = significant
                .iter()
                .copied()
                .enumerate()
                .filter(|(_, token_index)| tokens[*token_index].range.end.byte <= range.end.byte)
                .map(|(position, _)| position)
                .max()
                .unwrap_or(close_position);
            let scope = self
                .scopes
                .iter()
                .find(|scope| {
                    scope.kind == LexicalScopeKind::Function
                        && scope.range.start.byte == range.start.byte
                        && scope.range.end.byte == range.end.byte
                })
                .map(|scope| scope.id)
                .unwrap_or_else(|| self.file_scope());
            let id = FunctionId(self.functions.len());
            if let Some(scope_fact) = self.scopes.get_mut(scope.0) {
                scope_fact.function = Some(id);
            }
            self.function_by_token.insert(function_token, id);
            self.functions.push(FunctionFact {
                id,
                kind,
                range,
                body_range,
                function_token,
                body_tokens: (close_position + 1)..end_position,
                parameters: Vec::new(),
                callback_signal: None,
                callback_signal_token: None,
                callback_method: None,
            });
        }
    }

    fn build_bindings(&mut self, tokens: &[LexToken], significant: &[usize]) {
        for function_index in 0..self.functions.len() {
            let function = self.functions[function_index].clone();
            let Some(function_position) = significant
                .iter()
                .position(|token_index| *token_index == function.function_token)
            else {
                continue;
            };
            let Some(open_position) = (function_position + 1..significant.len())
                .find(|position| tokens[significant[*position]].text == "(")
            else {
                continue;
            };
            let Some(close_position) =
                matching_symbol(tokens, significant, open_position, "(", ")")
            else {
                continue;
            };
            let function_scope = self
                .scopes
                .iter()
                .find(|scope| scope.function == Some(function.id))
                .map(|scope| scope.id)
                .unwrap_or_else(|| self.file_scope());
            let mut expect_name = true;
            let mut type_depth = 0usize;
            for token_index in significant
                .iter()
                .take(close_position)
                .skip(open_position + 1)
                .copied()
            {
                let token = &tokens[token_index];
                match token.text.as_str() {
                    "," if type_depth == 0 => expect_name = true,
                    ":" => {
                        type_depth = type_depth.saturating_add(1);
                        expect_name = false;
                    }
                    _ if expect_name && type_depth == 0 && token.kind == LexKind::Identifier => {
                        let binding = self.add_binding(
                            token,
                            token_index,
                            BindingKind::Parameter,
                            function_scope,
                            Some(function.id),
                        );
                        self.functions[function_index].parameters.push(binding);
                        expect_name = false;
                    }
                    _ if type_depth > 0 && (token.text == "," || token.text == ")") => {
                        type_depth = 0;
                        expect_name = token.text == ",";
                    }
                    _ => {}
                }
            }
        }

        let mut position = 0usize;
        while position < significant.len() {
            let token_index = significant[position];
            let token = &tokens[token_index];
            if token.text == "local" {
                if significant
                    .get(position + 1)
                    .is_some_and(|index| tokens[*index].text == "function")
                {
                    if let Some(name_index) = significant.get(position + 2).copied() {
                        let name = &tokens[name_index];
                        if name.kind == LexKind::Identifier {
                            let scope = self.scope_at_token(name_index);
                            self.add_binding(
                                name,
                                name_index,
                                BindingKind::LocalFunction,
                                scope,
                                self.enclosing_function(name_index),
                            );
                            self.declaration_tokens.insert(name_index);
                        }
                    }
                    position += 2;
                    continue;
                }
                let mut cursor = position + 1;
                let mut expect_name = true;
                let mut in_type = false;
                while cursor < significant.len() {
                    let name_index = significant[cursor];
                    let name = &tokens[name_index];
                    if name.text == "=" || name.text == ";" || name.text == "end" {
                        break;
                    }
                    if name.text == "," {
                        expect_name = true;
                        in_type = false;
                        cursor += 1;
                        continue;
                    }
                    if name.text == ":" {
                        in_type = true;
                        expect_name = false;
                        cursor += 1;
                        continue;
                    }
                    if expect_name && !in_type && name.kind == LexKind::Identifier {
                        let scope = self.scope_at_token(name_index);
                        self.add_binding(
                            name,
                            name_index,
                            BindingKind::Local,
                            scope,
                            self.enclosing_function(name_index),
                        );
                        self.declaration_tokens.insert(name_index);
                        expect_name = false;
                    }
                    cursor += 1;
                }
                position = cursor;
                continue;
            }
            if token.text == "for" {
                let mut cursor = position + 1;
                let mut expect_name = true;
                while cursor < significant.len() {
                    let name_index = significant[cursor];
                    let name = &tokens[name_index];
                    if matches!(name.text.as_str(), "=" | "in" | "do") {
                        break;
                    }
                    if name.text == "," {
                        expect_name = true;
                    } else if expect_name && name.kind == LexKind::Identifier {
                        let scope = self.scope_at_token(name_index);
                        self.add_binding(
                            name,
                            name_index,
                            BindingKind::LoopVariable,
                            scope,
                            self.enclosing_function(name_index),
                        );
                        self.declaration_tokens.insert(name_index);
                        expect_name = false;
                    }
                    cursor += 1;
                }
                position = cursor;
                continue;
            }
            position += 1;
        }
    }

    fn add_binding(
        &mut self,
        token: &LexToken,
        declaration_token: usize,
        kind: BindingKind,
        scope: ScopeId,
        function: Option<FunctionId>,
    ) -> BindingId {
        let id = BindingId(self.bindings.len());
        self.bindings.push(BindingFact {
            id,
            name: token.text.clone(),
            kind,
            declaration_token,
            declaration: token.range,
            scope,
            function,
        });
        id
    }

    fn build_references(&mut self, tokens: &[LexToken], significant: &[usize]) {
        for (position, token_index) in significant.iter().copied().enumerate() {
            let token = &tokens[token_index];
            if token.kind != LexKind::Identifier || self.declaration_tokens.contains(&token_index) {
                continue;
            }
            if position > 0 && matches!(tokens[significant[position - 1]].text.as_str(), "." | ":")
            {
                continue;
            }
            let scope = self.scope_at_token(token_index);
            let function = self.enclosing_function(token_index);
            let binding = self.resolve_name(&token.text, token.range.start.byte);
            self.references.push(ReferenceFact {
                token_index,
                name: token.text.clone(),
                range: token.range,
                scope,
                binding,
                function,
            });
            if let Some(binding) = binding {
                self.token_bindings.insert(token_index, binding);
            }
        }
    }

    fn build_calls(&mut self, tokens: &[LexToken], significant: &[usize]) {
        for (position, token_index) in significant.iter().copied().enumerate() {
            let token = &tokens[token_index];
            if token.kind != LexKind::Identifier
                || significant
                    .get(position + 1)
                    .is_none_or(|index| tokens[*index].text != "(")
            {
                continue;
            }
            let receiver_token = position
                .checked_sub(2)
                .filter(|dot| matches!(tokens[significant[*dot + 1]].text.as_str(), "." | ":"))
                .map(|receiver| significant[receiver]);
            self.calls.push(SemanticCallFact {
                name: token.text.clone(),
                token_index,
                open_paren_index: significant[position + 1],
                receiver_token,
                method_style: receiver_token.is_some(),
                function: self.enclosing_function(token_index),
                scope: self.scope_at_token(token_index),
            });
        }
    }

    fn build_assignments(&mut self, tokens: &[LexToken], significant: &[usize]) {
        for (position, token_index) in significant.iter().copied().enumerate() {
            if !is_assignment_operator(&tokens[token_index]) || position == 0 {
                continue;
            }
            let candidates = assignment_target_positions(tokens, significant, position);
            if candidates.is_empty() {
                continue;
            }
            let target_count = candidates.len();
            for (target_ordinal, target_position) in candidates.iter().copied().enumerate() {
                let target_token = significant[target_position];
                let target = self.token_bindings.get(&target_token).copied().or_else(|| {
                    self.resolve_name(
                        tokens[target_token].text.as_str(),
                        tokens[target_token].range.start.byte,
                    )
                });
                self.assignments.push(SemanticAssignmentFact {
                    target_token,
                    operator_token: token_index,
                    target,
                    target_ordinal,
                    target_count,
                    function: self.enclosing_function(target_token),
                    scope: self.scope_at_token(target_token),
                });
            }
        }
    }

    /// Build a small statement-level CFG for every AST function.  The AST
    /// visitor identifies function ownership; token boundaries are used only
    /// to connect the lossless source ranges into fallthrough/branch/loop
    /// edges.  This keeps the graph cheap while still handling nested blocks
    /// without treating every `end` as the end of the current function.
    fn build_cfgs(&mut self, tokens: &[LexToken], significant: &[usize]) {
        // Control-flow markers come from the lossless AST visitor.  The token
        // stream is still used to connect exact byte positions, but keywords
        // inside strings/identifiers can no longer accidentally create a
        // branch or loop.
        let ast_controls = self
            .ast_controls
            .iter()
            .filter_map(|control| {
                significant
                    .iter()
                    .position(|token_index| {
                        tokens
                            .get(*token_index)
                            .is_some_and(|token| token.range.start.byte == control.range.start.byte)
                    })
                    .map(|position| (position, control.kind))
            })
            .collect::<HashMap<_, _>>();
        for function in self.functions.clone() {
            let start = function.body_tokens.start.min(significant.len());
            let end = function.body_tokens.end.min(significant.len());
            if start >= end {
                self.cfgs.insert(
                    function.id,
                    FunctionCfg {
                        start,
                        end,
                        successors: Vec::new(),
                    },
                );
                continue;
            }
            let length = end - start;
            let mut cfg = FunctionCfg {
                start,
                end,
                successors: (0..length)
                    .map(|local| {
                        if local + 1 < length {
                            vec![local + 1]
                        } else {
                            vec![length]
                        }
                    })
                    .collect(),
            };
            let mut stack = Vec::<CfgBlock>::new();
            let mut blocks = Vec::<CfgBlock>::new();
            for position in start..end {
                let Some(token_index) = significant.get(position).copied() else {
                    continue;
                };
                if self
                    .enclosing_function(token_index)
                    .is_some_and(|owner| owner != function.id)
                {
                    continue;
                }
                let text = tokens[token_index].text.as_str();
                match ast_controls.get(&position).copied() {
                    Some(AstControlKind::If) => {
                        let then_position =
                            find_after_keyword(tokens, significant, position + 1, end, "then")
                                .unwrap_or(position);
                        stack.push(CfgBlock {
                            kind: CfgBlockKind::If {
                                branches: vec![CfgBranch {
                                    marker: position,
                                    body_start: (then_position + 1).min(end),
                                }],
                            },
                            end: None,
                        });
                    }
                    Some(AstControlKind::ElseIf) => {
                        if let Some(CfgBlock {
                            kind: CfgBlockKind::If { branches },
                            ..
                        }) = stack.last_mut()
                        {
                            let then_position =
                                find_after_keyword(tokens, significant, position + 1, end, "then")
                                    .unwrap_or(position);
                            branches.push(CfgBranch {
                                marker: position,
                                body_start: (then_position + 1).min(end),
                            });
                        }
                    }
                    _ if text == "else" => {
                        if let Some(CfgBlock {
                            kind: CfgBlockKind::If { branches },
                            ..
                        }) = stack.last_mut()
                        {
                            branches.push(CfgBranch {
                                marker: position,
                                body_start: (position + 1).min(end),
                            });
                        }
                    }
                    Some(AstControlKind::Loop) => {
                        let body_start =
                            find_after_keyword(tokens, significant, position + 1, end, "do")
                                .map(|do_position| do_position + 1)
                                .unwrap_or(position + 1)
                                .min(end);
                        stack.push(CfgBlock {
                            kind: CfgBlockKind::Loop {
                                header: position,
                                body_start,
                            },
                            end: None,
                        });
                    }
                    Some(AstControlKind::Repeat) => stack.push(CfgBlock {
                        kind: CfgBlockKind::Repeat {
                            header: position,
                            body_start: (position + 1).min(end),
                        },
                        end: None,
                    }),
                    Some(AstControlKind::Do) => {
                        let loop_header = stack.last().is_some_and(|block| {
                            matches!(
                                &block.kind,
                                CfgBlockKind::Loop { body_start, .. }
                                    if *body_start == position + 1
                            )
                        });
                        if !loop_header {
                            stack.push(CfgBlock {
                                kind: CfgBlockKind::Do,
                                end: None,
                            });
                        }
                    }
                    _ if text == "end" => {
                        if let Some(mut block) = stack.pop() {
                            block.end = Some(position);
                            blocks.push(block);
                        }
                    }
                    _ if text == "until" => {
                        if let Some(mut block) = stack.pop() {
                            if matches!(&block.kind, CfgBlockKind::Repeat { .. }) {
                                block.end = Some(position);
                                blocks.push(block);
                            } else {
                                stack.push(block);
                            }
                        }
                    }
                    _ => {}
                }
            }

            for block in &blocks {
                let Some(block_end) = block.end else {
                    continue;
                };
                let after_end = block_end + 1;
                match &block.kind {
                    CfgBlockKind::If { branches } => {
                        for (index, branch) in branches.iter().enumerate() {
                            let next_marker = branches
                                .get(index + 1)
                                .map(|next| next.marker)
                                .unwrap_or(block_end);
                            let is_condition = tokens
                                .get(*significant.get(branch.marker).unwrap_or(&0))
                                .is_some_and(|token| token.text == "if" || token.text == "elseif");
                            if is_condition {
                                set_successors(
                                    &mut cfg,
                                    branch.marker,
                                    &[branch.body_start, next_marker],
                                );
                            } else {
                                set_successors(&mut cfg, branch.marker, &[branch.body_start]);
                            }
                            if let Some(tail) = cfg_tail(
                                self,
                                function.id,
                                branch.body_start,
                                next_marker,
                                tokens,
                                significant,
                            ) {
                                set_successors(&mut cfg, tail, &[after_end]);
                            }
                        }
                    }
                    CfgBlockKind::Loop {
                        header, body_start, ..
                    } => {
                        set_successors(&mut cfg, *header, &[*body_start, after_end]);
                        if let Some(tail) = cfg_tail(
                            self,
                            function.id,
                            *body_start,
                            block_end,
                            tokens,
                            significant,
                        ) {
                            set_successors(&mut cfg, tail, &[*header]);
                        }
                    }
                    CfgBlockKind::Repeat { header, body_start } => {
                        set_successors(&mut cfg, *header, &[*body_start]);
                        if let Some(tail) = cfg_tail(
                            self,
                            function.id,
                            *body_start,
                            block_end,
                            tokens,
                            significant,
                        ) {
                            set_successors(&mut cfg, tail, &[block_end]);
                        }
                        set_successors(&mut cfg, block_end, &[after_end, *body_start]);
                    }
                    CfgBlockKind::Do => {}
                }
            }

            for position in start..end {
                let Some(token_index) = significant.get(position).copied() else {
                    continue;
                };
                if self
                    .enclosing_function(token_index)
                    .is_some_and(|owner| owner != function.id)
                {
                    continue;
                }
                match tokens[token_index].text.as_str() {
                    "return"
                        if matches!(ast_controls.get(&position), Some(AstControlKind::Return)) =>
                    {
                        set_successors(&mut cfg, position, &[])
                    }
                    "break" => {
                        if let Some(loop_block) = blocks
                            .iter()
                            .filter(|block| {
                                block.end.is_some_and(|block_end| {
                                    block_end > position
                                        && matches!(
                                            &block.kind,
                                            CfgBlockKind::Loop { .. } | CfgBlockKind::Repeat { .. }
                                        )
                                })
                            })
                            .min_by_key(|block| block.end.unwrap_or(end))
                        {
                            set_successors(
                                &mut cfg,
                                position,
                                &[loop_block.end.unwrap_or(end) + 1],
                            );
                        }
                    }
                    "continue" => {
                        if let Some(loop_block) = blocks
                            .iter()
                            .filter(|block| {
                                block.end.is_some_and(|block_end| {
                                    block_end > position
                                        && matches!(
                                            &block.kind,
                                            CfgBlockKind::Loop { .. } | CfgBlockKind::Repeat { .. }
                                        )
                                })
                            })
                            .min_by_key(|block| block.end.unwrap_or(end))
                        {
                            let target = match &loop_block.kind {
                                CfgBlockKind::Loop { header, .. }
                                | CfgBlockKind::Repeat { header, .. } => *header,
                                _ => position + 1,
                            };
                            set_successors(&mut cfg, position, &[target]);
                        }
                    }
                    _ => {}
                }
            }
            self.cfgs.insert(function.id, cfg);
        }
    }

    fn associate_callbacks(&mut self, tokens: &[LexToken], significant: &[usize]) {
        self.remote_endpoints.clear();
        let by_function_token = self
            .functions
            .iter()
            .map(|function| (function.function_token, function.id))
            .collect::<HashMap<_, _>>();
        let mut function_names = HashMap::<String, Vec<FunctionId>>::new();
        for function in &self.functions {
            if let Some(name) = function_name(tokens, significant, function.function_token) {
                function_names.entry(name).or_default().push(function.id);
            }
        }

        for position in 0..significant.len().saturating_sub(4) {
            let signal_index = significant[position];
            // `OnServerEvent:Connect(...)` is a property access in the
            // Roblox form (`Remote.OnServerEvent` or `self.OnServerEvent`).
            // Requiring the preceding separator prevents a local variable
            // literally named `OnServerEvent` from being mistaken for a
            // RemoteEvent endpoint.
            if position == 0
                || !matches!(tokens[significant[position - 1]].text.as_str(), "." | ":")
            {
                continue;
            }
            let Some(separator) = significant.get(position + 1) else {
                continue;
            };
            if !matches!(tokens[*separator].text.as_str(), "." | ":") {
                continue;
            }
            let Some(method_index) = significant.get(position + 2) else {
                continue;
            };
            if !matches!(tokens[*method_index].text.as_str(), "Connect" | "connect") {
                continue;
            }
            let Some(open_index) = significant.get(position + 3) else {
                continue;
            };
            if tokens[*open_index].text != "(" {
                continue;
            }
            let Some(handler_position) = significant.get(position + 4).copied() else {
                continue;
            };
            let function_id = if tokens[handler_position].text == "function" {
                by_function_token.get(&handler_position).copied()
            } else {
                self.resolve_callback_name(tokens, significant, handler_position, &function_names)
            };
            let Some(function_id) = function_id else {
                continue;
            };
            self.record_endpoint(
                tokens[signal_index].text.clone(),
                tokens[*method_index].text.clone(),
                function_id,
                signal_index,
                handler_position,
            );
        }

        // OnServerInvoke is assigned a function rather than connected with
        // `:Connect`.  Match both inline and named handlers while preserving
        // the same lexical resolution used for OnServerEvent.
        for position in 0..significant.len().saturating_sub(2) {
            let signal_index = significant[position];
            if tokens[signal_index].text != "OnServerInvoke"
                || tokens[significant[position + 1]].text != "="
                || position < 2
                || !matches!(tokens[significant[position - 1]].text.as_str(), "." | ":")
            {
                continue;
            }
            let handler_position = significant[position + 2];
            let function_id = if tokens[handler_position].text == "function" {
                by_function_token.get(&handler_position).copied()
            } else {
                self.resolve_callback_name(tokens, significant, handler_position, &function_names)
            };
            let Some(function_id) = function_id else {
                continue;
            };
            self.record_endpoint(
                tokens[signal_index].text.clone(),
                "=".into(),
                function_id,
                signal_index,
                handler_position,
            );
        }
    }

    fn record_endpoint(
        &mut self,
        signal_name: String,
        method: String,
        function_id: FunctionId,
        signal_token: usize,
        handler_token: usize,
    ) {
        if self.remote_endpoints.iter().any(|endpoint| {
            endpoint.signal_token == signal_token
                && endpoint.function_id == function_id
                && endpoint.method == method
        }) {
            return;
        }
        self.remote_endpoints.push(RemoteEndpointFact {
            signal_name: signal_name.clone(),
            method: method.clone(),
            function_id,
            signal_token,
            handler_token,
        });
        // Keep the legacy callback fields populated for callers that only
        // need one callback context (and for backwards-compatible plugins).
        if let Some(function) = self.functions.get_mut(function_id.0) {
            if function.callback_signal.is_none() {
                function.callback_signal = Some(signal_name);
                function.callback_signal_token = Some(signal_token);
                function.callback_method = Some(method);
            }
        }
    }

    fn resolve_callback_name(
        &self,
        tokens: &[LexToken],
        _significant: &[usize],
        handler_token: usize,
        function_names: &HashMap<String, Vec<FunctionId>>,
    ) -> Option<FunctionId> {
        let name = tokens.get(handler_token)?.text.as_str();
        let byte = tokens.get(handler_token)?.range.start.byte;
        let binding = self.binding_for_token(handler_token);
        if binding.is_some_and(|id| {
            self.binding(id)
                .is_some_and(|declaration| declaration.kind != BindingKind::LocalFunction)
        }) {
            // A resolved local value/function expression is not enough proof
            // that it refers to a named declaration. Decline instead of
            // falling back to an unrelated global function with the same name.
            return None;
        }
        let candidates = function_names.get(name)?;
        candidates
            .iter()
            .copied()
            .filter(|id| {
                let Some(function) = self.function(*id) else {
                    return false;
                };
                if function.range.start.byte > byte {
                    return false;
                }
                if let Some(binding) = binding {
                    let Some(declaration) = self.binding(binding) else {
                        return false;
                    };
                    declaration.kind == BindingKind::LocalFunction
                        && declaration.name == name
                        && self
                            .is_scope_inside(self.scope_at_token(handler_token), declaration.scope)
                } else {
                    true
                }
            })
            .min_by_key(|id| {
                self.function(*id)
                    .map(|function| {
                        (
                            function
                                .range
                                .end
                                .byte
                                .saturating_sub(function.range.start.byte),
                            std::cmp::Reverse(function.range.start.byte),
                        )
                    })
                    .unwrap_or((usize::MAX, std::cmp::Reverse(0)))
            })
            .or_else(|| {
                // A named global function has no lexical BindingFact in the
                // current resolver; fall back to its nearest prior definition.
                candidates
                    .iter()
                    .copied()
                    .filter(|id| {
                        self.function(*id)
                            .is_some_and(|function| function.range.start.byte <= byte)
                    })
                    .max_by_key(|id| {
                        self.function(*id)
                            .map(|function| function.range.start.byte)
                            .unwrap_or_default()
                    })
            })
        // A forward reference with no lexical binding is not proof that
        // the handler value exists when the connection runs. The prior
        // declaration filter above therefore intentionally leaves this
        // unresolved instead of associating an unrelated same-name
        // function.
    }

    fn is_scope_inside(&self, inner: ScopeId, outer: ScopeId) -> bool {
        let mut current = Some(inner);
        while let Some(scope) = current {
            if scope == outer {
                return true;
            }
            current = self.scopes.get(scope.0).and_then(|fact| fact.parent);
        }
        false
    }

    fn scope_depth(&self, scope: ScopeId) -> usize {
        let mut depth = 0;
        let mut current = Some(scope);
        while let Some(id) = current {
            depth += 1;
            current = self.scopes.get(id.0).and_then(|fact| fact.parent);
        }
        depth
    }
}

fn function_name(
    tokens: &[LexToken],
    significant: &[usize],
    function_token: usize,
) -> Option<String> {
    let position = significant
        .iter()
        .position(|token_index| *token_index == function_token)?;
    let open = (position + 1..significant.len())
        .find(|candidate| tokens[significant[*candidate]].text == "(")?;
    let identifiers = significant
        .iter()
        .copied()
        .skip(position + 1)
        .take(open.saturating_sub(position + 1))
        .filter(|token_index| tokens[*token_index].kind == LexKind::Identifier)
        .map(|token_index| tokens[token_index].text.clone())
        .collect::<Vec<_>>();
    identifiers.last().cloned()
}

/// Return the lexical target identifiers immediately to the left of an
/// assignment operator.  The previous implementation collected every
/// identifier while walking backwards, which made a type annotation such as
/// `value: number = ...` look like two targets and made member writes appear
/// to rebind their receiver.  Segmenting the LHS at top-level commas keeps
/// aliases and typed targets precise while declining table/member targets.
fn assignment_target_positions(
    tokens: &[LexToken],
    significant: &[usize],
    operator_position: usize,
) -> Vec<usize> {
    let mut start = operator_position;
    let mut nesting = 0usize;
    while start > 0 {
        let candidate = start - 1;
        let token = &tokens[significant[candidate]];
        match token.text.as_str() {
            ")" | "]" | "}" => nesting += 1,
            "(" | "[" | "{" if nesting > 0 => nesting -= 1,
            ";" | "then" | "do" | "else" | "elseif" | "end" | "until" | "local" | "return"
            | "for" | "while" | "if" | "repeat"
                if nesting == 0 =>
            {
                break;
            }
            _ => {}
        }
        start = candidate;
    }

    let mut segments = Vec::<StdRange<usize>>::new();
    let mut segment_start = start;
    nesting = 0;
    for position in start..operator_position {
        let token = &tokens[significant[position]];
        match token.text.as_str() {
            "(" | "[" | "{" => nesting += 1,
            ")" | "]" | "}" => nesting = nesting.saturating_sub(1),
            "," if nesting == 0 => {
                segments.push(segment_start..position);
                segment_start = position + 1;
            }
            _ => {}
        }
    }
    segments.push(segment_start..operator_position);

    segments
        .into_iter()
        .filter_map(|segment| {
            let mut nesting = 0usize;
            let mut saw_member_or_index = false;
            let mut candidate = None;
            for position in segment {
                let token = &tokens[significant[position]];
                match token.text.as_str() {
                    "(" | "[" | "{" => {
                        nesting += 1;
                        if token.text != "(" {
                            saw_member_or_index = true;
                        }
                    }
                    ")" | "]" | "}" => nesting = nesting.saturating_sub(1),
                    "." if nesting == 0 => saw_member_or_index = true,
                    _ if nesting == 0
                        && candidate.is_none()
                        && token.kind == LexKind::Identifier
                        && !is_keyword(token.text.as_str()) =>
                    {
                        // Return the position in the significant-token slice,
                        // not the raw token index.  Callers use that position
                        // to resolve the matching token consistently.
                        candidate = Some(position);
                    }
                    _ => {}
                }
            }
            (!saw_member_or_index).then_some(candidate).flatten()
        })
        .collect()
}

fn to_range(
    (start, end): (
        full_moon::tokenizer::Position,
        full_moon::tokenizer::Position,
    ),
) -> Range {
    Range {
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
    }
}

fn matching_symbol(
    tokens: &[LexToken],
    significant: &[usize],
    start: usize,
    open: &str,
    close: &str,
) -> Option<usize> {
    let mut depth = 0usize;
    for position in start..significant.len() {
        match tokens[significant[position]].text.as_str() {
            value if value == open => depth += 1,
            value if value == close => {
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

fn statement_end(
    significant: &[usize],
    tokens: &[LexToken],
    start: usize,
    function_end: usize,
) -> usize {
    let mut paren_depth = 0usize;
    let mut position = start;
    while position < function_end {
        let token = &tokens[significant[position]];
        match token.text.as_str() {
            "(" | "{" | "[" => paren_depth += 1,
            ")" | "}" | "]" => paren_depth = paren_depth.saturating_sub(1),
            ";" if paren_depth == 0 => return position,
            "end" | "else" | "elseif" | "until" if paren_depth == 0 => return position,
            _ if paren_depth == 0
                && position > start
                && token.range.start.line > tokens[significant[start - 1]].range.start.line
                && !matches!(
                    tokens[significant[position - 1]].text.as_str(),
                    "," | "." | ":"
                ) =>
            {
                return position;
            }
            _ => {}
        }
        position += 1;
    }
    function_end
}

/// Split an assignment RHS into top-level expressions.  Parenthesized,
/// table, and indexed expressions keep their internal commas in one segment.
fn assignment_rhs_segments(
    significant: &[usize],
    tokens: &[LexToken],
    start: usize,
    function_end: usize,
) -> Vec<StdRange<usize>> {
    let end = statement_end(significant, tokens, start, function_end);
    if start >= end {
        return Vec::new();
    }
    let mut segments = Vec::new();
    let mut segment_start = start;
    let mut nesting = 0usize;
    for position in start..end {
        match tokens[significant[position]].text.as_str() {
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

fn find_after_keyword(
    tokens: &[LexToken],
    significant: &[usize],
    start: usize,
    end: usize,
    keyword: &str,
) -> Option<usize> {
    (start..end).find(|position| {
        significant
            .get(*position)
            .and_then(|token| tokens.get(*token))
            .is_some_and(|token| token.text == keyword)
    })
}

fn set_successors(cfg: &mut FunctionCfg, position: usize, targets: &[usize]) {
    if position < cfg.start || position >= cfg.end {
        return;
    }
    let local = position - cfg.start;
    let terminal = cfg.end - cfg.start;
    let mut successors = targets
        .iter()
        .map(|target| {
            if *target >= cfg.end {
                terminal
            } else {
                target.saturating_sub(cfg.start)
            }
        })
        .filter(|target| *target <= terminal)
        .collect::<Vec<_>>();
    successors.sort_unstable();
    successors.dedup();
    cfg.successors[local] = successors;
}

fn cfg_tail(
    semantic: &SemanticIndex,
    function: FunctionId,
    start: usize,
    boundary: usize,
    tokens: &[LexToken],
    significant: &[usize],
) -> Option<usize> {
    let tail = (start..boundary).rev().find(|position| {
        significant
            .get(*position)
            .copied()
            .is_some_and(|token_index| {
                semantic
                    .enclosing_function(token_index)
                    .is_none_or(|owner| owner == function)
            })
    })?;
    let token = tokens.get(*significant.get(tail)?)?;
    (!matches!(
        token.text.as_str(),
        "if" | "elseif" | "else" | "then" | "do" | "repeat" | "until"
    ))
    .then_some(tail)
}

fn join_into(
    target: &mut HashMap<BindingId, TaintState>,
    incoming: &HashMap<BindingId, TaintState>,
) -> bool {
    let mut changed = false;
    for (binding, state) in incoming {
        let current = target.get(binding).copied().unwrap_or(TaintState::Clean);
        let joined = current.join(*state);
        if joined != current {
            target.insert(*binding, joined);
            changed = true;
        }
    }
    changed
}

fn is_assignment_operator(token: &LexToken) -> bool {
    matches!(
        token.text.as_str(),
        "=" | "+=" | "-=" | "*=" | "/=" | "//=" | "%=" | "^=" | "..="
    )
}

fn is_keyword(value: &str) -> bool {
    matches!(
        value,
        "and"
            | "break"
            | "continue"
            | "do"
            | "else"
            | "elseif"
            | "end"
            | "export"
            | "for"
            | "function"
            | "if"
            | "in"
            | "local"
            | "not"
            | "or"
            | "repeat"
            | "return"
            | "then"
            | "until"
            | "while"
    )
}

fn is_known_global(value: &str) -> bool {
    matches!(
        value,
        "game"
            | "workspace"
            | "script"
            | "math"
            | "table"
            | "string"
            | "task"
            | "warn"
            | "error"
            | "print"
            | "pairs"
            | "ipairs"
            | "pcall"
            | "xpcall"
            | "type"
            | "typeof"
            | "require"
    )
}

impl SemanticIndex {
    /// Return the project-level scope associated with a relative path.
    /// This convenience keeps rule code from duplicating config lookups.
    pub fn configured_scope(&self, _path: &str, scope: ScopeKind) -> ScopeKind {
        scope
    }
}
