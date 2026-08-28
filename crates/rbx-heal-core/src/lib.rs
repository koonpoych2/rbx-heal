//! Core engine for the Roblox Heal Engine.
//!
//! The core crate deliberately knows nothing about Roblox-specific rules.  It
//! owns the stable data model, Luau parsing/token indexing, project discovery,
//! safe edit application, verification and local run history.

pub mod baseline;
pub mod config;
pub mod discovery;
pub mod engine;
mod hashing;
pub mod history;
pub mod model;
pub mod parser;
pub mod path;
pub mod semantic;
pub mod suppression;
pub mod transaction;
pub mod verification;

pub use baseline::{BaselineAction, BaselineEntry, BaselineFile};
pub use config::{Config, PolicyConfig, ScopeKind, VerifyKind};
pub use engine::{scan, Rule, RuleContext, RuleExample, RuleFinding, RuleMetadata, ScanReport};
pub use history::{HistoryCounts, HistoryEvent, HistoryFinding, HistorySummary};
pub use model::{
    BaselineState, BaselineSummaryV1, Confidence, Edit, EvidenceDetail, FilePatchV1, Finding,
    FixPreviewV1, Fixability, PatchEditV1, Range, Severity,
};
pub use parser::{parse_source, AssignmentFact, CallFact, CallbackFact, IndexedFacts, ParsedFile};
pub use path::{
    canonical_project_root as canonicalize_project_root, validate_existing_file,
    validate_existing_path, validate_finding_file, validate_relative_input, PathError, ProjectPath,
};
pub use semantic::{
    AstControlFact, AstControlKind, BindingFact, BindingId, BindingKind, FunctionFact, FunctionId,
    FunctionKind, LexicalScopeKind, ReferenceFact, RemoteEndpointFact, ScopeFact, ScopeId,
    SemanticAssignmentFact, SemanticCallFact, SemanticIndex, TaintState,
};
