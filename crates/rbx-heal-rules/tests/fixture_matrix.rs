use rbx_heal_core::{
    config::{Config, PathSuppression},
    model::Finding,
    parser::parse_source_with_path,
    suppression::apply_suppressions,
    RuleContext,
};
use rbx_heal_rules::built_in_rules;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct FixtureCase {
    rule: String,
    positive: String,
    negative: String,
    positive_path: String,
    negative_path: String,
}

fn rule_findings(rule_id: &str, fixture: &str, relative_path: &str) -> Vec<Finding> {
    let source = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(fixture),
    )
    .expect("fixture must be readable");
    let file = parse_source_with_path(PathBuf::from(fixture), relative_path.to_owned(), source)
        .expect("fixture must parse");
    let config = Config::default();
    let rule = built_in_rules()
        .into_iter()
        .find(|rule| rule.id() == rule_id)
        .expect("manifest rule must be built in");
    let mut findings = Vec::new();
    rule.analyze(
        &RuleContext {
            file: &file,
            config: &config,
        },
        &mut findings,
    );
    findings
}

#[test]
fn manifest_covers_positive_and_negative_examples_for_every_rule() {
    let cases: Vec<FixtureCase> = serde_json::from_str(include_str!("fixtures/matrix.json"))
        .expect("fixture matrix must be valid JSON");
    assert_eq!(cases.len(), 12);
    for case in cases {
        assert!(
            !rule_findings(&case.rule, &case.positive, &case.positive_path).is_empty(),
            "positive fixture {} did not trigger {}",
            case.positive,
            case.rule
        );
        assert!(
            rule_findings(&case.rule, &case.negative, &case.negative_path).is_empty(),
            "negative fixture {} triggered {}",
            case.negative,
            case.rule
        );
    }
}

#[test]
fn malformed_reference_fixture_is_rejected() {
    let source = include_str!("fixtures/malformed.luau");
    assert!(parse_source_with_path(
        PathBuf::from("malformed.luau"),
        "src/server/malformed.luau".into(),
        source.to_owned(),
    )
    .is_err());
}

#[test]
fn inline_and_config_suppressions_require_reasons() {
    let source = include_str!("fixtures/suppressed_frame.client.luau");
    let file = parse_source_with_path(
        PathBuf::from("suppressed_frame.client.luau"),
        "src/client/suppressed_frame.client.luau".into(),
        source.to_owned(),
    )
    .unwrap();
    let config = Config::default();
    let rule = built_in_rules()
        .into_iter()
        .find(|rule| rule.id() == "RBX-PERF-001")
        .unwrap();
    let mut findings = Vec::new();
    rule.analyze(
        &RuleContext {
            file: &file,
            config: &config,
        },
        &mut findings,
    );
    assert_eq!(findings.len(), 1);
    apply_suppressions(&mut findings[0], &file, &config);
    assert!(findings[0].suppressed);
    assert_eq!(
        findings[0].suppression_reason.as_deref(),
        Some("bounded by the scene contract")
    );

    let mut config = Config::default();
    config.suppressions.push(PathSuppression {
        rule: "RBX-PERF-001".into(),
        path: "src/client/**".into(),
        reason: "reviewed bounded traversal".into(),
    });
    // Move the finding away from the inline marker so this second assertion
    // exercises the path-level suppression independently.
    let mut finding = findings.remove(0);
    finding.suppressed = false;
    finding.suppression_reason = None;
    finding.range.start.line = 1;
    apply_suppressions(&mut finding, &file, &config);
    assert!(finding.suppressed);
    assert_eq!(
        finding.suppression_reason.as_deref(),
        Some("reviewed bounded traversal")
    );
}

#[test]
fn typed_unicode_path_preserves_remote_flow_and_utf8_ranges() {
    let fixture = "space ☃/unicode.server.luau";
    let source = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(fixture),
    )
    .unwrap();
    let file =
        parse_source_with_path(PathBuf::from(fixture), format!("src/{fixture}"), source).unwrap();
    let config = Config::default();
    let rule = built_in_rules()
        .into_iter()
        .find(|rule| rule.id() == "RBX-SEC-001")
        .unwrap();
    let mut findings = Vec::new();
    rule.analyze(
        &RuleContext {
            file: &file,
            config: &config,
        },
        &mut findings,
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, format!("src/{fixture}"));
    assert!(findings[0].range.start.byte < file.source.len());
}
