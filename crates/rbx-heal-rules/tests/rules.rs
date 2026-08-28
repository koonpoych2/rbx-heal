use rbx_heal_core::{
    config::Config, model::Fixability, parser::parse_source_with_path, RuleContext,
};
use rbx_heal_rules::built_in_rules;
use std::path::PathBuf;

fn findings(source: &str, path: &str) -> Vec<rbx_heal_core::model::Finding> {
    let file = parse_source_with_path(PathBuf::from(path), path.into(), source.into())
        .expect("fixture must parse");
    let mut result = Vec::new();
    let config = Config::default();
    for rule in built_in_rules() {
        let before = result.len();
        rule.analyze(
            &RuleContext {
                file: &file,
                config: &config,
            },
            &mut result,
        );
        for finding in result[before..].iter_mut() {
            if finding.fixability == Fixability::Safe {
                if let Some(edits) = rule.safe_fix(
                    &RuleContext {
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
    result
}

#[test]
fn detects_data_load_failure_default() {
    let source = include_str!("fixtures/data_failure.server.luau");
    assert!(findings(source, "src/server/data_failure.server.luau")
        .iter()
        .any(|finding| finding.rule_id == "RBX-DATA-002"));
}

#[test]
fn does_not_flag_default_after_failure_branch() {
    let source = "local ok, result = pcall(function() return store:GetAsync(key) end)\nif not ok then\n warn(result)\nend\nreturn {}\n";
    assert!(!findings(source, "src/server/DataService.luau")
        .iter()
        .any(|finding| finding.rule_id == "RBX-DATA-002"));
}

#[test]
fn detects_frame_traversal_but_not_cached_traversal() {
    let positive = include_str!("fixtures/frame_traversal.client.luau");
    let negative = include_str!("fixtures/cached_before_frame.client.luau");
    let positive_findings = findings(positive, "src/client/frame.client.luau");
    assert!(positive_findings
        .iter()
        .any(|finding| finding.rule_id == "RBX-PERF-001"));
    assert!(!findings(negative, "src/client/cached.client.luau")
        .iter()
        .any(|finding| finding.rule_id == "RBX-PERF-001"));
}

#[test]
fn safe_alias_fixes_have_expected_edits() {
    let result = findings(
        include_str!("fixtures/legacy_aliases.luau"),
        "src/server/legacy.luau",
    );
    let service = result
        .iter()
        .find(|finding| finding.rule_id == "RBX-API-002")
        .expect("service alias finding");
    assert_eq!(service.fixability, Fixability::Safe);
    assert_eq!(service.edit.as_ref().unwrap().replacement, "GetService");
    let signal = result
        .iter()
        .find(|finding| finding.rule_id == "RBX-API-001")
        .expect("signal alias finding");
    assert_eq!(signal.fixability, Fixability::Safe);
}

#[test]
fn protected_state_rule_does_not_treat_server_constant_as_remote_taint() {
    let source = "local Remote = {}\nRemote.OnServerEvent:Connect(function(player, amount)\n data.cash += 10\nend)\n";
    assert!(!findings(source, "src/server/constant.server.luau")
        .iter()
        .any(|finding| finding.rule_id == "RBX-SEC-001"));
}

#[test]
fn malformed_fixture_is_rejected_by_parser() {
    assert!(parse_source_with_path(
        PathBuf::from("bad.luau"),
        "bad.luau".into(),
        include_str!("fixtures/malformed.luau").into()
    )
    .is_err());
}
