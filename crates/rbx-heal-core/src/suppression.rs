use crate::{config::Config, model::Finding, parser::ParsedFile};
use globset::{Glob, GlobSetBuilder};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct InlineSuppression {
    pub rule: String,
    pub line: usize,
    pub reason: String,
}

pub fn parse_inline(source: &str) -> Vec<InlineSuppression> {
    source
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let marker = "-- rbx-heal: ignore ";
            let start = line.find(marker)? + marker.len();
            let rest = &line[start..];
            let (rule, reason) = rest.split_once(" -- ")?;
            let rule = rule.trim();
            let reason = reason.trim();
            if rule.is_empty() || reason.is_empty() {
                return None;
            }
            Some(InlineSuppression {
                rule: rule.into(),
                line: index + 1,
                reason: reason.into(),
            })
        })
        .collect()
}

pub fn apply_suppressions(finding: &mut Finding, file: &ParsedFile, config: &Config) {
    let inline = parse_inline(&file.source);
    let line = finding.range.start.line;
    if let Some(suppression) = inline
        .iter()
        .find(|item| item.rule == finding.rule_id && item.line + 1 == line)
    {
        finding.suppressed = true;
        finding.suppression_reason = Some(suppression.reason.clone());
        finding.suppression_origin = Some("inSource".into());
        return;
    }

    let mut builder = GlobSetBuilder::new();
    let mut matches = Vec::new();
    for suppression in &config.suppressions {
        if suppression.rule == finding.rule_id || suppression.rule == "*" {
            if let Ok(glob) = Glob::new(&suppression.path) {
                builder.add(glob);
                matches.push(suppression);
            }
        }
    }
    if let Ok(set) = builder.build() {
        if set.is_match(&finding.path) {
            let reason = matches
                .into_iter()
                .find(|item| {
                    Glob::new(&item.path)
                        .ok()
                        .is_some_and(|glob| glob.compile_matcher().is_match(&finding.path))
                })
                .map(|item| item.reason.clone());
            finding.suppressed = true;
            finding.suppression_reason = reason;
            finding.suppression_origin = Some("external".into());
        }
    }
}

pub fn suppression_summary(findings: &[Finding]) -> HashMap<String, usize> {
    findings.iter().filter(|finding| finding.suppressed).fold(
        HashMap::new(),
        |mut summary, finding| {
            *summary.entry(finding.rule_id.clone()).or_default() += 1;
            summary
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Config, PathSuppression},
        model::{Confidence, Position, Range, Severity},
        parser::parse_source_with_path,
    };
    use std::path::PathBuf;

    #[test]
    fn inline_suppression_applies_only_to_adjacent_statement() {
        let source =
            "-- rbx-heal: ignore RBX-TEST-001 -- bounded\nlocal value = 1\nlocal other = 2\n";
        let file = parse_source_with_path(
            PathBuf::from("fixture.luau"),
            "fixture.luau".into(),
            source.into(),
        )
        .unwrap();
        let mut finding = Finding::new(
            "RBX-TEST-001",
            "test",
            Severity::Warning,
            Confidence::High,
            "fixture.luau",
            Range {
                start: Position {
                    line: 2,
                    column: 1,
                    byte: 42,
                },
                end: Position {
                    line: 2,
                    column: 6,
                    byte: 47,
                },
            },
            "test",
        );
        apply_suppressions(&mut finding, &file, &Config::default());
        assert!(finding.suppressed);
        assert_eq!(finding.suppression_reason.as_deref(), Some("bounded"));
    }

    #[test]
    fn config_suppression_requires_matching_path_and_rule() {
        let source = "local value = 1\n";
        let file = parse_source_with_path(
            PathBuf::from("fixture.luau"),
            "src/fixture.luau".into(),
            source.into(),
        )
        .unwrap();
        let mut config = Config::default();
        config.suppressions.push(PathSuppression {
            rule: "RBX-TEST-001".into(),
            path: "src/**".into(),
            reason: "intentional".into(),
        });
        let mut finding = Finding::new(
            "RBX-TEST-001",
            "test",
            Severity::Warning,
            Confidence::High,
            "src/fixture.luau",
            Range::default(),
            "test",
        );
        apply_suppressions(&mut finding, &file, &config);
        assert!(finding.suppressed);
    }

    #[test]
    fn inline_marker_on_same_line_does_not_suppress_that_statement() {
        let source = "local value = 1 -- rbx-heal: ignore RBX-TEST-001 -- too late\n";
        let file = parse_source_with_path(
            PathBuf::from("fixture.luau"),
            "fixture.luau".into(),
            source.into(),
        )
        .unwrap();
        let mut finding = Finding::new(
            "RBX-TEST-001",
            "test",
            Severity::Warning,
            Confidence::High,
            "fixture.luau",
            Range::default(),
            "test",
        );
        apply_suppressions(&mut finding, &file, &Config::default());
        assert!(!finding.suppressed);
    }
}
