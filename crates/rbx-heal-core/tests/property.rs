//! Small deterministic property-style checks for the public safety contracts.
//!
//! The suite deliberately avoids a network-fetched generator dependency: the
//! values are generated from fixed tables so CI and release builds exercise
//! the same cases on every platform.

use rbx_heal_core::{
    history::baseline_fingerprint,
    model::{Edit, Position, Range},
    path::validate_relative_input,
    transaction::apply_edits,
};
use std::path::Path;

#[test]
fn generated_path_inputs_never_accept_lexical_escape() {
    let cases = [
        "../outside.luau",
        "a/../../outside.luau",
        "..\\outside.luau",
        "/absolute.luau",
        "C:/absolute.luau",
        "C:drive-relative.luau",
        "\\\\server\\share\\outside.luau",
        "src/ok.luau",
        "space ☃/ok.luau",
    ];
    for value in cases {
        let accepted = validate_relative_input(Path::new(value)).is_ok();
        let expected = !value.contains("..")
            && !value.starts_with('/')
            && !value
                .as_bytes()
                .get(0..2)
                .is_some_and(|prefix| prefix[0].is_ascii_alphabetic() && prefix[1] == b':')
            && !value.starts_with("\\\\");
        assert_eq!(accepted, expected, "path case: {value}");
    }
}

#[test]
fn generated_utf8_ranges_only_apply_on_character_boundaries() {
    let source = "é🙂money";
    for start in 0..source.len() {
        for end in start..=source.len() {
            let valid = source.is_char_boundary(start) && source.is_char_boundary(end);
            let edit = Edit::new(
                Range {
                    start: Position {
                        byte: start,
                        line: 1,
                        column: 1,
                    },
                    end: Position {
                        byte: end,
                        line: 1,
                        column: 1,
                    },
                },
                source.get(start..end).unwrap_or_default(),
                "X",
            );
            assert_eq!(
                apply_edits(source, &[edit], Path::new("fixture.luau")).is_ok(),
                valid,
                "range {start}..{end}"
            );
        }
    }
}

#[test]
fn generated_edit_ordering_is_deterministic_and_conflicts_are_rejected() {
    let source = "abcdef";
    let edits = [
        Edit::new(
            Range {
                start: Position {
                    byte: 0,
                    line: 1,
                    column: 1,
                },
                end: Position {
                    byte: 1,
                    line: 1,
                    column: 2,
                },
            },
            "a",
            "A",
        ),
        Edit::new(
            Range {
                start: Position {
                    byte: 4,
                    line: 1,
                    column: 5,
                },
                end: Position {
                    byte: 6,
                    line: 1,
                    column: 7,
                },
            },
            "ef",
            "EF",
        ),
    ];
    assert_eq!(
        apply_edits(source, &edits, Path::new("fixture.luau")).unwrap(),
        "AbcdEF"
    );
    let overlap = [
        edits[0].clone(),
        Edit::new(
            Range {
                start: Position {
                    byte: 0,
                    line: 1,
                    column: 1,
                },
                end: Position {
                    byte: 2,
                    line: 1,
                    column: 3,
                },
            },
            "ab",
            "AB",
        ),
    ];
    assert!(apply_edits(source, &overlap, Path::new("fixture.luau")).is_err());
}

#[test]
fn portable_baseline_identity_is_stable_for_generated_equivalents() {
    for ordinal in 0..32 {
        let slash = baseline_fingerprint(
            "RBX-SEC-001",
            "remote_arg_to_sensitive_sink/v2",
            "src/server\\Remote.luau",
            "function:anonymous:handler",
            "statement-digest",
            ordinal,
        );
        let forward = baseline_fingerprint(
            "RBX-SEC-001",
            "remote_arg_to_sensitive_sink/v2",
            "src/server/Remote.luau",
            "function:anonymous:handler",
            "statement-digest",
            ordinal,
        );
        assert_eq!(slash, forward);
        assert_eq!(slash.len(), 64);
    }
}
