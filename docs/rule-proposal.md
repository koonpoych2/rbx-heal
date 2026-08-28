# Manual rule proposal

The 0.7 learning log is metadata-only. A candidate becomes a built-in rule
only after a human review records every field below:

    rule_id: RBX-EXAMPLE-001
    pattern_id: stable_pattern_name/v1
    detector_predicate: "precise semantic predicate and decline conditions"
    evidence:
      - "indexed fact or verification result"
    positive_fixtures:
      - path: tests/fixtures/example-positive.luau
    negative_fixtures:
      - path: tests/fixtures/example-negative.luau
    precision_result:
      true_positives: 0
      false_positives: 0
      declined: 0
    pilot_delta:
      before: 0
      after: 0
    approved_by: "human reviewer"
    approved_at_utc: "YYYY-MM-DDTHH:MM:SSZ"

Do not attach source text, absolute paths, diffs, verifier output, community
posts, or an executable custom rule to a proposal. Promotion remains a
reviewed code change with positive/negative fixtures and a precision gate.
