# Codex integration

Use the CLI from a Roblox project root. It emits stable JSON so Codex can consume findings without an LLM-to-LLM protocol.

```powershell
rbx-heal check --format json
rbx-heal baseline create --write --reason "reviewed existing debt"
rbx-heal fix
rbx-heal fix --write
rbx-heal check --format json
```

For an agent that needs a structured patch, use the single JSON envelope from
`rbx-heal fix --format json`; each patch includes relative path, original and
candidate hashes, byte ranges, expected text, and replacement text. Human mode
renders the same edits as a unified diff.

Recommended project instruction:

```text
Run `rbx-heal check --format json` before changing Luau.
Use `rbx-heal check --no-baseline --format json` when auditing all debt.
Never update a baseline automatically; use `baseline prune --write` only
after reviewing resolved entries.
After changing Luau, run `rbx-heal fix` and review the preview.
Only use `rbx-heal fix --write` for findings marked safe.
Resolve remaining security/data findings with server-authoritative code.
Finish with `rbx-heal check --format json` and the project's verification command.
```

The tool never sends source to a service. `history` contains only local hashes, rule IDs, outcomes and timings.

The public rule API receives `RuleContext` and returns findings plus optional
guarded `Vec<Edit>` safe fixes. Suggested fixes remain metadata-only, so an
agent can reason about them without accidentally entering the write transaction.
