# Slime Farm pilot (legacy local acceptance check)

The pilot is intentionally read-only against the existing game repository:

```powershell
rbx-heal pilot --format human
rbx-heal pilot --format json
```

Set `RBX_HEAL_SLIME_FARM_ROOT` to override the default `..\Slime farm` root.
The runner reads `pilot/slime-farm.toml` and the expectation manifest, but does
not add configuration or generated files to the game repository.

Representative findings from the current source:

- `RBX-DATA-002` identifies the load-failure branch in `DataService` that returns a fresh default profile.
- `RBX-NET-001` identifies both server remotes in `Main.server.luau` that lack a configured anti-spam guard.
- `RBX-ARCH-001` identifies direct protected-state writes outside `EconomyService` for review.
- `RBX-TYPE-001` reports production modules without `--!strict` as informational findings.

The acceptance run on 2026-08-28 scanned 16 files (64,123 bytes) in about 66 ms,
with 18 findings and no parse errors: `RBX-DATA-002` (1), `RBX-LIFE-001` (1),
`RBX-NET-001` (2), `RBX-ARCH-001` (4), and `RBX-TYPE-001` (10). The two
DataStore calls are inside the configured `pcall` boundaries, so
`RBX-DATA-003` correctly reports zero findings in this pilot.

The pilot also provides negative evidence: `DataService` is accepted as a DataStore owner, and the `GetDescendants` calls that populate caches before `RenderStepped` are not reported as frame traversal.

Safe-fix behavior is tested on a temporary copy. The source hash map is checked
before and after every run; the existing `Slime Farm` files are never modified.
The official gate is complete only when all Luau files reparse and a real Rojo
binary completes `rojo build`. If Rojo is missing or resolves to an Aftman shim,
the report says `official_gate_complete: false` instead of silently claiming a
full pilot pass.

The release CI checks out commit `3a43723be2651da45e0f353f77d583b3fc427d66`
from `koonpoych2/RBX-Slime-farm`, installs the pinned official tools from
`ci/tools.lock.json`, and requires `official_gate_complete: true` on Windows.
The Ubuntu job exercises the same scan and process/verification path for
portability. Both jobs assert that the source hash map is identical before and
after the run; the synthetic safe-fix and rollback exercise runs only on a
temporary copy.
