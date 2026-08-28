# Public corpus pilot

The public-v1 suite is a read-only, manifest-driven proof gate for three
open-source Roblox projects pinned to immutable commits. The source repositories
are never copied into this repository and the CLI never clones or contacts a
network service.

CI checks out each repository with credentials disabled and passes canonical
roots through:

- RBX_HEAL_PILOT_PLANT_ROOT
- RBX_HEAL_PILOT_INFECTED_ROOT
- RBX_HEAL_PILOT_ROBLOQUAKE_ROOT

Run the suite after those roots are available:

    rbx-heal pilot --suite public-v1 --format human
    rbx-heal pilot --suite public-v1 --format json

The manifest and project configs live in pilot/public-v1.toml. Review labels
and portable baseline identities live in pilot/public-v1-expectations/. Every
non-parse finding must have a reviewed verdict; Error precision must be 100
percent and Warning precision at least 90 percent. The gate also checks pinned
commit identity, SPDX license files, Luau source hashes, temporary safe-fix
behavior, Luau reparse, and a Rojo build whose output is confined to a
temporary directory.

Slime Farm remains available through the default rbx-heal pilot command for
backward compatibility, but it is private and is not a release gate.

