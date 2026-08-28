# GitHub CI adoption

The production-proof workflow runs on windows-2025 and ubuntu-24.04, checks the
pinned public-v1 corpus, compares portable finding identities across platforms,
and uploads a SARIF smoke report. The checked-in workflow is deliberately the
source of truth; it does not execute scripts from checked-out corpus
repositories.

These examples keep the runtime local. They do not call the GitHub API; the
SARIF upload is performed by the GitHub Actions runner after the scan.

## Generic JSON gate

Use a committed baseline to fail only on newly introduced findings while
keeping all existing findings in the uploaded job log:

~~~yaml
name: Roblox Heal
on: [push, pull_request]
permissions:
  contents: read
jobs:
  heal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803
      - uses: dtolnay/rust-toolchain@bc540ba06a4ccee415bb241490e0b25ee8e7d315
        with:
          toolchain: 1.85.0
      - run: cargo run --locked --release -- check --format json > heal-report.json
        id: heal
        continue-on-error: true
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        if: always()
        with:
          name: rbx-heal-json
          path: heal-report.json
      - if: steps.heal.outcome == 'failure'
        run: exit 1
~~~

## SARIF upload

GitHub Code Scanning accepts SARIF 2.1.0 ([SARIF support reference](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)). Keep the scan step
continue-on-error so the report is uploaded even when the policy returns exit
code 1, then restore that exit code afterwards:

~~~yaml
name: Roblox Heal SARIF
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  heal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803
      - uses: dtolnay/rust-toolchain@bc540ba06a4ccee415bb241490e0b25ee8e7d315
        with:
          toolchain: 1.85.0
      - name: Scan
        id: heal
        shell: bash
        run: |
          set +e
          cargo run --locked --release -- check --format sarif > heal.sarif
          status=$?
          echo "status=$status" >> "$GITHUB_OUTPUT"
          exit 0
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@fddeee1a7ece751b577e409a89057319e3172939
        with:
          sarif_file: heal.sarif
      - name: Enforce policy
        if: steps.heal.outputs.status != '0'
        run: exit 1
~~~

For private repositories, enable GitHub Code Security before using the SARIF
workflow. If a scan is larger than the GitHub SARIF result limit, split the
scan or use the JSON workflow instead.
