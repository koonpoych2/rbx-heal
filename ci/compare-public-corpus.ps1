[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$WindowsReport,
    [Parameter(Mandatory = $true)]
    [string]$UbuntuReport,
    [string]$Output = ""
)

$ErrorActionPreference = "Stop"

function Read-Report([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "public corpus report is missing"
    }
    $report = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($report.schema_version -ne 1 -or $report.suite -ne "public-v1") {
        throw "public corpus report schema or suite is invalid"
    }
    return $report
}

function Comparable([object]$Report) {
    $cases = @($Report.cases | Sort-Object id | ForEach-Object {
        [ordered]@{
            id = $_.id
            repository = $_.repository
            commit = $_.commit
            license = $_.license
            status = $_.status
            files_scanned = $_.files_scanned
            # Source byte counts are deliberately not portable: Git may check
            # out LF files on Ubuntu and CRLF files on Windows.  The gate is
            # about semantic findings and identities, not checkout encoding.
            findings = $_.findings
            parse_errors = $_.parse_errors
            rule_counts = $_.rule_counts
            baseline_ids = @($_.baseline_ids | Sort-Object)
            finding_stats = [ordered]@{
                reviewed = $_.finding_stats.reviewed
                unreviewed = $_.finding_stats.unreviewed
                suppressed = $_.finding_stats.suppressed
                error_total = $_.finding_stats.error_total
                warning_total = $_.finding_stats.warning_total
                error_true_positive = $_.finding_stats.error_true_positive
                warning_true_positive = $_.finding_stats.warning_true_positive
                error_precision = $_.finding_stats.error_precision
                warning_precision = $_.finding_stats.warning_precision
                rule_counts_match = $_.finding_stats.rule_counts_match
                identities_match = $_.finding_stats.identities_match
            }
            source_unchanged = $_.source_unchanged
            temporary_fix_status = $_.temporary_fix_status
            checkout_commit = $_.checkout_commit
            official_gate_complete = $_.official_gate_complete
            expectations_passed = $_.expectations_passed
        }
    })
    return [ordered]@{
        schema_version = $Report.schema_version
        suite = $Report.suite
        cases = $cases
        cases_passed = $Report.cases_passed
        total_findings = $Report.total_findings
        total_reviewed = $Report.total_reviewed
        total_unreviewed = $Report.total_unreviewed
        official_gate_complete = $Report.official_gate_complete
        source_unchanged = $Report.source_unchanged
        expectations_passed = $Report.expectations_passed
    }
}

$windows = Read-Report $WindowsReport
$ubuntu = Read-Report $UbuntuReport
if (-not $windows.official_gate_complete -or -not $ubuntu.official_gate_complete) {
    throw "official public-v1 gate is incomplete on one or more platforms"
}
$left = (Comparable $windows | ConvertTo-Json -Depth 20 -Compress)
$right = (Comparable $ubuntu | ConvertTo-Json -Depth 20 -Compress)
if ($left -cne $right) {
    throw "public-v1 findings or portable identities differ across operating systems"
}
$result = [ordered]@{
    schema_version = 1
    suite = "public-v1"
    cross_os_deterministic = $true
    windows_cases = $windows.cases.Count
    ubuntu_cases = $ubuntu.cases.Count
    official_gate_complete = $true
    source_unchanged = $true
    findings = $windows.total_findings
}
$json = $result | ConvertTo-Json -Depth 10
if ($Output) {
    $json | Set-Content -LiteralPath $Output -Encoding utf8
}
Write-Output $json
