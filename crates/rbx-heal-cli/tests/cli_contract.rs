use serde_json::Value;
use std::{fs, path::Path, process::Command};
use tempfile::tempdir;

fn run(root: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rbx-heal"))
        .arg("--project")
        .arg(root)
        .args(args)
        .output()
        .expect("rbx-heal binary should run")
}

#[test]
fn json_fix_preview_is_machine_consumable_and_read_only() {
    let dir = tempdir().unwrap();
    let source_dir = dir.path().join("src");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("Legacy.luau");
    let original = "local Players = game:service(\"Players\")\n";
    fs::write(&source_path, original).unwrap();

    let output = run(dir.path(), &["fix", "--format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["schema_version"], 1);
    assert_eq!(envelope["patches"][0]["path"], "src/Legacy.luau");
    assert_eq!(envelope["patches"][0]["rule_ids"][0], "RBX-API-002");
    assert_eq!(
        envelope["patches"][0]["edits"][0]["replacement"],
        "GetService"
    );
    assert_eq!(fs::read_to_string(&source_path).unwrap(), original);
}

#[test]
fn explain_and_doctor_have_json_contracts() {
    let dir = tempdir().unwrap();
    fs::create_dir_all(dir.path().join("src")).unwrap();
    let explain = run(dir.path(), &["explain", "RBX-API-002", "--format", "json"]);
    assert!(explain.status.success());
    let explain_json: Value = serde_json::from_slice(&explain.stdout).unwrap();
    assert_eq!(explain_json["schema_version"], 1);
    assert_eq!(explain_json["id"], "RBX-API-002");
    assert!(explain_json["semantic_pattern"].is_string());

    let doctor = run(dir.path(), &["doctor", "--format", "json"]);
    assert!(doctor.status.success());
    let doctor_json: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(doctor_json["schema_version"], 1);
    assert!(doctor_json["checks"].is_array());
}

#[test]
fn safe_write_commits_only_after_the_previewed_edit() {
    let dir = tempdir().unwrap();
    let source_dir = dir.path().join("src");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("Legacy.luau");
    fs::write(&source_path, "local Players = game:service(\"Players\")\n").unwrap();

    let output = run(dir.path(), &["fix", "--write", "--format", "json"]);
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["schema_version"], 1);
    assert_eq!(envelope["patches"][0]["path"], "src/Legacy.luau");
    assert!(fs::read_to_string(&source_path)
        .unwrap()
        .contains("game:GetService(\"Players\")"));
}

#[test]
fn json_fix_noop_still_contains_an_empty_patch_array() {
    let dir = tempdir().unwrap();
    let source_dir = dir.path().join("src");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("Clean.luau"), "return 1\n").unwrap();

    let output = run(dir.path(), &["fix", "--format", "json"]);
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["schema_version"], 1);
    assert_eq!(envelope["patches"].as_array().map(Vec::len), Some(0));
}

#[test]
fn absolute_scan_input_is_rejected_at_project_boundary() {
    let project = tempdir().unwrap();
    fs::create_dir_all(project.path().join("src")).unwrap();
    let outside = tempdir().unwrap();
    let outside_file = outside.path().join("outside.luau");
    fs::write(&outside_file, "return 1\n").unwrap();
    let output = run(
        project.path(),
        &["check", outside_file.to_str().expect("utf8 path")],
    );
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn baseline_ratchets_without_hiding_existing_findings() {
    let dir = tempdir().unwrap();
    let source_dir = dir.path().join("src/server");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("Remote.server.luau");
    fs::write(
        &source_path,
        "local R = {}\nR.OnServerEvent:Connect(function(player) grant(player) end)\n",
    )
    .unwrap();

    let create = run(
        dir.path(),
        &[
            "baseline",
            "create",
            "--write",
            "--reason",
            "existing debt reviewed",
            "--format",
            "json",
        ],
    );
    assert!(create.status.success(), "{:?}", create.stderr);
    assert!(dir.path().join(".rbx-heal/baseline.json").is_file());

    let check = run(dir.path(), &["check", "--format", "json"]);
    assert!(check.status.success(), "{:?}", check.stderr);
    let report: Value = serde_json::from_slice(&check.stdout).unwrap();
    let matched = report["summary"]["baseline"]["matched"].as_u64().unwrap();
    assert!(matched > 0);
    assert_eq!(report["summary"]["baseline"]["new"], 0);
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|finding| finding["baseline_state"] == "matched"));

    fs::write(
        source_dir.join("New.server.luau"),
        "local R = {}\nR.OnServerEvent:Connect(function(player) grant(player) end)\n",
    )
    .unwrap();
    let check_new = run(dir.path(), &["check", "--format", "json"]);
    assert_eq!(check_new.status.code(), Some(1));
    let report_new: Value = serde_json::from_slice(&check_new.stdout).unwrap();
    assert_eq!(
        report_new["summary"]["baseline"]["new"].as_u64().unwrap(),
        matched
    );

    let audit = run(dir.path(), &["check", "--no-baseline", "--format", "json"]);
    assert_eq!(audit.status.code(), Some(1));
    let audit_report: Value = serde_json::from_slice(&audit.stdout).unwrap();
    assert!(audit_report["summary"]["baseline"].is_null());
}

#[test]
fn baseline_create_refuses_parse_errors_and_sarif_is_deterministic() {
    let dir = tempdir().unwrap();
    let source_dir = dir.path().join("src");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("Broken.server.luau"), "function(\n").unwrap();
    let create = run(
        dir.path(),
        &[
            "baseline",
            "create",
            "--write",
            "--reason",
            "should fail",
            "--format",
            "json",
        ],
    );
    assert_eq!(create.status.code(), Some(2));
    assert!(!dir.path().join(".rbx-heal/baseline.json").exists());

    fs::write(
        source_dir.join("Broken.server.luau"),
        "local R = {}\nR.OnServerEvent:Connect(function(player) grant(player) end)\n",
    )
    .unwrap();
    let sarif = run(dir.path(), &["check", "--format", "sarif"]);
    assert_eq!(sarif.status.code(), Some(1));
    let sarif_json: Value = serde_json::from_slice(&sarif.stdout).unwrap();
    assert_eq!(sarif_json["version"], "2.1.0");
    assert_eq!(sarif_json["runs"][0]["results"][0]["baselineState"], "new");
    assert!(
        sarif_json["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
            .as_str()
            .unwrap()
            .len()
            >= 64
    );
    let uri = sarif_json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        ["artifactLocation"]["uri"]
        .as_str()
        .unwrap();
    assert_eq!(uri, "src/Broken.server.luau");
    assert!(!String::from_utf8_lossy(&sarif.stdout).contains(dir.path().to_string_lossy().as_ref()));
}

#[test]
fn portable_baseline_id_survives_comments_and_whitespace() {
    let dir = tempdir().unwrap();
    let source_dir = dir.path().join("src/server");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("Remote.server.luau");
    fs::write(
        &source_path,
        "local R = {}\nR.OnServerEvent:Connect(function(player) grant(player) end)\n",
    )
    .unwrap();
    let create = run(
        dir.path(),
        &[
            "baseline",
            "create",
            "--write",
            "--reason",
            "portable identity",
        ],
    );
    assert!(create.status.success(), "{:?}", create.stderr);
    let baseline: Value = serde_json::from_str(
        &fs::read_to_string(dir.path().join(".rbx-heal/baseline.json")).unwrap(),
    )
    .unwrap();
    let first_id = baseline["entries"][0]["id"].as_str().unwrap().to_owned();

    fs::write(
        &source_path,
        "-- a comment inserted above\nlocal R = {}\n\nR.OnServerEvent:Connect(function(player) grant(player) end)\n",
    )
    .unwrap();
    let check = run(dir.path(), &["check", "--format", "json"]);
    assert!(check.status.success(), "{:?}", check.stderr);
    let report: Value = serde_json::from_slice(&check.stdout).unwrap();
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |finding| finding["baseline_id"] == first_id && finding["baseline_state"] == "matched"
        ));
}

#[test]
fn malformed_baseline_fails_closed_and_prune_removes_only_stale_entries() {
    let dir = tempdir().unwrap();
    let source_dir = dir.path().join("src");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("Legacy.luau");
    fs::write(&source_path, "local Players = game:service(\"Players\")\n").unwrap();
    let create = run(
        dir.path(),
        &[
            "baseline",
            "create",
            "--write",
            "--reason",
            "reviewed legacy API",
        ],
    );
    assert!(create.status.success());
    let baseline_path = dir.path().join(".rbx-heal/baseline.json");
    fs::remove_file(&source_path).unwrap();
    let prune = run(
        dir.path(),
        &["baseline", "prune", "--write", "--format", "json"],
    );
    assert!(prune.status.success(), "{:?}", prune.stderr);
    let pruned: Value = serde_json::from_slice(&prune.stdout).unwrap();
    assert!(pruned["action"]["stale"].as_u64().unwrap() > 0);
    assert_eq!(pruned["baseline"]["entries"].as_array().unwrap().len(), 0);

    fs::write(&baseline_path, "{not json").unwrap();
    let check = run(dir.path(), &["check", "--format", "json"]);
    assert_eq!(check.status.code(), Some(2));
    assert_eq!(fs::read_to_string(&baseline_path).unwrap(), "{not json");
}

#[test]
fn sarif_uses_relative_percent_encoded_uris_for_unicode_paths() {
    let dir = tempdir().unwrap();
    let source_dir = dir.path().join("src").join("space ☃");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(
        source_dir.join("Legacy.server.luau"),
        "local Players = game:service(\"Players\")\n",
    )
    .unwrap();
    let output = run(dir.path(), &["check", "--format", "sarif"]);
    assert_eq!(output.status.code(), Some(1));
    let repeat = run(dir.path(), &["check", "--format", "sarif"]);
    assert_eq!(repeat.status.code(), Some(1));
    assert_eq!(output.stdout, repeat.stdout);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let uris = report["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|result| {
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].as_str()
        })
        .collect::<Vec<_>>();
    assert!(uris
        .iter()
        .any(|uri| { *uri == "src/space%20%E2%98%83/Legacy.server.luau" }));
    assert!(uris
        .iter()
        .all(|uri| !uri.contains(dir.path().to_string_lossy().as_ref())));
}
