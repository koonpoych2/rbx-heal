use rbx_heal_core::{engine::scan, Config};
use rbx_heal_rules::built_in_rules;
use std::{fs, time::Instant};
use tempfile::tempdir;

fn scan_corpus(loc: usize) -> u128 {
    let dir = tempdir().unwrap();
    let source_dir = dir.path().join("src");
    fs::create_dir_all(&source_dir).unwrap();
    // Keep real functions, remote callbacks, lexical scopes and branches in
    // the corpus so this gate exercises the semantic index rather than only
    // lexer throughput.
    let template = r#"local Remote = {}
Remote.OnServerEvent:Connect(function(player, amount)
    local alias = amount
    if amount then
        alias = amount + 1
    else
        alias = 0
    end
    for index = 1, 4 do
        local nested = alias + index
        if nested > 0 then
            print(nested)
        end
    end
end)
"#;
    let lines = template.repeat((200 / template.lines().count()).max(1));
    let files = (loc / 200).max(1);
    for index in 0..files {
        fs::write(source_dir.join(format!("Module{index}.luau")), &lines).unwrap();
    }
    let rules = built_in_rules();
    let mut timings = Vec::new();
    // Warm the filesystem and parser/rule code paths before taking samples.
    scan(dir.path(), &Config::default(), &[], &rules, "performance").unwrap();
    for _ in 0..3 {
        let started = Instant::now();
        let report = scan(dir.path(), &Config::default(), &[], &rules, "performance").unwrap();
        assert_eq!(report.parse_errors, 0);
        timings.push(started.elapsed().as_millis());
    }
    timings.sort_unstable();
    timings[1]
}

#[test]
#[ignore = "release performance gate; run with cargo test --release -- --ignored"]
fn warm_cache_corpus_is_linear_and_under_two_seconds_at_100k_loc() {
    let t25 = scan_corpus(25_000);
    let t50 = scan_corpus(50_000);
    let t100 = scan_corpus(100_000);
    assert!(
        t100 < 2_000,
        "100k LOC scan took {t100} ms (25k={t25} ms, 50k={t50} ms)"
    );
    assert!(
        t100 <= t25.saturating_mul(5).saturating_add(100),
        "scan appears super-linear: 25k={t25} ms, 50k={t50} ms, 100k={t100} ms"
    );
    assert!(t50 <= t25.saturating_mul(3).saturating_add(100));
}
