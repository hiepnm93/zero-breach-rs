//! A synthetic positive must be detected by each module: a known hash planted
//! in a fake tree, a test domain in a browser cache and history. A
//! clean-machine test only proves the modules return without finding anything.
//! Ported from zero-breach scan/tests/test_synthetic.py (Apache-2.0).

mod common;

use std::path::Path;

use zero_breach_rs::context::ScanContext;
use zero_breach_rs::modules::browser::{self, BrowserConfig};
use zero_breach_rs::modules::hashscan;
use zero_breach_rs::result::{ModuleResult, CLEAN, HITS, UNKNOWN};

use common::{temp_dir, TEST_DOMAIN};

fn browser_config(root: &Path) -> BrowserConfig {
    BrowserConfig {
        chromium: vec![("test".to_string(), root.to_path_buf())],
        firefox: Some(vec![]),
        snapshot: None,
    }
}

fn assert_hit_implies_hits_status(result: &ModuleResult) {
    // No module may ever report CLEAN for a run that found something.
    if !result.hits.is_empty() {
        assert_eq!(result.status(), HITS);
    }
}

#[test]
fn known_sample_hash_is_detected_exactly_once() {
    let dir = temp_dir("synhash");
    let iocs = common::synthetic_ioc_set(&dir);
    let scan_root = dir.join("fakeroot");
    std::fs::create_dir_all(&scan_root).unwrap();
    let payload = scan_root.join("payload.dll");
    std::fs::write(&payload, common::PAYLOAD_BYTES).unwrap();

    let mut ctx = common::quiet_ctx(&iocs);
    let r = hashscan::run_with(&mut ctx, vec![scan_root.clone()]);

    assert_eq!(
        r.hits.len(),
        1,
        "the synthetic sample must be found, exactly once"
    );
    let hit = &r.hits[0];
    assert_eq!(hit.indicator, common::payload_sha256());
    assert_eq!(Path::new(&hit.location), payload, "the hit names the file");
    // Provenance comes from the IOC set, not from the module.
    assert_eq!(hit.tier, "sample");
    assert_eq!(hit.confidence, "primary");
    assert!(hit.detail.contains(&common::payload_sha256()));
    assert_eq!(r.status(), HITS);
    assert_hit_implies_hits_status(&r);

    // The walked root is recorded as a check that ran.
    assert!(r
        .checks
        .iter()
        .any(|c| c.ran && c.name.contains(scan_root.to_string_lossy().as_ref())));
    assert!(r.checked >= 1);
    assert!(r.metric("files_hashed") >= 1);
}

#[test]
fn non_matching_file_is_clean_not_a_hit() {
    let dir = temp_dir("synhash2");
    let iocs = common::synthetic_ioc_set(&dir);
    let scan_root = dir.join("fakeroot");
    std::fs::create_dir_all(&scan_root).unwrap();
    std::fs::write(scan_root.join("payload.dll"), common::PAYLOAD_BYTES).unwrap();
    std::fs::write(scan_root.join("benign.dll"), b"something else entirely").unwrap();

    let mut ctx = common::quiet_ctx(&iocs);
    let r = hashscan::run_with(&mut ctx, vec![scan_root]);
    assert_eq!(r.hits.len(), 1);
    assert_eq!(r.metric("files_hashed"), 2);
}

#[test]
fn empty_hash_target_set_is_unknown_not_clean() {
    // D3: nothing to compare against is a gap, never a clean result.
    let dir = temp_dir("synhash3");
    let scan_root = dir.join("fakeroot");
    std::fs::create_dir_all(&scan_root).unwrap();
    std::fs::write(scan_root.join("payload.dll"), common::PAYLOAD_BYTES).unwrap();
    let mut iocs = common::ioc_set_from_lines(
        &dir,
        &[
            &format!("{}\tdelivery\tprimary", TEST_DOMAIN),
            &format!("{}\tsample\tprimary", "a".repeat(64)),
        ],
    );
    // Drop the hash indicators the way the Python test filtered the set.
    iocs.indicators.retain(|i| i.kind != "sha256");

    let mut ctx = common::quiet_ctx(&iocs);
    let r = hashscan::run_with(&mut ctx, vec![scan_root]);
    assert_eq!(r.status(), UNKNOWN);
    assert!(r.checks.iter().any(|c| c.name == "hash-compare" && !c.ran));
}

#[test]
fn browser_detects_the_domain_in_both_sqlite_and_blob_artifacts() {
    let dir = temp_dir("synbrowser");
    let iocs = common::synthetic_ioc_set(&dir);
    let root = dir.join("User Data");
    let profile = root.join("Default");
    let cache_dir = profile.join("Cache").join("Cache_Data");
    std::fs::create_dir_all(&cache_dir).unwrap();

    // (1) blob path: the HTTP cache entry, where a subresource ad impression
    // would actually survive (history only records top-level navigations).
    let cache_file = cache_dir.join("f_000001");
    std::fs::write(
        &cache_file,
        format!("\x00\x01HTTP/1.1 200 OK\nhost: {}\n\x00\x02", TEST_DOMAIN),
    )
    .unwrap();

    // (2) sqlite path: a real History database with the urls table.
    let history = profile.join("History");
    common::chromium_history_db(&history, &format!("https://{}/ad?id=1", TEST_DOMAIN));
    {
        use rusqlite::Connection;
        let con = Connection::open(&history).unwrap();
        con.execute("UPDATE urls SET title = 'synthetic page'", [])
            .unwrap();
    }

    let mut ctx = common::quiet_ctx(&iocs);
    let r = browser::run_with(&mut ctx, &browser_config(&root));

    assert!(!r.hits.is_empty(), "the synthetic domain must be detected");
    let sqlite_hits: Vec<&zero_breach_rs::result::Hit> = r
        .hits
        .iter()
        .filter(|h| h.detail.starts_with("history:"))
        .collect();
    let blob_hits: Vec<&zero_breach_rs::result::Hit> = r
        .hits
        .iter()
        .filter(|h| h.detail.contains("binary match"))
        .collect();
    assert!(
        !sqlite_hits.is_empty(),
        "the sqlite (History) path must detect it"
    );
    assert!(!blob_hits.is_empty(), "the cache-blob path must detect it");

    assert_eq!(
        Path::new(&sqlite_hits[0].location),
        history,
        "the sqlite hit names the History file"
    );
    assert_eq!(Path::new(&blob_hits[0].location), cache_file);
    for h in &r.hits {
        assert_eq!(h.indicator, TEST_DOMAIN);
        assert_eq!(h.tier, "delivery");
        assert_eq!(h.confidence, "primary");
    }

    // Counts scanned, not just hits, so a result is auditable.
    assert!(r.metric("sqlite") >= 1);
    assert!(r.metric("blob") >= 1);
    assert_eq!(r.status(), HITS);
    assert_hit_implies_hits_status(&r);
}

#[test]
fn installed_root_is_recorded_as_a_check_that_ran() {
    let dir = temp_dir("synbrowser2");
    let iocs = common::synthetic_ioc_set(&dir);
    let root = dir.join("User Data");
    common::chromium_history_db(
        &root.join("Default").join("History"),
        &format!("https://{}/x", TEST_DOMAIN),
    );

    let mut ctx = common::quiet_ctx(&iocs);
    let r = browser::run_with(&mut ctx, &browser_config(&root));
    let names: Vec<&str> = r.checks.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"test:history"));
    assert!(names.iter().any(|n| n.starts_with("test:")));
    assert!(
        r.checks.iter().all(|c| c.ran),
        "nothing in this readable tree should be a gap"
    );
}

#[test]
fn clean_tree_finds_nothing_and_stays_clean() {
    let dir = temp_dir("synbrowser3");
    let iocs = common::synthetic_ioc_set(&dir);
    let empty_root = dir.join("Empty User Data");
    std::fs::create_dir_all(empty_root.join("Default").join("Cache").join("Cache_Data")).unwrap();

    let mut ctx = common::quiet_ctx(&iocs);
    let r = browser::run_with(&mut ctx, &browser_config(&empty_root));
    assert!(r.hits.is_empty());
    assert_eq!(r.status(), CLEAN);
}

#[test]
fn corrupt_sqlite_file_does_not_crash_the_module() {
    // A path that exists but is not a database. The only contract asserted is
    // "did not panic" and "still returned a ModuleResult".
    let dir = temp_dir("synbrowser4");
    let iocs = common::synthetic_ioc_set(&dir);
    let root = dir.join("User Data");
    let profile = root.join("Default");
    common::chromium_history_db(
        &profile.join("History"),
        &format!("https://{}/ad?id=1", TEST_DOMAIN),
    );
    std::fs::write(profile.join("Favicons"), vec![0u8; 4096]).unwrap();

    let mut ctx = common::quiet_ctx(&iocs);
    let r = browser::run_with(&mut ctx, &browser_config(&root));
    assert!(!r.hits.is_empty(), "the real positives must still be found");
    assert_hit_implies_hits_status(&r);
}

#[test]
fn every_module_with_a_hit_reports_hits() {
    // Cross-module invariant, stated once more as its own assertion.
    let dir = temp_dir("synall");
    let iocs = common::synthetic_ioc_set(&dir);
    let mut results: Vec<ModuleResult> = Vec::new();

    let scan_root = dir.join("h");
    std::fs::create_dir_all(&scan_root).unwrap();
    std::fs::write(scan_root.join("payload.dll"), common::PAYLOAD_BYTES).unwrap();
    let mut ctx: ScanContext = common::quiet_ctx(&iocs);
    results.push(hashscan::run_with(&mut ctx, vec![scan_root]));

    let root = dir.join("ud");
    let cache = root.join("Default").join("Cache").join("Cache_Data");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("f_000001"), TEST_DOMAIN).unwrap();
    let mut ctx = common::quiet_ctx(&iocs);
    results.push(browser::run_with(&mut ctx, &browser_config(&root)));

    for r in &results {
        assert!(
            !r.hits.is_empty(),
            "{}: synthetic positive not detected",
            r.name
        );
        assert_eq!(
            r.status(),
            HITS,
            "{}: reported {} despite {} hit(s)",
            r.name,
            r.status(),
            r.hits.len()
        );
    }
}

#[test]
fn quick_mode_is_a_gap_never_a_clean_result() {
    // The --quick behaviour lives in the CLI's module loop; its contract is
    // that the skipped check reads as UNKNOWN, never as covered.
    let mut r = ModuleResult::new("hash");
    r.could_not_run(
        "file-fingerprints",
        "skipped by --quick. No file on this machine was fingerprinted",
    );
    assert_eq!(r.status(), UNKNOWN);
    assert!(r.notes.iter().any(|n| n.contains("--quick")));
}

#[test]
fn unsupported_host_module_reports_unknown_not_clean() {
    // On a non-Windows host every host check is a named gap.
    let dir = temp_dir("synhost");
    let iocs =
        common::ioc_set_from_lines(&dir, &[&format!("{}\tdelivery\tprimary\tt", TEST_DOMAIN)]);
    let mut ctx = common::quiet_ctx(&iocs);
    let r = zero_breach_rs::modules::host::run(&mut ctx);
    if cfg!(windows) {
        assert_eq!(r.status(), CLEAN);
    } else {
        assert_eq!(r.status(), UNKNOWN);
        for name in [
            "com-persistence",
            "dns-cache",
            "dns-log",
            "hosts-file",
            "known-paths",
        ] {
            let c = r.checks.iter().find(|c| c.name == name).unwrap();
            assert!(!c.ran, "{} must not claim to have run", name);
            assert!(
                c.reason.contains("not supported on"),
                "{}: {}",
                name,
                c.reason
            );
        }
    }
}
