//! How far back a scan could see must be reported, and honestly bounded:
//! overlap statements, cache-age summaries and the oldest-cookie window.
//! Ported from zero-breach scan/tests/test_reach.py (Apache-2.0).

mod common;

use std::path::Path;

use zero_breach_rs::datetime::{days_from_civil, CivilDate};
use zero_breach_rs::modules::browser::{self, BrowserConfig};
use zero_breach_rs::report::{overlap_statement, CAMPAIGN_FROM, CAMPAIGN_TO};

use common::{temp_dir, TEST_DOMAIN};

#[test]
fn evidence_after_campaign_end_says_no_overlap() {
    let lines = overlap_statement(
        CivilDate {
            year: 2026,
            month: 6,
            day: 1,
        },
        "browser/cache",
    );
    let text = lines.join("\n");
    assert!(text.contains("DO NOT OVERLAP"));
    assert!(text.contains("cannot rule out past contact"));
    assert!(text.contains("browser/cache"));
}

#[test]
fn evidence_starting_inside_campaign_is_partial_not_none() {
    let lines = overlap_statement(
        CivilDate {
            year: 2024,
            month: 6,
            day: 1,
        },
        "browser/cache",
    );
    let text = lines.join("\n");
    assert!(text.contains("PART of the campaign period"));
    assert!(text.contains("does not establish continuous coverage"));
    assert!(text.contains("2024-06-01"));
}

#[test]
fn evidence_before_campaign_still_hedged() {
    let lines = overlap_statement(
        CivilDate {
            year: 2021,
            month: 1,
            day: 1,
        },
        "browser/cache",
    );
    let text = lines.join("\n");
    assert!(text.contains("predates"));
    assert!(text.contains("does not establish continuous coverage"));
    assert!(text.contains("cannot rule out past contact"));
}

#[test]
fn boundary_days() {
    // Last day of the campaign: partial coverage (it does not extend past it).
    let at_end = overlap_statement(CAMPAIGN_TO, "x").join("\n");
    assert!(at_end.contains("PART of the campaign period"));
    // The day after: no overlap at all.
    let after = overlap_statement(
        CivilDate {
            year: 2026,
            month: 1,
            day: 1,
        },
        "x",
    )
    .join("\n");
    assert!(after.contains("DO NOT OVERLAP"));
    // Exactly the first day hits the final branch upstream (the comparisons
    // are strict), and the port replicates that wording.
    let at_start = overlap_statement(CAMPAIGN_FROM, "x").join("\n");
    assert!(at_start.contains("predates"));
    let day_after_start = overlap_statement(
        CivilDate {
            year: 2024,
            month: 1,
            day: 2,
        },
        "x",
    )
    .join("\n");
    assert!(day_after_start.contains("PART of the campaign period"));
}

/// The browser module reports the oldest surviving cookie as its measured
/// window, and the reach entry carries the store count it came from.
#[test]
fn browser_reports_oldest_cookie() {
    let dir = temp_dir("reach");
    let iocs =
        common::ioc_set_from_lines(&dir, &[&format!("{}\tdelivery\tprimary\tt", TEST_DOMAIN)]);
    let root = dir.join("User Data");
    let cookies = root.join("Default").join("Network").join("Cookies");
    std::fs::create_dir_all(cookies.parent().unwrap()).unwrap();
    let con = rusqlite::Connection::open(&cookies).unwrap();
    con.execute_batch(
        "CREATE TABLE cookies (host_key TEXT, name TEXT, creation_utc INTEGER);
         INSERT INTO cookies VALUES ('.unrelated.example', 'a', 13270000000000000);
         INSERT INTO cookies VALUES ('.unrelated.example', 'b', 13290000000000000);",
    )
    .unwrap();

    let mut ctx = common::quiet_ctx(&iocs);
    let cfg = BrowserConfig {
        chromium: vec![("test".to_string(), root.clone())],
        firefox: Some(vec![]),
        snapshot: None,
    };
    let r = browser::run_with(&mut ctx, &cfg);

    let reach = r.reach_get("cookies").expect("a cookie window is reported");
    let earliest = reach["earliest"].as_str().unwrap();
    let oldest_us: i64 = 13_270_000_000_000_000;
    let oldest_secs = oldest_us / 1_000_000 - 11_644_473_600;
    assert_eq!(
        earliest,
        zero_breach_rs::datetime::iso_from_unix(oldest_secs)
    );
    assert!(reach["basis"]
        .as_str()
        .unwrap()
        .starts_with("oldest surviving cookie across 1 cookie store(s)"));
    assert!(reach["note"].as_str().unwrap().contains("oldest SURVIVOR"));
    let days = reach["days"].as_i64().unwrap();
    let now_days = zero_breach_rs::datetime::now_days();
    assert!(
        days >= 1 && days <= now_days,
        "a plausible cookie age, got {}",
        days
    );
}

/// Cache file ages are summarised by year so the report can say how much
/// evidence actually falls inside the campaign window.
#[test]
fn cache_by_year_is_reported() {
    let dir = temp_dir("reach2");
    let iocs =
        common::ioc_set_from_lines(&dir, &[&format!("{}\tdelivery\tprimary\tt", TEST_DOMAIN)]);
    let root = dir.join("User Data");
    let cache = root.join("Default").join("Cache").join("Cache_Data");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("f_000001"), TEST_DOMAIN).unwrap();
    std::fs::write(cache.join("f_000002"), b"nothing here").unwrap();

    let mut ctx = common::quiet_ctx(&iocs);
    let cfg = BrowserConfig {
        chromium: vec![("test".to_string(), root.clone())],
        firefox: Some(vec![]),
        snapshot: None,
    };
    let r = browser::run_with(&mut ctx, &cfg);

    let reach = r.reach_get("cache").expect("a cache window is reported");
    let by_year = reach["by_year"].as_object().expect("by_year present");
    let total: i64 = by_year.values().filter_map(|v| v.as_i64()).sum();
    assert_eq!(total, 2, "both cache files are dated");
    assert!(reach["basis"]
        .as_str()
        .unwrap()
        .contains("cache/LevelDB/Service-Worker files searched"));
    assert!(reach["note"].as_str().unwrap().contains("oldest SURVIVOR"));
}

/// A history reach entry never advertises a window the scan did not observe.
#[test]
fn history_reach_is_only_claimed_when_rows_were_read() {
    let dir = temp_dir("reach3");
    let iocs =
        common::ioc_set_from_lines(&dir, &[&format!("{}\tdelivery\tprimary\tt", TEST_DOMAIN)]);
    let root = dir.join("User Data");
    common::chromium_history_db(
        &root.join("Default").join("History"),
        &format!("https://{}/x", TEST_DOMAIN),
    );
    let mut ctx = common::quiet_ctx(&iocs);
    let cfg = BrowserConfig {
        chromium: vec![("test".to_string(), root.clone())],
        firefox: Some(vec![]),
        snapshot: None,
    };
    let r = browser::run_with(&mut ctx, &cfg);
    let reach = r.reach_get("history").expect("history was searched");
    assert!(reach["earliest"].is_null());
    assert!(reach["basis"]
        .as_str()
        .unwrap()
        .contains("records only top-level navigations"));

    // With no history table at all, no history reach entry is claimed.
    let dir2 = temp_dir("reach4");
    let iocs2 =
        common::ioc_set_from_lines(&dir2, &[&format!("{}\tdelivery\tprimary\tt", TEST_DOMAIN)]);
    let root2 = dir2.join("User Data");
    std::fs::create_dir_all(root2.join("Default")).unwrap();
    let mut ctx2 = common::quiet_ctx(&iocs2);
    let cfg2 = BrowserConfig {
        chromium: vec![("test".to_string(), root2.clone())],
        firefox: Some(vec![]),
        snapshot: None,
    };
    let r2 = browser::run_with(&mut ctx2, &cfg2);
    assert!(r2.reach_get("history").is_none());
    let _ = Path::new("");
    let _ = days_from_civil(2024, 1, 1);
}
