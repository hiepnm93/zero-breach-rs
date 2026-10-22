//! Evidence grading is the field that stops this tool doing harm: connection
//! artifacts must grade as `contacted`, page content as `referenced`, and the
//! report must say so plainly in both directions.
//! Ported from zero-breach scan/tests/test_evidence.py (Apache-2.0).

mod common;

use std::path::Path;

use zero_breach_rs::datetime::{days_from_civil, iso_from_unix};
use zero_breach_rs::iocs::IocSet;
use zero_breach_rs::modules::browser::{self, BrowserConfig};
use zero_breach_rs::modules::host::{self, DnsCacheRow, DnsEvent, DnsLogMeta};
use zero_breach_rs::result::{Hit, ModuleResult, EV_CONTACTED, EV_DNS, EV_ON_DISK, EV_PERSISTENCE};
use zero_breach_rs::{cli, report};

use common::{temp_dir, TEST_DOMAIN};

fn browser_config(root: &Path) -> BrowserConfig {
    BrowserConfig {
        chromium: vec![("test".to_string(), root.to_path_buf())],
        firefox: Some(vec![]),
        snapshot: None,
    }
}

fn run_browser_on(dir: &Path, root: &Path) -> ModuleResult {
    let iocs = common::ioc_set_from_lines(
        dir,
        &[&format!("{}\tdelivery\tprimary\ttest-source", TEST_DOMAIN)],
    );
    let mut ctx = common::quiet_ctx(&iocs);
    browser::run_with(&mut ctx, &browser_config(root))
}

fn hsts_fingerprint_of(host: &str) -> String {
    zero_breach_rs::modules::browser::hsts_fingerprint(host)
}

#[test]
fn hsts_entry_for_an_indicator_is_contacted_with_a_date() {
    let dir = temp_dir("hsts");
    let net = dir.join("User Data").join("Default").join("Network");
    std::fs::create_dir_all(&net).unwrap();
    let observed_secs = days_from_civil(2025, 3, 4) * 86_400 + 12 * 3600;
    let fingerprint = hsts_fingerprint_of(TEST_DOMAIN);
    std::fs::write(
        net.join("TransportSecurity"),
        format!(
            r#"{{"version": 2, "sts": [
                {{"host": "{}", "mode": "force-https", "sts_observed": {}, "expiry": {}, "sts_include_subdomains": false}},
                {{"host": "someOtherHashThatIsNotOurs=", "mode": "force-https", "sts_observed": {}, "expiry": 0, "sts_include_subdomains": false}}
            ]}}"#,
            fingerprint,
            observed_secs,
            observed_secs + 31_536_000,
            observed_secs
        ),
    )
    .unwrap();

    let r = run_browser_on(&dir, &dir.join("User Data"));
    let hits: Vec<&Hit> = r
        .hits
        .iter()
        .filter(|h| h.evidence == "contacted")
        .collect();
    assert_eq!(hits.len(), 1, "the HSTS entry should be one contacted hit");
    assert_eq!(hits[0].indicator, TEST_DOMAIN);
    assert!(
        hits[0].observed.starts_with("2025-03-04"),
        "HSTS records when it was observed; that date is the most useful thing \
         about this artifact (got {:?})",
        hits[0].observed
    );
    assert_eq!(r.metric("hsts_entries"), 2);
}

#[test]
fn unrelated_hsts_entries_do_not_match() {
    let dir = temp_dir("hsts2");
    let net = dir.join("User Data").join("Default").join("Network");
    std::fs::create_dir_all(&net).unwrap();
    std::fs::write(
        net.join("TransportSecurity"),
        r#"{"sts": [{"host": "notOurHash=", "sts_observed": 0, "expiry": 0}]}"#,
    )
    .unwrap();
    let r = run_browser_on(&dir, &dir.join("User Data"));
    assert!(r.hits.is_empty());
}

#[test]
fn connected_server_origin_is_contacted() {
    let dir = temp_dir("nps");
    let net = dir.join("User Data").join("Default").join("Network");
    std::fs::create_dir_all(&net).unwrap();
    std::fs::write(
        net.join("Network Persistent State"),
        format!(
            r#"{{"net": {{"http_server_properties": {{
                "servers": [
                    {{"server": "https://{d}:443", "supports_spdy": true}},
                    {{"server": "https://unrelated.example:443"}}
                ],
                "broken_alternative_services": [
                    {{"host": "sub.{d}", "port": 443, "protocol_str": "quic"}}
                ]}}}}}}"#,
            d = TEST_DOMAIN
        ),
    )
    .unwrap();
    let r = run_browser_on(&dir, &dir.join("User Data"));
    assert_eq!(
        r.hits.len(),
        2,
        "the connected origin and the subdomain in broken alternative services \
         should both be found"
    );
    assert!(r.hits.iter().all(|h| h.evidence == "contacted"));
    assert_eq!(r.metric("connection_records"), 3);
}

#[test]
fn a_similar_but_different_host_does_not_match() {
    let dir = temp_dir("nps2");
    let net = dir.join("User Data").join("Default").join("Network");
    std::fs::create_dir_all(&net).unwrap();
    // A host that merely ENDS with the indicator text, and one that extends
    // it. Neither is the indicator.
    std::fs::write(
        net.join("Network Persistent State"),
        format!(
            r#"{{"net": {{"http_server_properties": {{"servers": [
                {{"server": "https://not{d}:443"}},
                {{"server": "https://{d}.evil.example:443"}}
            ]}}}}}}"#,
            d = TEST_DOMAIN
        ),
    )
    .unwrap();
    let r = run_browser_on(&dir, &dir.join("User Data"));
    assert!(
        r.hits.is_empty(),
        "host matching must be exact-or-subdomain, never a substring"
    );
}

#[test]
fn blob_match_is_referenced_not_contacted() {
    let dir = temp_dir("blob");
    let cache = dir
        .join("User Data")
        .join("Default")
        .join("Cache")
        .join("Cache_Data");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(
        cache.join("f_000001"),
        format!("an article discussing {} at length", TEST_DOMAIN),
    )
    .unwrap();
    let r = run_browser_on(&dir, &dir.join("User Data"));
    assert!(!r.hits.is_empty());
    assert!(
        r.hits.iter().all(|h| h.evidence == "referenced"),
        "page content mentioning a domain is not contact with it"
    );
}

#[test]
fn cookie_is_contacted() {
    let dir = temp_dir("cookie");
    let net = dir.join("User Data").join("Default").join("Network");
    std::fs::create_dir_all(&net).unwrap();
    common::chromium_cookie_db(&net.join("Cookies"), &format!(".{}", TEST_DOMAIN));
    let r = run_browser_on(&dir, &dir.join("User Data"));
    assert!(!r.hits.is_empty());
    assert!(
        r.hits.iter().any(|h| h.evidence == "contacted"),
        "a cookie exists only because that host responded"
    );
    // The cookie's creation time is reported as the observed time.
    let contacted = r.hits.iter().find(|h| h.evidence == "contacted").unwrap();
    assert!(
        contacted.detail.contains("cookie set by"),
        "the cookie detail names the setting host: {:?}",
        contacted.detail
    );
}

// --- report wording ---------------------------------------------------------

fn doc_with(hits: Vec<Hit>) -> serde_json::Value {
    let mut m = ModuleResult::new("browser");
    m.ran("chromium:test");
    for h in hits {
        m.add_hit(h);
    }
    let iocs = cli::embedded_ioc_set().unwrap();
    report::build_document(&iocs, &[m], 0)
}

#[test]
fn referenced_only_result_is_explained_as_probably_not_compromise() {
    let doc = doc_with(vec![Hit {
        tier: "delivery".to_string(),
        confidence: "primary".to_string(),
        source: "s".to_string(),
        evidence: "referenced".to_string(),
        ..Hit::new("x.example", "cache", "binary match")
    }]);
    let flat: String = report::render_human(&doc)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(flat.contains("reference-only"));
    assert!(flat.contains("probably not a sign of compromise"));
}

#[test]
fn contacted_result_is_called_out_first() {
    let doc = doc_with(vec![
        Hit {
            tier: "delivery".to_string(),
            confidence: "primary".to_string(),
            source: "s".to_string(),
            evidence: "referenced".to_string(),
            ..Hit::new("a.example", "cache", "binary")
        },
        Hit {
            tier: "cc".to_string(),
            confidence: "primary".to_string(),
            source: "s".to_string(),
            evidence: EV_CONTACTED.to_string(),
            ..Hit::new("b.example", "hsts", "HSTS")
        },
    ]);
    let text = report::render_human(&doc);
    assert!(text.contains("SERIOUS"));
    // The contacted hit is the one surfaced in the summary; it must appear
    // before the merely-referenced one anywhere in the report.
    let b = text.find("b[.]example").expect("contacted hit present");
    let a = text.find("a[.]example").expect("referenced hit present");
    assert!(
        b < a,
        "the contacted hit must be listed before the merely referenced one"
    );
}

#[test]
fn sample_on_disk_is_never_reported_as_harmless() {
    // The whole reason the evidence contract exists: a file on disk whose
    // fingerprint matches a published sample must be a SERIOUS finding with
    // the preserve-the-evidence instructions.
    let doc = doc_with(vec![Hit {
        tier: "sample".to_string(),
        confidence: "primary".to_string(),
        source: "s".to_string(),
        evidence: EV_ON_DISK.to_string(),
        ..Hit::new(
            &"deadbeef".repeat(8),
            r"C:\Users\x\AppData\Roaming\evil.dll",
            "sample",
        )
    }]);
    let text = report::render_human(&doc);
    assert!(text.to_lowercase().contains("serious"));
    assert!(text.contains("KNOWN SPYWARE FILE"));
    assert!(!text.contains("probably not a sign of compromise"));
    assert!(text.contains("Do NOT delete"));
}

#[test]
fn persistence_is_never_reported_as_harmless() {
    let doc = doc_with(vec![Hit {
        tier: "cc".to_string(),
        confidence: "primary".to_string(),
        source: "s".to_string(),
        evidence: EV_PERSISTENCE.to_string(),
        ..Hit::new("b.example", r"HKCU\...\InprocServer32", "COM")
    }]);
    let text = report::render_human(&doc);
    assert!(text.to_lowercase().contains("serious"));
    assert!(!text.contains("probably not a sign of compromise"));
    assert!(text.contains("Do NOT delete"));
}

#[test]
fn unknown_evidence_grade_is_treated_as_serious() {
    let doc = doc_with(vec![Hit {
        tier: "cc".to_string(),
        confidence: "primary".to_string(),
        source: "s".to_string(),
        evidence: "".to_string(),
        ..Hit::new("b.example", "somewhere", "d")
    }]);
    let text = report::render_human(&doc);
    assert!(!text.contains("probably not a sign of compromise"));
    assert!(text.to_lowercase().contains("serious"));
    assert!(
        text.contains("evidence: UNCLASSIFIED"),
        "the grade is shown"
    );
}

#[test]
fn evidence_grade_is_shown_on_every_hit() {
    let doc = doc_with(vec![Hit {
        tier: "cc".to_string(),
        confidence: "primary".to_string(),
        source: "s".to_string(),
        evidence: EV_CONTACTED.to_string(),
        ..Hit::new("a.example", "loc", "d")
    }]);
    assert!(report::render_human(&doc).contains("evidence: CONTACTED"));
}

#[test]
fn the_detail_line_is_defanged_not_only_the_indicator() {
    // The detail field quotes saved page content, so it carries whole URLs.
    // This report is written to be forwarded to a helpline, through mail
    // gateways and link scanners that fetch anything fetchable.
    let location = r"C:\Users\x\AppData\Local\Cache\f_000001";
    let doc = doc_with(vec![Hit {
        tier: "cc".to_string(),
        confidence: "primary".to_string(),
        source: "s".to_string(),
        evidence: "referenced".to_string(),
        ..Hit::new(
            "a.example",
            location,
            "history: https://A.EXAMPLE/landing.php some page title",
        )
    }]);
    let text = report::render_human(&doc);
    let detail: Vec<&str> = text
        .lines()
        .filter(|l| l.trim_start().starts_with("detail :"))
        .collect();
    assert_eq!(detail.len(), 1);
    assert!(!detail[0].contains("https://"));
    assert!(detail[0].contains("hxxps://a[.]example/landing.php"));
    // The path must survive intact: a reader who cannot find the file the
    // report names cannot act on it.
    let at: Vec<&str> = text
        .lines()
        .filter(|l| l.trim_start().starts_with("at     :"))
        .collect();
    assert_eq!(at[0].trim(), format!("at     : {}", location));
}

// --- a blocked lookup is not contact ---------------------------------------

fn dns_cache_result(data: &str) -> ModuleResult {
    let dir = temp_dir("dnscache");
    let iocs = common::ioc_set_from_lines(
        &dir,
        &[&format!("{}\tdelivery\tprimary\ttest", TEST_DOMAIN)],
    );
    let mut ctx = common::quiet_ctx(&iocs);
    let mut r = ModuleResult::new("host");
    let rows = vec![DnsCacheRow {
        entry: TEST_DOMAIN.to_string(),
        name: TEST_DOMAIN.to_string(),
        data: data.to_string(),
    }];
    host::check_dns_cache(
        &mut r,
        &mut ctx,
        &rows,
        Some("2026-01-01T00:00:00".to_string()),
        "",
    );
    r
}

#[test]
fn sink_address_is_protective_state_without_a_finding() {
    for sink in ["0.0.0.0", "127.0.0.1", "::", "::1"] {
        let r = dns_cache_result(sink);
        assert!(r.hits.is_empty(), "{} must not be a finding", sink);
        assert_eq!(r.metric("dns_cache_blocked_indicators"), 1);
        assert!(r.notes.iter().any(|n| n.contains("without any lookup")),);
    }
}

#[test]
fn real_address_is_a_dns_record_without_proof_of_contact() {
    let r = dns_cache_result("192.0.2.10");
    assert_eq!(r.hits.len(), 1);
    assert_eq!(r.hits[0].evidence, EV_DNS);
    assert!(r.hits[0].detail.contains("endpoint contact is unverified"));
    assert!(!r.hits[0].detail.contains("BLOCKED"));
}

// --- DNS history ------------------------------------------------------------

struct DnsFixture {
    meta: Result<DnsLogMeta, String>,
    events: Vec<DnsEvent>,
    error: String,
    calls: usize,
}

fn dns_log_result(fixture: &mut DnsFixture) -> ModuleResult {
    let dir = temp_dir("dnslog");
    let iocs = common::ioc_set_from_lines(
        &dir,
        &[&format!("{}\tdelivery\tprimary\ttest", TEST_DOMAIN)],
    );
    let mut ctx = common::quiet_ctx(&iocs);
    let mut r = ModuleResult::new("host");
    let calls = std::cell::Cell::new(0u32);
    host::check_dns_log(&mut r, &mut ctx, fixture.meta.clone(), &mut || {
        calls.set(calls.get() + 1);
        (fixture.events.clone(), fixture.error.clone())
    });
    fixture.calls = calls.get() as usize;
    r
}

fn meta(enabled: bool, records: i64) -> Result<DnsLogMeta, String> {
    Ok(DnsLogMeta {
        is_enabled: enabled,
        record_count: records,
    })
}

fn event(time: &str, message: &str) -> DnsEvent {
    DnsEvent {
        time: time.to_string(),
        message: message.to_string(),
    }
}

#[test]
fn disabled_log_still_searches_retained_matching_event() {
    let mut f = DnsFixture {
        meta: meta(false, 1),
        events: vec![event("2025-03-04T12:00:00Z", TEST_DOMAIN)],
        error: String::new(),
        calls: 0,
    };
    let r = dns_log_result(&mut f);
    assert_eq!(
        f.calls, 1,
        "the retained events are read after the metadata"
    );
    assert_eq!(r.status(), "HITS");
    assert_eq!(
        r.hits
            .iter()
            .map(|h| (h.indicator.as_str(), h.evidence.as_str()))
            .collect::<Vec<_>>(),
        vec![(TEST_DOMAIN, "dns-record")]
    );
    assert_eq!(r.hits[0].observed, "2025-03-04T12:00:00Z");
    assert_eq!(r.metric("dns_log_events_scanned"), 1);
    assert_eq!(r.metric("dns_log_enabled"), 0);
    assert!(r
        .reach_get("dns-log")
        .unwrap()
        .get("how_to_enable")
        .is_some());
}

#[test]
fn disabled_log_clean_retained_event_keeps_recording_gap() {
    let mut f = DnsFixture {
        meta: meta(false, 1),
        events: vec![event("2025-03-04T12:00:00Z", "ordinary.invalid")],
        error: String::new(),
        calls: 0,
    };
    let r = dns_log_result(&mut f);
    assert_eq!(r.status(), "PARTIAL");
    assert!(r.hits.is_empty());
    assert!(r.checks.iter().any(|c| c.name == "dns-log" && c.ran));
    assert!(r
        .checks
        .iter()
        .any(|c| c.name == "dns-log-recording" && !c.ran));
}

#[test]
fn disabled_empty_log_is_not_clean() {
    let mut f = DnsFixture {
        meta: meta(false, 0),
        events: vec![],
        error: String::new(),
        calls: 0,
    };
    let r = dns_log_result(&mut f);
    assert_eq!(r.status(), "UNKNOWN");
    assert_eq!(r.metric("dns_log_events_scanned"), 0);
    assert_eq!(f.calls, 0, "no event read is attempted for an empty log");
}

#[test]
fn disabled_log_read_failure_is_not_clean() {
    let mut f = DnsFixture {
        meta: meta(false, 1),
        events: vec![],
        error: "fixture permission denied".to_string(),
        calls: 0,
    };
    let r = dns_log_result(&mut f);
    assert_eq!(r.status(), "UNKNOWN");
    assert!(r.hits.is_empty());
    assert!(r.checks.iter().any(|c| c.name == "dns-log" && !c.ran));
    assert_eq!(r.metric("dns_log_events_scanned"), 0);
}

#[test]
fn disabled_log_preserves_hit_and_older_retained_gap_together() {
    let mut f = DnsFixture {
        meta: meta(false, 50_001),
        events: vec![event("2025-03-04T12:00:00Z", TEST_DOMAIN)],
        error: String::new(),
        calls: 0,
    };
    let r = dns_log_result(&mut f);
    assert_eq!(r.status(), "HITS");
    assert_eq!(r.hits.len(), 1);
    assert!(r
        .checks
        .iter()
        .any(|c| c.name == "dns-log-older-events" && !c.ran));
    assert!(r
        .checks
        .iter()
        .any(|c| c.name == "dns-log-recording" && !c.ran));
}

#[test]
fn dns_match_after_the_event_cap_is_read() {
    let mut events: Vec<DnsEvent> = (0..20_000)
        .map(|_| event("2025-03-04T12:00:00Z", ""))
        .collect();
    events.push(event(
        "2025-03-03T12:00:00Z",
        &format!("DNS query for {}", TEST_DOMAIN),
    ));
    let mut f = DnsFixture {
        meta: meta(true, 20_001),
        events,
        error: String::new(),
        calls: 0,
    };
    let r = dns_log_result(&mut f);
    assert_eq!(r.metric("dns_log_events_scanned"), 20_001);
    assert_eq!(r.hits.len(), 1);
    assert!(!r.checks.iter().any(|c| c.name == "dns-log-older-events"));
    assert_eq!(
        host::DNS_EVENT_CAP,
        50_000,
        "the bounded read cap the tool documents"
    );
}

#[test]
fn retained_older_dns_events_are_a_coverage_gap() {
    let mut f = DnsFixture {
        meta: meta(true, 50_001),
        events: vec![event("2025-03-04T12:00:00Z", "ordinary.test")],
        error: String::new(),
        calls: 0,
    };
    let r = dns_log_result(&mut f);
    assert_eq!(r.status(), "PARTIAL");
    assert!(r
        .checks
        .iter()
        .any(|c| c.name == "dns-log-older-events" && !c.ran));
}

#[test]
fn failed_nxdomain_lookup_remains_dns_evidence() {
    let mut f = DnsFixture {
        meta: meta(true, 1),
        events: vec![event(
            "2025-03-04T12:00:00Z",
            &format!(
                "DNS query for {} failed: status 9003 (NXDOMAIN)",
                TEST_DOMAIN
            ),
        )],
        error: String::new(),
        calls: 0,
    };
    let r = dns_log_result(&mut f);
    assert_eq!(r.hits.len(), 1);
    assert_eq!(r.hits[0].evidence, EV_DNS);
    assert!(!r.hits[0].is_contact());
    assert_eq!(r.hits[0].observed, "2025-03-04T12:00:00Z");
    assert!(r.hits[0]
        .detail
        .contains("does not establish successful resolution"));
}

#[test]
fn metadata_unreadable_is_the_same_gap_as_disabled() {
    let mut f = DnsFixture {
        meta: Err("log not present".to_string()),
        events: vec![],
        error: String::new(),
        calls: 0,
    };
    let r = dns_log_result(&mut f);
    assert!(r.checks.iter().any(|c| c.name == "dns-log" && !c.ran));
    assert_eq!(r.metric("dns_log_enabled"), 0);
    assert_eq!(r.metric("dns_log_records"), 0);
    assert!(r
        .reach_get("dns-log")
        .unwrap()
        .get("how_to_enable")
        .is_some());
    assert!(r
        .notes
        .iter()
        .any(|n| n.contains("HOW TO TURN ON DNS HISTORY")));
}

#[test]
fn the_timestamp_helpers_agree_with_the_documented_examples() {
    assert_eq!(iso_from_unix(0), "1970-01-01T00:00:00");
    // 2025-03-04T12:00:00Z
    let secs = days_from_civil(2025, 3, 4) * 86_400 + 12 * 3600;
    assert_eq!(iso_from_unix(secs), "2025-03-04T12:00:00");
}

/// Silence the unused-import lint when assertions above change shape.
#[allow(unused)]
fn _uses(i: &IocSet) {
    let _ = i.len();
}
