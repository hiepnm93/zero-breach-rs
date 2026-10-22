//! D1 (the mandatory closing line), D3 (CLEAN != UNKNOWN), the verdict
//! rollup, IOC freshness and loader refusals.
//! Ported from zero-breach scan/tests/test_doctrine.py (Apache-2.0).

mod common;

use std::path::Path;

use serde_json::json;

use zero_breach_rs::iocs::{
    self, infer_type, Indicator, IocError, IocSet, TYPE_DOMAIN, TYPE_SHA256,
};
use zero_breach_rs::report::{
    build_document, render_human, D1_LINE, V_HITS, V_NONE, V_NONE_WITH_GAPS,
};
use zero_breach_rs::result::{
    is_serious, Hit, ModuleResult, CLEAN, EV_CONTACTED, EV_REFERENCED, HITS, PARTIAL, UNKNOWN,
};

use common::temp_dir;

fn hit(indicator: &str, tier: &str, evidence: &str) -> Hit {
    Hit {
        indicator: indicator.to_string(),
        location: r"C:\Users\x\AppData\Roaming\thing".to_string(),
        detail: "some detail".to_string(),
        tier: tier.to_string(),
        confidence: "primary".to_string(),
        source: "s".to_string(),
        evidence: evidence.to_string(),
        observed: String::new(),
        profile: String::new(),
    }
}

fn fixture_iocs() -> IocSet {
    let mut s = IocSet::new(
        vec![Indicator {
            value: "review-indicator.invalid".to_string(),
            tier: "delivery".to_string(),
            confidence: "primary".to_string(),
            kind: TYPE_DOMAIN.to_string(),
            source: "test".to_string(),
        }],
        "fixture",
        None,
    );
    s.asof = None;
    s
}

// --- D1 ---------------------------------------------------------------------

#[test]
fn d1_line_constant_is_the_required_sentence() {
    assert_eq!(
        D1_LINE,
        "No known indicators were found in the places that can be checked. \
         This is not a clean bill of health."
    );
}

#[test]
fn d1_line_present_when_nothing_found_and_absent_when_there_is_a_hit() {
    let iocs = fixture_iocs();

    let mut clean = ModuleResult::new("browser");
    clean.ran("chromium:test");
    let doc = build_document(&iocs, &[clean], 0);
    assert_eq!(doc["doctrine_line"], json!(D1_LINE));
    let text = render_human(&doc);
    assert!(text.contains(D1_LINE));

    let mut with_hit = ModuleResult::new("browser");
    with_hit.ran("chromium:test");
    with_hit.add_hit(hit("review-indicator.invalid", "delivery", EV_CONTACTED));
    let doc2 = build_document(&iocs, &[with_hit], 0);
    assert!(doc2["doctrine_line"].is_null());
    assert!(!render_human(&doc2).contains(D1_LINE));
}

#[test]
fn d1_line_present_even_when_there_are_gaps() {
    let iocs = fixture_iocs();
    let mut m = ModuleResult::new("host");
    m.could_not_run("dns-log", "disabled");
    let doc = build_document(&iocs, &[m], 0);
    assert_eq!(doc["verdict"]["status"], json!(V_NONE_WITH_GAPS));
    assert_eq!(doc["doctrine_line"], json!(D1_LINE));
}

// --- D3 status rollup -------------------------------------------------------

#[test]
fn status_rollup_never_collapses_unknown_into_clean() {
    let r = ModuleResult::new("m");
    assert_eq!(r.status(), UNKNOWN, "zero checks is UNKNOWN");

    let mut r = ModuleResult::new("m");
    r.ran("a");
    assert_eq!(r.status(), CLEAN);

    let mut r = ModuleResult::new("m");
    r.could_not_run("a", "why");
    assert_eq!(r.status(), UNKNOWN, "no check ran is UNKNOWN, not clean");

    let mut r = ModuleResult::new("m");
    r.ran("a");
    r.could_not_run("b", "why");
    assert_eq!(r.status(), PARTIAL);

    let mut r = ModuleResult::new("m");
    r.could_not_run("a", "why");
    r.add_hit(hit("x.example", "cc", EV_CONTACTED));
    assert_eq!(r.status(), HITS, "any hit is HITS even with gaps");

    let mut r = ModuleResult::new("m");
    r.could_not_run("a-check", "because");
    assert!(r
        .notes
        .iter()
        .any(|n| n.contains("could not run (because)")));
}

// --- verdict rollup ---------------------------------------------------------

#[test]
fn verdict_rollup() {
    let iocs = fixture_iocs();

    let mut clean = ModuleResult::new("browser");
    clean.ran("chromium:test");
    let doc = build_document(&iocs, &[clean], 0);
    assert_eq!(doc["verdict"]["status"], json!(V_NONE));
    assert_eq!(doc["verdict"]["hits_total"], json!(0));

    let mut gapped = ModuleResult::new("browser");
    gapped.ran("chromium:test");
    gapped.could_not_run("chromium:cookies", "locked");
    let doc = build_document(&iocs, &[gapped], 0);
    assert_eq!(doc["verdict"]["status"], json!(V_NONE_WITH_GAPS));
    let gaps: Vec<String> = doc["verdict"]["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g.as_str().unwrap_or("").to_string())
        .collect();
    assert!(
        gaps.iter().any(|g| g.contains("browser/chromium:cookies")),
        "the gap must be named: {:?}",
        gaps
    );

    let mut hit_mod = ModuleResult::new("host");
    hit_mod.ran("dns-log");
    hit_mod.add_hit(hit("review-indicator.invalid", "delivery", EV_CONTACTED));
    let doc = build_document(&iocs, &[hit_mod], 0);
    assert_eq!(doc["verdict"]["status"], json!(V_HITS));
    assert_eq!(doc["verdict"]["hits_total"], json!(1));

    // A module that produced NO checks at all is a gap too.
    let empty = ModuleResult::new("browser");
    let doc = build_document(&iocs, &[empty], 0);
    assert_eq!(doc["verdict"]["status"], json!(V_NONE_WITH_GAPS));
    assert!(doc["verdict"]["gaps"].as_array().unwrap().iter().any(|g| g
        .as_str()
        .unwrap_or("")
        .contains("browser: nothing in this check could run")));
}

// --- a hit renders as INVESTIGATE ------------------------------------------

#[test]
fn hit_renders_as_investigate_never_compromise() {
    let iocs = fixture_iocs();
    let mut m = ModuleResult::new("browser");
    m.ran("chromium:test");
    // The Python test used the indicator itself in the detail line, so the
    // whole-report defang pass has a real job to do here too.
    m.add_hit(Hit {
        detail: "history: http://fearevolve.com/x".to_string(),
        ..hit("fearevolve.com", "delivery", EV_CONTACTED)
    });
    let doc = build_document(&iocs, &[m], 0);
    let text = render_human(&doc);
    let low = text.to_lowercase();
    assert!(low.contains("investigate"), "the verdict is investigate");
    // report.rs deliberately prints the phrase as a NEGATION:
    //   "A match means INVESTIGATE, not 'you are compromised'."
    // so only AFFIRMATIVE claims are banned, and every occurrence of
    // "compromised" must sit inside a negation.
    for affirmative in [
        "this device is compromised",
        "your machine is compromised",
        "you have been infected",
        "you are infected",
    ] {
        assert!(
            !low.contains(affirmative),
            "must not claim: {}",
            affirmative
        );
    }
    let mut start = 0usize;
    while let Some(idx) = low[start..].find("compromised") {
        let idx = start + idx;
        let window = &low[idx.saturating_sub(30)..idx];
        assert!(
            window.contains("not"),
            "'compromised' at offset {} is not negated: {:?}",
            idx,
            &low[idx.saturating_sub(40)..(idx + 20).min(low.len())]
        );
        start = idx + 1;
    }
    assert_eq!(
        low.matches("you are compromised").count(),
        low.matches("not 'you are compromised'").count(),
        "the only permitted use of 'you are compromised' is the explicit denial of it"
    );
    // Provenance and location travel; the indicator is defanged everywhere,
    // including inside the detail line's URL.
    assert!(text.contains("fearevolve[.]com"));
    assert!(!text.contains("fearevolve.com"));
    assert!(!text.contains("fearevolve.com"), "detail lines defang too");
    assert!(text.contains("hxxp://"));
    assert!(text.contains("delivery/primary"));
    assert!(text.contains(r"C:\Users\x\AppData\Roaming\thing"));
    assert!(text.contains("accessnow.org"), "referrals offered");
    assert!(text.contains("securitylab.amnesty.org"));
    assert!(text.contains("citizenlab.ca"));

    // A clean run also offers the referrals.
    let mut clean = ModuleResult::new("browser");
    clean.ran("chromium:test");
    let doc = build_document(&iocs, &[clean], 0);
    assert!(render_human(&doc).contains("https://www.accessnow.org/help/"));
}

// --- IOC freshness ----------------------------------------------------------

fn set_with_asof(asof: Option<String>) -> IocSet {
    let mut s = IocSet::new(
        vec![Indicator {
            value: "a.example".to_string(),
            tier: "cc".to_string(),
            confidence: "primary".to_string(),
            kind: TYPE_DOMAIN.to_string(),
            source: String::new(),
        }],
        "fixture",
        None,
    );
    s.asof = asof;
    s
}

fn days_ago_str(days: i64) -> String {
    let d = zero_breach_rs::datetime::now_days() - days;
    zero_breach_rs::datetime::civil_from_days(d).iso()
}

#[test]
fn ioc_freshness_windows() {
    assert!(!set_with_asof(Some(days_ago_str(10))).is_stale());
    assert!(
        set_with_asof(Some(days_ago_str(40))).is_stale(),
        "older than 30 days is stale and warned about"
    );
    assert!(
        !set_with_asof(Some(days_ago_str(30))).is_stale(),
        "exactly 30 days is not yet stale"
    );
    assert_eq!(set_with_asof(None).age_days(), None);
    assert!(
        !set_with_asof(None).is_stale(),
        "unknown age is reported as unknown, never as fresh-or-stale"
    );
    // The rendered report says "unknown age" for an undated set.
    let doc = build_document(&set_with_asof(None), &[], 0);
    assert!(render_human(&doc).contains("unknown age"));
}

#[test]
fn mtime_fallback_for_an_undated_set() {
    // A set without a header date degrades to the file's mtime.
    let dir = temp_dir("fresh");
    let path = dir.join("iocs.txt");
    std::fs::write(&path, "a.example\tcc\tprimary\n").unwrap();
    let s = iocs::load(&path).unwrap();
    assert!(s.asof.is_none());
    assert!(s.age_days().is_some());
}

// --- loader refusals --------------------------------------------------------

fn assert_ioc_error(text: &str, needle: &str) {
    let dir = temp_dir("reject");
    let path = dir.join("iocs.txt");
    std::fs::write(&path, text).unwrap();
    match iocs::load(&path) {
        Err(IocError(msg)) => assert!(
            msg.contains(needle),
            "expected {:?} in the error, got {:?}",
            needle,
            msg
        ),
        Ok(_) => panic!("expected a refusal for {:?}", text),
    }
}

#[test]
fn loader_rejects_malformed_data() {
    assert_ioc_error("a.example\tcc\n", "expected 3 or 4 tab-separated columns");
    assert_ioc_error("a.example\tnot-a-tier\tprimary\n", "unknown tier");
    assert_ioc_error("a.example\tcc\tbelievable\n", "unknown confidence");
    assert_ioc_error("999.1.1.1\tcc\tprimary\n", "not a valid IP address");
    assert_ioc_error("0.0.0.0\tcc\tprimary\n", "would match far more");
    assert_ioc_error("a.b\tcc\tprimary\n", "not the length of a hostname");
    assert_ioc_error(
        "ab_c.example\tcc\tprimary\n",
        "is not a valid hostname label",
    );
    assert_ioc_error(
        "bad-.example\tcc\tprimary\n",
        "is not a valid hostname label",
    );
    assert_ioc_error("nodot\tcc\tprimary\n", "a hostname needs at least one dot");

    let dir = temp_dir("missing");
    match iocs::load(Path::new(&dir.join("nope.txt"))) {
        Err(IocError(msg)) => assert!(msg.contains("IOC file not found")),
        Ok(_) => panic!("missing file must be refused"),
    }
}

#[test]
fn comments_and_blank_lines_are_ignored_and_provenance_kept() {
    let dir = temp_dir("comments");
    let path = dir.join("iocs.txt");
    std::fs::write(
        &path,
        "# as-of: 2026-01-01\n\na.example\tcc\tprimary\tthe-report\nb.example\tdelivery\tsecondary\n",
    )
    .unwrap();
    let s = iocs::load(&path).unwrap();
    assert_eq!(s.len(), 2);
    assert_eq!(s.asof.as_deref(), Some("2026-01-01"));
    let a = s.lookup("a.example").unwrap();
    assert_eq!(
        (a.tier.as_str(), a.confidence.as_str(), a.source.as_str()),
        ("cc", "primary", "the-report")
    );
    let b = s.lookup("b.example").unwrap();
    assert_eq!(
        (b.tier.as_str(), b.confidence.as_str()),
        ("delivery", "secondary")
    );
}

#[test]
fn network_strings_hold_domains_and_ips_but_no_hashes() {
    let s = iocs::parse(
        "a.example\tcc\tprimary\n52.174.65.77\tcc\tprimary\n\
         0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\tsample\tprimary\n",
        "fixture",
        None,
    )
    .unwrap();
    let net = s.network_strings();
    assert_eq!(net.len(), 2);
    assert!(net.contains(&"a.example".to_string()));
    assert!(net.contains(&"52.174.65.77".to_string()));
    assert_eq!(s.hashes().len(), 1);
    assert_eq!(s.domains().len(), 1);
    assert_eq!(s.ips().len(), 1);
    assert_eq!(
        infer_type("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        TYPE_SHA256
    );
    assert_eq!(infer_type("a.example"), TYPE_DOMAIN);
}

#[test]
fn benign_evidence_is_a_deny_list() {
    assert!(!is_serious(EV_REFERENCED));
    assert!(is_serious(EV_CONTACTED));
    assert!(is_serious(""), "missing grade is serious");
    assert!(is_serious("misspelled"), "unknown grade is serious");
}
