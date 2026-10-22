//! Matching must not fire on a longer name or number that merely contains an
//! indicator, and the loader's failure modes must stay loud.
//! Ported from zero-breach scan/tests/test_matching.py (Apache-2.0).

mod common;

use zero_breach_rs::iocs::{self, infer_type, IocError, TYPE_DOMAIN, TYPE_IP, TYPE_SHA256};

use common::{temp_dir, TEST_DOMAIN};

fn make_set(lines: &[&str]) -> iocs::IocSet {
    let dir = temp_dir("match");
    common::ioc_set_from_lines(&dir, lines)
}

#[test]
fn ip_boundaries() {
    let s = make_set(&["52.174.65.77\tcc\tprimary\ttest"]);
    let hits =
        |text: &str| -> Vec<String> { s.search(text).into_iter().map(|i| i.value).collect() };
    assert_eq!(
        hits("connected to 52.174.65.77 today"),
        vec!["52.174.65.77"]
    );
    assert_eq!(hits("52.174.65.77"), vec!["52.174.65.77"]);
    assert!(
        hits("x 152.174.65.771 y").is_empty(),
        "an IP must not match inside a longer number"
    );
    assert!(hits("52.174.65.771").is_empty(), "trailing digit");
    assert!(hits("152.174.65.77").is_empty(), "leading digit");
    assert!(hits("52.174.65.77.9").is_empty(), "further octet");
    assert_eq!(hits("52.174.65.77:443"), vec!["52.174.65.77"]);
    // The near miss must not stop the scan finding the genuine one later.
    assert_eq!(
        hits("152.174.65.771 and also 52.174.65.77"),
        vec!["52.174.65.77"]
    );
}

#[test]
fn domain_boundaries() {
    let s = make_set(&["controlium.net\tdelivery\tprimary\ttest"]);
    let hits =
        |text: &str| -> Vec<String> { s.search(text).into_iter().map(|i| i.value).collect() };
    assert_eq!(hits("https://controlium.net/x"), vec!["controlium.net"]);
    assert_eq!(
        hits("noas.controlium.net"),
        vec!["controlium.net"],
        "a subdomain of an indicator is still that indicator"
    );
    assert!(
        hits("notcontrolium.net").is_empty(),
        "a different domain that merely ends with the indicator must not match"
    );
    assert!(hits("controlium.network").is_empty());
    assert!(hits("safe-controlium.net").is_empty());
}

#[test]
fn bytes_and_text_agree() {
    let s = make_set(&[
        "52.174.65.77\tcc\tprimary\ttest",
        "controlium.net\tdelivery\tprimary\ttest",
    ]);
    for text in [
        "152.174.65.771 notcontrolium.net",
        "52.174.65.77 noas.controlium.net",
        "controlium.network",
    ] {
        let text_hits: Vec<String> = s.search(text).into_iter().map(|i| i.value).collect();
        let byte_hits: Vec<String> = s
            .search_bytes(text.as_bytes())
            .into_iter()
            .map(|i| i.value)
            .collect();
        assert_eq!(
            text_hits, byte_hits,
            "text and binary matching disagree on {:?}",
            text
        );
    }
}

#[test]
fn optional_fourth_column_is_read() {
    let s = make_set(&["a.example\tcc\tprimary\tsome-report-2025"]);
    assert_eq!(s.lookup("a.example").unwrap().source, "some-report-2025");
}

#[test]
fn three_column_file_still_loads() {
    let s = make_set(&["b.example\tcc\tprimary"]);
    assert_eq!(s.lookup("b.example").unwrap().source, "");
}

#[test]
fn new_tiers_accepted() {
    let s = make_set(&[
        "c.example\tcandiru\tprimary\tr",
        "1.2.3.4\tcandiru-ip\tprimary\tr",
    ]);
    assert_eq!(s.len(), 2);
}

#[test]
fn unknown_tier_still_rejected() {
    let dir = temp_dir("tier");
    let path = dir.join("iocs.txt");
    std::fs::write(&path, "d.example\tnot-a-tier\tprimary\tr\n").unwrap();
    assert!(matches!(iocs::load(&path), Err(IocError(_))));
}

#[test]
fn utf8_bom_does_not_corrupt_first_indicator() {
    // A Windows editor saves a BOM; U+FEFF is not whitespace to a trim().
    let dir = temp_dir("bom");
    let path = dir.join("iocs.txt");
    std::fs::write(
        path.clone(),
        "\u{FEFF}controlium.net\tdelivery\tprimary\tt\n",
    )
    .unwrap();
    let s = iocs::load(&path).unwrap();
    assert_eq!(s.indicators[0].value, "controlium.net");
    assert!(!s.indicators[0].value.starts_with('\u{FEFF}'));
    assert!(!s.search("go to controlium.net now").is_empty());
}

#[test]
fn empty_file_is_refused() {
    let dir = temp_dir("empty");
    let path = dir.join("iocs.txt");
    std::fs::write(&path, "# only a comment\n\n").unwrap();
    assert!(matches!(iocs::load(&path), Err(IocError(_))));
}

#[test]
fn zero_width_character_in_indicator_is_rejected() {
    let dir = temp_dir("zw");
    let path = dir.join("iocs.txt");
    std::fs::write(&path, "contro\u{200B}lium.net\tdelivery\tprimary\tt\n").unwrap();
    match iocs::load(&path) {
        Err(IocError(msg)) => assert!(msg.contains("invisible character")),
        Ok(_) => panic!("a zero-width character must be refused"),
    }
}

#[test]
fn internationalised_domain_is_stored_as_punycode() {
    let dir = temp_dir("idn");
    let path = dir.join("iocs.txt");
    std::fs::write(&path, "müller.example\tdelivery\tprimary\tt\n").unwrap();
    let s = iocs::load(&path).unwrap();
    assert_eq!(s.indicators[0].value, "xn--mller-kva.example");
}

#[test]
fn trailing_dot_is_normalised_at_load() {
    let dir = temp_dir("dot");
    let path = dir.join("iocs.txt");
    std::fs::write(&path, "controlium.net.\tdelivery\tprimary\tt\n").unwrap();
    let s = iocs::load(&path).unwrap();
    assert_eq!(s.indicators[0].value, "controlium.net");
}

#[test]
fn utf16le_bytes_match() {
    let s = make_set(&["controlium.net\tdelivery\tprimary\tt"]);
    let buf: Vec<u8> = "visited controlium.net today"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .map(|b| b.to_ascii_lowercase())
        .collect();
    let got: Vec<String> = s.search_bytes(&buf).into_iter().map(|i| i.value).collect();
    assert_eq!(got, vec!["controlium.net"]);
}

#[test]
fn utf16le_respects_boundaries() {
    let s = make_set(&["controlium.net\tdelivery\tprimary\tt"]);
    let buf: Vec<u8> = "notcontrolium.network"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    assert!(s.search_bytes(&buf).is_empty());
}

#[test]
fn ipv6_exact_and_boundary() {
    let s = make_set(&["2a02:db8::1\tcandiru-ip\tprimary\tt"]);
    assert!(!s.search("peer 2a02:db8::1 seen").is_empty());
    assert!(s.search("2a02:db8::1a").is_empty());
}

#[test]
fn suffix_trap_domain_does_not_match() {
    let s = make_set(&["controlium.net\tdelivery\tprimary\tt"]);
    assert!(s.search("controlium.net.evil.example").is_empty());
}

#[test]
fn parent_and_child_one_record_collapses() {
    let s = make_set(&[
        "powerium.net\tdelivery\tprimary\tt",
        "noas.powerium.net\tdelivery\tprimary\tt",
    ]);
    let got: Vec<String> = s
        .search("cookie for .noas.powerium.net")
        .into_iter()
        .map(|i| i.value)
        .collect();
    assert_eq!(got, vec!["noas.powerium.net"]);
}

#[test]
fn type_inference_shapes() {
    assert_eq!(infer_type(&"a".repeat(64)), TYPE_SHA256);
    assert_eq!(infer_type("52.174.65.77"), TYPE_IP);
    assert_eq!(infer_type("2a02:db8::1"), TYPE_IP);
    assert_eq!(infer_type(TEST_DOMAIN), TYPE_DOMAIN);
}

#[test]
fn embedded_default_set_loads_with_provenance() {
    // The bundled set must load exactly as the file does, and keep its
    // curated date (the staleness reference).
    let s = zero_breach_rs::cli::embedded_ioc_set().expect("embedded set loads");
    assert!(s.len() > 300, "the real set has hundreds of indicators");
    assert!(s.asof.is_some(), "the curated date travels with the set");
    assert_eq!(s.hashes().len(), 2, "one sample hash and one driver hash");
    assert!(!s.network_strings().is_empty());
    for ind in &s.indicators {
        assert_eq!(infer_type(&ind.value), ind.kind);
    }
}
