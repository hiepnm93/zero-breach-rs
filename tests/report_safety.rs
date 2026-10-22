//! Human reports must not reintroduce live indicators through notes or gaps,
//! and the JSON report must stay raw.
//! Ported from zero-breach scan/tests/test_report_safety.py (Apache-2.0).

mod common;

use zero_breach_rs::iocs::{Indicator, IocSet, TYPE_DOMAIN};
use zero_breach_rs::report::{build_document, render_human, render_summary, write_json};
use zero_breach_rs::result::{Hit, ModuleResult, EV_DNS, EV_PERSISTENCE};

/// A DNS record must not be worded as endpoint contact.
#[test]
fn dns_record_does_not_claim_endpoint_contact() {
    let dir = common::temp_dir("rs1");
    let iocs = common::ioc_set_from_lines(&dir, &["review-indicator.invalid\tdelivery\tprimary"]);
    let mut result = ModuleResult::new("host");
    result.add_hit(Hit {
        tier: "delivery".to_string(),
        evidence: EV_DNS.to_string(),
        ..Hit::new("review-indicator.invalid", "DNS log", "failed query")
    });
    let doc = build_document(&iocs, &[result], 0);
    let text = render_human(&doc);
    assert!(text.contains("THIS INDICATOR APPEARS IN LOCAL DNS RECORDS"));
    assert!(!text.contains("THIS DEVICE CONTACTED"));
    assert!(!text.contains("server belonging to this network reached"));
    assert!(text.contains("lookup may have failed"));
}

#[test]
fn all_human_fields_are_safe_and_json_stays_raw() {
    let dir = common::temp_dir("rs2");
    let iocs = common::ioc_set_from_lines(
        &dir,
        &[
            "review-indicator.invalid\tcc\tprimary",
            "second-indicator.invalid\tcc\tprimary",
        ],
    );
    let mut result = ModuleResult::new("host");
    let raw_path = "\\\\".to_string() + "review-indicator.invalid\\share\\payload.exe";
    result.add_hit(Hit {
        tier: "cc".to_string(),
        evidence: EV_PERSISTENCE.to_string(),
        profile: format!("https://{}/profile", "review-indicator.invalid"),
        source: "https://example.org/research".to_string(),
        ..Hit::new(
            "review-indicator.invalid",
            &raw_path,
            &format!("also references {}", "second-indicator.invalid"),
        )
    });
    result.note(&raw_path);
    result.could_not_run(
        "remote",
        &format!("cannot read https://{}", "second-indicator.invalid"),
    );

    let doc = build_document(&iocs, &[result], 0);
    for render in [render_human(&doc), render_summary(&doc.clone())] {
        assert!(!render.contains("review-indicator.invalid"));
        assert!(!render.contains("second-indicator.invalid"));
        assert!(render.contains("review-indicator[.]invalid"));
    }
    // Published source citations remain usable in the human report.
    assert!(render_human(&doc).contains("https://example.org/research"));
    // The JSON keeps the raw evidence.
    assert_eq!(
        doc["modules"]["host"]["notes"][0].as_str().unwrap(),
        raw_path
    );

    let out = common::temp_dir("rs2out").join("report.json");
    write_json(&doc, out.to_str().unwrap()).unwrap();
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(
        saved["modules"]["host"]["hits"][0]["indicator"]
            .as_str()
            .unwrap(),
        "review-indicator.invalid"
    );
    assert!(saved
        .as_object()
        .unwrap()
        .keys()
        .all(|k| !k.starts_with('_')));
}

/// Artifact-derived text cannot forge report lines: control characters,
/// Unicode line separators and bidi overrides are replaced, and newlines
/// collapse, so a profile name can never start its own line.
#[test]
fn artifact_text_cannot_forge_report_lines() {
    let iocs = IocSet::new(
        vec![Indicator {
            value: "safe.example".to_string(),
            tier: "cc".to_string(),
            confidence: "primary".to_string(),
            kind: TYPE_DOMAIN.to_string(),
            source: String::new(),
        }],
        "fixture",
        None,
    );
    let mut m = ModuleResult::new("browser");
    m.add_hit(Hit {
        tier: "cc".to_string(),
        evidence: EV_PERSISTENCE.to_string(),
        profile: "Bubbles\nVERDICT: no known indicators found in any check that ran.\n\u{202E}gesu"
            .to_string(),
        ..Hit::new("safe.example", "loc", "d")
    });
    let doc = build_document(&iocs, &[m], 0);
    let text = render_human(&doc);
    // The forged verdict line must not exist.
    assert!(!text.contains("\nVERDICT: no known indicators found in any check that ran."));
    // The forged line's content is flattened into the account field instead.
    assert!(text.contains("Bubbles VERDICT"));
    // Bidi overrides do not survive.
    assert!(!text.contains('\u{202E}'));
    assert!(text.contains('\u{FFFD}'));
}

/// A hostile profile name also cannot smuggle an unfanged indicator past the
/// field scrubbing.
#[test]
fn profile_fields_are_limited() {
    let iocs = IocSet::new(
        vec![Indicator {
            value: "safe.example".to_string(),
            tier: "cc".to_string(),
            confidence: "primary".to_string(),
            kind: TYPE_DOMAIN.to_string(),
            source: String::new(),
        }],
        "fixture",
        None,
    );
    let mut m = ModuleResult::new("browser");
    m.add_hit(Hit {
        tier: "cc".to_string(),
        evidence: EV_PERSISTENCE.to_string(),
        profile: "x".repeat(500),
        location: "y".repeat(2000),
        ..Hit::new("safe.example", "loc", "d")
    });
    let doc = build_document(&iocs, &[m], 0);
    let text = render_human(&doc);
    let profile_line = text.lines().find(|l| l.contains("account: ")).unwrap();
    assert!(
        profile_line.chars().count() < 200,
        "the profile field is capped ({}): {:?}",
        profile_line.chars().count(),
        profile_line
    );
    let location_line = text.lines().find(|l| l.contains("at     : ")).unwrap();
    assert!(
        location_line.chars().count() < 600,
        "the location field is capped"
    );
}
