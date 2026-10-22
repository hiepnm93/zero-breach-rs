//! Shared result types — the contract every scan module implements.
//! Ported from zero-breach scan/adint_scan/result.py (Apache-2.0).
//!
//! Doctrine baked into these types:
//!
//!   D3  Measured, never inferred. A module reports CLEAN only for checks
//!       that actually ran and found nothing. A check that could not run is
//!       UNKNOWN, which is a DISTINCT outcome from CLEAN. Never collapse
//!       the two.

use serde_json::json;

pub const CLEAN: &str = "CLEAN";
pub const HITS: &str = "HITS";
pub const UNKNOWN: &str = "UNKNOWN";
pub const PARTIAL: &str = "PARTIAL";

// Evidence grades, strongest first. See Hit::evidence for what each means.
pub const EV_ON_DISK: &str = "on-disk"; // a known sample's fingerprint matched a file
pub const EV_FILE_PATTERN: &str = "file-pattern"; // a research rule matched; needs verification
pub const EV_PERSISTENCE: &str = "persistence"; // named in an auto-start registration
pub const EV_CONTACTED: &str = "contacted"; // the device demonstrably talked to the host
pub const EV_DNS: &str = "dns-record"; // a resolver record; endpoint contact unverified
pub const EV_ATTEMPTED: &str = "attempted"; // a lookup happened but a filter blocked it
pub const EV_CONFIGURED: &str = "configured"; // named in local config, NOT as a block
pub const EV_REFERENCED: &str = "referenced"; // the string appeared in saved content

pub const EVIDENCE_ORDER: [&str; 8] = [
    EV_ON_DISK,
    EV_FILE_PATTERN,
    EV_PERSISTENCE,
    EV_CONTACTED,
    EV_DNS,
    EV_ATTEMPTED,
    EV_CONFIGURED,
    EV_REFERENCED,
];

/// Everything except `referenced` is a finding that needs a person to look at
/// it. This is deliberately a DENY-list of the one benign grade rather than an
/// allow-list of serious ones: a hit whose grade is missing or misspelled is
/// then treated as serious, never as harmless. The opposite default is how a
/// known sample on disk once came to be reported as "probably not a sign of
/// compromise".
pub fn is_serious(evidence: &str) -> bool {
    evidence != EV_REFERENCED
}

/// A single indicator match. `indicator` is the IOC string that matched
/// (domain, IP or hash); the tier/confidence come from the IOC set so every
/// hit carries its own provenance, never a bare "found something".
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Hit {
    pub indicator: String,
    pub location: String,
    pub detail: String,
    pub tier: String,
    pub confidence: String,
    /// Which published report this indicator came from.
    pub source: String,
    /// How strong this hit is as evidence — the single most important field
    /// for anyone triaging a result, because the artifact decides the meaning:
    ///
    ///   on-disk     a file on this machine has the fingerprint of a published
    ///               sample. Conclusive.
    ///   persistence the name appears in an auto-start/COM registration.
    ///   contacted   the browser or OS demonstrably talked to this host.
    ///   dns-record  the name or address appears in DNS cache or event log.
    ///   attempted   a lookup happened but a DNS filter blocked the answer.
    ///   configured  named in local configuration pointing somewhere REAL.
    ///   referenced  the string appeared in saved content — often a page ABOUT
    ///               the indicator. Usually NOT contact.
    ///
    /// Collapsing these would be the tool's most harmful bug in either
    /// direction. An empty or unknown grade is treated as SERIOUS.
    pub evidence: String,
    /// When the artifact says the contact happened, if it records that at all.
    pub observed: String,
    /// Which browser profile / account this came from, by its DISPLAY name
    /// (e.g. "Bubbles"), not just the folder name ("Profile 1"). The signed-in
    /// email address is deliberately NOT collected: reports get forwarded.
    pub profile: String,
}

impl Hit {
    pub fn new(indicator: &str, location: &str, detail: &str) -> Hit {
        Hit {
            indicator: indicator.to_string(),
            location: location.to_string(),
            detail: detail.to_string(),
            ..Default::default()
        }
    }

    pub fn is_contact(&self) -> bool {
        self.evidence == EV_CONTACTED
    }

    pub fn is_serious(&self) -> bool {
        is_serious(&self.evidence)
    }

    /// JSON shape, field order and values matching Python's
    /// `dataclasses.asdict(hit)`.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "indicator": self.indicator,
            "location": self.location,
            "detail": self.detail,
            "tier": self.tier,
            "confidence": self.confidence,
            "source": self.source,
            "evidence": self.evidence,
            "observed": self.observed,
            "profile": self.profile,
        })
    }
}

/// One named sub-check inside a module (e.g. "dns-cache"). `ran` records
/// whether it actually executed; `reason` explains why it did not. This is how
/// D3 (CLEAN != UNKNOWN) is enforced at the finest granularity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub ran: bool,
    pub reason: String,
}

impl Check {
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "name": self.name,
            "ran": self.ran,
            "reason": self.reason,
        })
    }
}

/// The result one scan module returns. Field order and JSON shape match
/// Python's `ModuleResult.to_dict()`.
#[derive(Clone, Debug)]
pub struct ModuleResult {
    pub name: String,
    pub checked: i64,
    pub skipped: i64,
    pub hits: Vec<Hit>,
    pub checks: Vec<Check>,
    pub notes: Vec<String>,
    /// Raw metrics, insertion-ordered the way the Python dict was.
    pub submetrics: Vec<(String, i64)>,
    /// Wall-clock seconds this module took, so a scan that prints nothing for
    /// ten minutes does not look hung.
    pub duration_s: f64,
    /// How far back in time this module's evidence actually reaches. A clean
    /// result is only as meaningful as the window it covers. Each entry is an
    /// object with earliest/basis/note and, where known, by_year and
    /// how_to_enable. Reported verbatim, because "we found nothing" and "we
    /// could only look back 11 weeks" are the same sentence.
    pub reach: Vec<(String, serde_json::Value)>,
}

impl ModuleResult {
    pub fn new(name: &str) -> ModuleResult {
        ModuleResult {
            name: name.to_string(),
            checked: 0,
            skipped: 0,
            hits: Vec::new(),
            checks: Vec::new(),
            notes: Vec::new(),
            submetrics: Vec::new(),
            duration_s: 0.0,
            reach: Vec::new(),
        }
    }

    pub fn add_hit(&mut self, hit: Hit) {
        self.hits.push(hit);
    }

    pub fn ran(&mut self, name: &str) {
        self.checks.push(Check {
            name: name.to_string(),
            ran: true,
            reason: String::new(),
        });
    }

    pub fn could_not_run(&mut self, name: &str, reason: &str) {
        self.checks.push(Check {
            name: name.to_string(),
            ran: false,
            reason: reason.to_string(),
        });
        self.notes
            .push(format!("{}: could not run ({})", name, reason));
    }

    pub fn note(&mut self, text: &str) {
        self.notes.push(text.to_string());
    }

    /// `submetrics[key] = submetrics.get(key, 0) + n`
    pub fn bump_metric(&mut self, key: &str, n: i64) {
        match self.submetrics.iter_mut().find(|(k, _)| k == key) {
            Some((_, v)) => *v += n,
            None => self.submetrics.push((key.to_string(), n)),
        }
    }

    pub fn set_metric(&mut self, key: &str, v: i64) {
        match self.submetrics.iter_mut().find(|(k, _)| k == key) {
            Some((_, slot)) => *slot = v,
            None => self.submetrics.push((key.to_string(), v)),
        }
    }

    pub fn metric(&self, key: &str) -> i64 {
        self.submetrics
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }

    pub fn reach_get(&self, key: &str) -> Option<&serde_json::Value> {
        self.reach.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn reach_set(&mut self, key: &str, value: serde_json::Value) {
        match self.reach.iter_mut().find(|(k, _)| k == key) {
            Some((_, slot)) => *slot = value,
            None => self.reach.push((key.to_string(), value)),
        }
    }

    pub fn has_check(&self, name: &str) -> bool {
        self.checks.iter().any(|c| c.name == name)
    }

    /// Status rollup. HITS if any hit; UNKNOWN if no check ran; CLEAN only if
    /// every recorded check ran; PARTIAL when gaps remain.
    pub fn status(&self) -> &'static str {
        if !self.hits.is_empty() {
            return HITS;
        }
        if self.checks.is_empty() {
            return UNKNOWN;
        }
        let ran = self.checks.iter().filter(|c| c.ran).count();
        if ran == 0 {
            return UNKNOWN;
        }
        if ran == self.checks.len() {
            return CLEAN;
        }
        PARTIAL
    }

    pub fn to_json(&self) -> serde_json::Value {
        let mut submetrics = serde_json::Map::new();
        for (k, v) in &self.submetrics {
            submetrics.insert(k.clone(), json!(v));
        }
        let mut reach = serde_json::Map::new();
        for (k, v) in &self.reach {
            reach.insert(k.clone(), v.clone());
        }
        json!({
            "name": self.name,
            "status": self.status(),
            "checked": self.checked,
            "skipped": self.skipped,
            "hits": self.hits.iter().map(|h| h.to_json()).collect::<Vec<_>>(),
            "checks": self.checks.iter().map(|c| c.to_json()).collect::<Vec<_>>(),
            "notes": self.notes,
            "submetrics": serde_json::Value::Object(submetrics),
            "reach": serde_json::Value::Object(reach),
            "duration_s": (self.duration_s * 10.0).round() / 10.0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_is_not_clean() {
        let r = ModuleResult::new("m");
        assert_eq!(r.status(), UNKNOWN);
        r.ran("a");
        assert_eq!(r.status(), CLEAN);
        let mut r2 = ModuleResult::new("m");
        r2.could_not_run("a", "why");
        assert_eq!(r2.status(), UNKNOWN);
        let mut r3 = ModuleResult::new("m");
        r3.ran("a");
        r3.could_not_run("b", "why");
        assert_eq!(r3.status(), PARTIAL);
        let mut r4 = ModuleResult::new("m");
        r4.could_not_run("a", "why");
        r4.add_hit(Hit::new("x.example", "loc", "d"));
        assert_eq!(r4.status(), HITS);
    }

    #[test]
    fn could_not_run_is_recorded_as_a_visible_note() {
        let mut r = ModuleResult::new("m");
        r.could_not_run("a-check", "because");
        assert!(r.notes.iter().any(|n| n.contains("could not run")));
        assert!(r.notes.iter().any(|n| n.contains("because")));
    }

    #[test]
    fn benign_evidence_deny_list() {
        assert!(!is_serious(EV_REFERENCED));
        for e in EVIDENCE_ORDER {
            if e != EV_REFERENCED {
                assert!(is_serious(e));
            }
        }
        assert!(is_serious(""), "an unknown grade is treated as serious");
        assert!(is_serious("misspelled"));
    }

    #[test]
    fn hit_json_shape() {
        let h = Hit::new("x.example", "loc", "d");
        let v = h.to_json();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "indicator",
                "location",
                "detail",
                "tier",
                "confidence",
                "source",
                "evidence",
                "observed",
                "profile"
            ]
        );
    }

    #[test]
    fn submetrics_are_ordered_and_bumpable() {
        let mut r = ModuleResult::new("m");
        r.bump_metric("sqlite", 1);
        r.bump_metric("blob", 1);
        r.bump_metric("sqlite", 2);
        assert_eq!(r.metric("sqlite"), 3);
        let keys: Vec<&str> = r
            .to_json()["submetrics"]
            .as_object()
            .unwrap()
            .keys()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(keys, vec!["sqlite", "blob"]);
    }
}
