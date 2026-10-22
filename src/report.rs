//! Human-readable + machine-readable reporting, and the overall verdict.
//! Ported from zero-breach scan/adint_scan/report.py (Apache-2.0).
//!
//! Doctrine enforced here:
//!   D1  Every run that finds nothing prints, verbatim, the mandatory closing
//!       line.
//!   D3  A module that could not run is UNKNOWN, never CLEAN; gaps are stated
//!       out loud in the interface, not buried.
//!   The verdict for a hit is "investigate", never "you are compromised" — an
//!   ad impression is not proof of infection.

use serde_json::{json, Map, Value};

use crate::datetime::{self, CivilDate};
use crate::iocs::IocSet;
use crate::result::{
    is_serious, ModuleResult, EV_ATTEMPTED, EV_CONFIGURED, EV_CONTACTED, EV_DNS, EV_FILE_PATTERN,
    EV_ON_DISK, EV_PERSISTENCE, EV_REFERENCED, UNKNOWN,
};

/// The exact text required by D1. Do not reword.
pub const D1_LINE: &str = "No known indicators were found in the places that can be checked. \
                           This is not a clean bill of health.";

pub const V_HITS: &str = "INDICATORS_FOUND";
pub const V_NONE_WITH_GAPS: &str = "NO_KNOWN_INDICATORS_WITH_GAPS";
pub const V_NONE: &str = "NO_KNOWN_INDICATORS";

/// `platform.system()`-style names, so report wording matches the original.
pub fn system_name() -> &'static str {
    if cfg!(windows) {
        "Windows"
    } else if cfg!(target_os = "macos") {
        "Darwin"
    } else {
        "Linux"
    }
}

/// Correct the release string on Windows 11, the way the Python had to:
/// the underlying version API reports major version 10 for compatibility, and
/// build 22000 and up is what actually distinguishes Windows 11.
fn windows_release(release: &str, version: &str) -> String {
    if release != "10" {
        return release.to_string();
    }
    let build: i64 = match version.split('.').nth(2).and_then(|b| b.parse().ok()) {
        Some(b) => b,
        None => return release.to_string(),
    };
    if build >= 22_000 {
        "11".to_string()
    } else {
        release.to_string()
    }
}

#[cfg(windows)]
fn windows_version_string() -> (String, String) {
    use winreg::enums::*;
    use winreg::RegKey;
    let hk = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(cur) = hk.open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") {
        let build: String = cur
            .get_value("CurrentBuildNumber")
            .unwrap_or_else(|_| String::new());
        if !build.is_empty() {
            return ("10".to_string(), format!("10.0.{}", build));
        }
    }
    (String::new(), String::new())
}

#[cfg(not(windows))]
fn windows_version_string() -> (String, String) {
    (String::new(), String::new())
}

#[cfg(target_os = "linux")]
fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
fn kernel_release() -> String {
    String::new()
}

fn machine_name() -> &'static str {
    let arch = std::env::consts::ARCH;
    if cfg!(windows) {
        // platform.machine() reports the Windows spelling.
        match arch {
            "x86_64" => "AMD64",
            "aarch64" => "ARM64",
            _ => arch,
        }
    } else {
        arch
    }
}

fn platform_info() -> Value {
    let (release, version) = if cfg!(windows) {
        let (r, v) = windows_version_string();
        (if r.is_empty() { "10".to_string() } else { r }, v)
    } else {
        let r = kernel_release();
        let v = r.clone();
        (r, v)
    };
    let release = if cfg!(windows) {
        windows_release(&release, &version)
    } else {
        release
    };
    json!({
        "system": system_name(),
        "release": release,
        "version": version,
        "machine": machine_name(),
        // Same slot as the Python report's interpreter version; this build's
        // toolchain is what a reproducibility question is about here.
        "python": format!("rust {}", option_env!("ZB_RUSTC_RELEASE").unwrap_or("(unknown)")),
    })
}

/// The report document, with the same fields and JSON shape as the Python
/// `build_document`. Two internal keys (prefixed `_`) exist for rendering and
/// are stripped from the JSON report exactly as upstream did.
pub fn build_document(iocs: &IocSet, modules: &[ModuleResult], started_unix: i64) -> Value {
    let hits_total: i64 = modules.iter().map(|m| m.hits.len() as i64).sum();
    let mut gaps: Vec<String> = Vec::new();
    for m in modules {
        for c in &m.checks {
            if !c.ran {
                gaps.push(format!(
                    "{}/{}: {}",
                    m.name,
                    c.name,
                    if c.reason.is_empty() {
                        ""
                    } else {
                        c.reason.as_str()
                    }
                ));
            }
        }
        // A module that produced NO checks at all is UNKNOWN — it observed
        // nothing — but has no failed Check to turn into a gap, so without
        // this it is invisible to the verdict and a "nothing found" reads as
        // clean.
        if m.status() == UNKNOWN && m.checks.is_empty() {
            gaps.push(format!(
                "{}: nothing in this check could run, so it cleared nothing",
                m.name
            ));
        }
    }

    let status = if hits_total > 0 {
        V_HITS
    } else if !gaps.is_empty() {
        V_NONE_WITH_GAPS
    } else {
        V_NONE
    };

    let mut module_map = Map::new();
    for m in modules {
        module_map.insert(m.name.clone(), m.to_json());
    }

    json!({
        "tool": {"name": "adint-scan", "version": env!("CARGO_PKG_VERSION")},
        "timestamp": datetime::iso_from_unix(started_unix),
        "platform": platform_info(),
        "ioc_set": {
            "path": iocs.source_path,
            "count": iocs.len(),
            "age_days": iocs.age_days(),
            "stale": iocs.is_stale(),
        },
        "modules": Value::Object(module_map),
        "verdict": {
            "status": status,
            "hits_total": hits_total,
            "gaps": gaps,
        },
        // D1 line is present whenever nothing was found (CLEAN or with gaps).
        "doctrine_line": if hits_total > 0 { Value::Null } else { json!(D1_LINE) },
        // Whether a "HOW TO TURN ON DNS HISTORY" block will actually be
        // rendered, so the summary's pointer to it does not dangle on a host
        // where no reach entry carried how_to_enable.
        "_dns_howto": modules.iter().any(|m| {
            m.reach.iter().any(|(_, info)| {
                info.get("how_to_enable")
                    .map(|h| !h.as_array().map(|a| a.is_empty()).unwrap_or(true))
                    .unwrap_or(false)
            })
        }),
        "_indicators": iocs.network_strings(),
    })
}

/// Write the JSON report. The internal `_`-prefixed rendering flags are not
/// part of the evidence record.
pub fn write_json(document: &Value, path: &str) -> Result<(), String> {
    let doc = match document {
        Value::Object(map) => {
            let mut clean = Map::new();
            for (k, v) in map {
                if !k.starts_with('_') {
                    clean.insert(k.clone(), v.clone());
                }
            }
            Value::Object(clean)
        }
        other => other.clone(),
    };
    let mut text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    text.push('\n');
    std::fs::write(path, text).map_err(|e| e.to_string())
}

// --- human-readable rendering ----------------------------------------------

const RULE: &str = "========================================================================";

/// Raw metric keys are developer shorthand. Say what each number is, in words,
/// because "com_registrations=37" tells a reader nothing about whether 37 is
/// bad.
fn metric_label(key: &str) -> Option<&'static str> {
    Some(match key {
        "sqlite" => "browser databases read",
        "blob" => "cache / stored-data files searched",
        "hsts_entries" => "HSTS security records checked (proof of past connections)",
        "connection_records" => "saved connection records checked",
        "files_hashed" => "files fingerprinted",
        "files_pattern_scanned" => "files checked against Candiru patterns",
        "bytes_pattern_scanned" => "bytes checked against Candiru patterns",
        "com_registrations" => "auto-start COM registrations reviewed",
        "com_user_writable" => "   of those, in a folder you can write to",
        "dns_cache_entries" => "names in the DNS cache since last reboot",
        "dns_log_records" => "DNS history records available",
        "dns_log_events_scanned" => "DNS history events searched",
        "hosts_entries" => "entries in the hosts file",
        "hosts_blocked_indicators" => "   of those, indicators you are BLOCKING (good)",
        "known_paths_checked" => "known malware file-paths checked",
        "known_paths_present" => "   of those, a file is present at (see notes)",
        _ => return None,
    })
}

fn describe_metrics(metrics: &Map<String, Value>) -> Vec<String> {
    let mut out = Vec::new();
    for (key, value) in metrics {
        let n = value.as_i64().unwrap_or(0);
        if key == "bytes_hashed" {
            // Python's "{:,.1f} GB of files read".
            let gb = n as f64 / 1e9;
            let fixed = format!("{:.1}", gb);
            let (int_part, frac) = fixed.split_once('.').unwrap_or((fixed.as_str(), "0"));
            out.push(format!(
                "{}.{} GB of files read",
                crate::text::fmt_count_i(int_part.parse::<i64>().unwrap_or(0)),
                frac
            ));
            continue;
        }
        if key == "dns_log_enabled" {
            out.push(format!(
                "Windows DNS history logging: {}",
                if n != 0 {
                    "ON"
                } else {
                    "OFF (the Windows default)"
                }
            ));
            continue;
        }
        match metric_label(key) {
            Some(label) => out.push(format!("{}: {}", label, crate::text::fmt_count_i(n))),
            None => out.push(format!("{}: {}", key, crate::text::fmt_count_i(n))),
        }
    }
    out
}

/// Sanitize artifact-derived fields without changing the JSON evidence.
///
/// Notes and gaps can quote remote paths just as hits can. Published source
/// citations and the fixed help links remain usable.
fn scrub(value: &Value, limit: usize) -> Value {
    match value {
        Value::String(s) => Value::String(defang_text(&safe_text(s, limit), "")),
        Value::Array(a) => Value::Array(a.iter().map(|v| scrub(v, limit)).collect()),
        Value::Object(o) => {
            let mut out = Map::new();
            for (k, v) in o {
                out.insert(k.clone(), scrub(v, limit));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

const HIT_FIELD_LIMITS: [(&str, usize); 4] = [
    ("location", 500),
    ("detail", 500),
    ("observed", 64),
    ("profile", 120),
];

fn human_document(document: &Value) -> Value {
    let mut doc = document.clone();
    if let Some(modules) = doc.get_mut("modules").and_then(|m| m.as_object_mut()) {
        for (_name, m) in modules.iter_mut() {
            for key in ["notes", "checks", "reach"] {
                if let Some(v) = m.get_mut(key) {
                    let cleaned = scrub(v, 2000);
                    *v = cleaned;
                }
            }
            if let Some(hits) = m.get_mut("hits").and_then(|h| h.as_array_mut()) {
                for hit in hits.iter_mut() {
                    for (key, limit) in HIT_FIELD_LIMITS {
                        if let Some(v) = hit.get_mut(key) {
                            *v = scrub(v, limit);
                        }
                    }
                }
            }
        }
    }
    if let Some(verdict) = doc.get_mut("verdict") {
        if let Some(gaps) = verdict.get_mut("gaps") {
            *gaps = scrub(gaps, 2000);
        }
    }
    doc
}

/// Make an indicator safe to paste into an email or chat without a client,
/// gateway or link scanner auto-fetching it. The report is designed to be
/// forwarded to Access Now / Amnesty, and the tool's own rule is never to
/// contact an indicator — so it must not ship them in a fetchable form. The
/// JSON report keeps the raw value; only the human text is defanged.
pub fn defang(indicator: &str) -> String {
    let out = indicator
        .replace("https://", "hxxps://")
        .replace("http://", "hxxp://");
    // Neuter the last dot (domains) or wrap every dot (IPs) so nothing resolves.
    if indicator.chars().any(|c| c.is_alphabetic()) && out.contains('.') {
        if let Some(i) = out.rfind('.') {
            return format!("{}[.]{}", &out[..i], &out[i + 1..]);
        }
    }
    out.replace('.', "[.]")
}

fn scheme_defang(text: &str) -> String {
    // A URL scheme is all a mail gateway, link preview or security scanner
    // needs in order to fetch the thing. ftp:// is covered too, because a
    // detail line quotes whatever was in the saved page.
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &bytes[i..];
        let (replacement, used) = if rest.len() >= 8 && rest[..8].eq_ignore_ascii_case(b"https://")
        {
            ("hxxps://", 8)
        } else if rest.len() >= 7 && rest[..7].eq_ignore_ascii_case(b"http://") {
            ("hxxp://", 7)
        } else if rest.len() >= 6 && rest[..6].eq_ignore_ascii_case(b"ftp://") {
            ("fxp://", 6)
        } else {
            ("", 0)
        };
        if used > 0 {
            out.push_str(replacement);
            i += used;
        } else {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Case-insensitive replace of every `needle` occurrence, passing the matched
/// text to the replacement (so the match's own case survives, as
/// `re.sub(re.escape(indicator), ...)` did).
fn replace_ci<F: Fn(&str) -> String>(hay: &str, needle: &str, replacement: F) -> String {
    if needle.is_empty() || hay.is_empty() {
        return hay.to_string();
    }
    let nb = needle.as_bytes();
    let hb = hay.as_bytes();
    let mut out = String::with_capacity(hay.len());
    let mut i = 0;
    while i + nb.len() <= hb.len() {
        if hb[i..i + nb.len()].eq_ignore_ascii_case(nb) {
            let matched = &hay[i..i + nb.len()];
            out.push_str(&replacement(matched));
            i += nb.len();
        } else {
            let ch = hay[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    if i < hb.len() {
        out.push_str(&hay[i..]);
    }
    out
}

/// Defang the indicator traces inside a free-text field — a detail line, a
/// path — and change nothing else about it.
///
/// Deliberately NOT a general "wrap every dot" pass. A location is usually a
/// Windows path, and blanket dot-wrapping would mangle real file and folder
/// names into something the person acting on this report can no longer find
/// on their own disk.
pub fn defang_text(text: &str, indicator: &str) -> String {
    let mut out = scheme_defang(text);
    if !indicator.is_empty() {
        let defanged = defang(indicator);
        if defanged != indicator {
            out = replace_ci(&out, indicator, |_| defanged.clone());
        }
    }
    out
}

/// Control characters, Unicode line separators and bidirectional overrides
/// (which can visually reverse a line without any newline) are replaced, and
/// newlines collapse to spaces so a field can never begin a line of its own.
/// The JSON report keeps the raw evidence.
fn is_unsafe_char(c: char) -> bool {
    matches!(c as u32,
        0x00..=0x08 | 0x0b..=0x1f | 0x7f..=0x9f
        | 0x2028 | 0x2029 | 0x202a..=0x202e | 0x2066..=0x2069)
}

fn safe_text(value: &str, limit: usize) -> String {
    let text = value.replace("\r\n", " ").replace(['\n', '\r'], " ");
    let mut out = String::with_capacity(text.len());
    let mut truncated = false;
    for (count, c) in text.chars().enumerate() {
        if count >= limit {
            truncated = true;
            break;
        }
        out.push(if is_unsafe_char(c) { '\u{FFFD}' } else { c });
    }
    if truncated {
        out.push('\u{2026}');
    }
    out
}

fn evidence_gloss(tier: &str, evidence: &str) -> String {
    // What this grade establishes for this hit (tier-aware).
    if tier == "vuln-driver" && evidence == EV_ON_DISK {
        return ON_DISK_NOT_MALWARE_GLOSS.to_string();
    }
    if evidence == EV_ON_DISK && tier != "sample" {
        return "a file fingerprint matched an indicator, but its classification \
                does not identify it as a known spyware sample; expert review \
                is needed"
            .to_string();
    }
    if tier == "candiru-ip" && evidence == EV_CONTACTED {
        return "a connection record names this IP address; who controlled it at \
                the time is not established by this match"
            .to_string();
    }
    evidence_meaning(evidence).unwrap_or("").to_string()
}

fn evidence_meaning(evidence: &str) -> Option<&'static str> {
    Some(match evidence {
        EV_FILE_PATTERN => {
            "patterns inside a file matched a published detection rule. This is \
             a lead for investigation, not a confirmed infection or an exact \
             known-file match"
        }
        EV_ON_DISK => {
            "a file on this machine has the fingerprint of a published spyware \
             sample - this is conclusive, not circumstantial"
        }
        EV_PERSISTENCE => {
            "the name is registered to run automatically on this machine - a \
             hallmark of installed spyware"
        }
        EV_CONTACTED => "this device demonstrably communicated with it",
        EV_DNS => {
            "the name or address appears in local DNS data; this does not \
             establish communication with the indicated server, and a logged \
             lookup may have failed"
        }
        EV_ATTEMPTED => {
            "something on this device looked the name up, but a filter blocked \
             the connection"
        }
        EV_CONFIGURED => {
            "the name is in local configuration pointing at a real address (a \
             protective block entry is not reported at all)"
        }
        EV_REFERENCED => {
            "the name appeared in saved page content - most often a page ABOUT \
             this campaign, not contact with it"
        }
        _ => return None,
    })
}

/// What a hit in each tier actually MEANS, in plain language. The tier is the
/// whole point of curating the indicator set: contact with an ad tracker and
/// contact with a command-and-control server are different events, and a
/// report that renders them identically has failed the person reading it.
fn tier_meaning(tier: &str) -> Option<&'static str> {
    Some(match tier {
        "delivery" => {
            "Advertising/tracking infrastructure belonging to this network. The \
             evidence grade says what was observed; a DNS record or saved \
             reference does not prove an ad reached this device. An ad \
             impression is NOT evidence of infection."
        }
        "cc" => {
            "A Candiru command-and-control server. This is the most serious \
             class of indicator - it is the address an active implant talks to."
        }
        "validator" => {
            "A Candiru validator server. These profiled a device and decided, \
             per device, whether to deliver an exploit. Contact suggests this \
             device was being assessed as a target."
        }
        "candiru" => {
            "A server attributed to Candiru by Recorded Future. Its exact role \
             is not published, so treat it as serious but unspecified."
        }
        "candiru-ip" => {
            "An IP address attributed to Candiru infrastructure in 2025. Weak \
             on its own: cloud IP addresses are reassigned to unrelated, \
             innocent customers within months."
        }
        "historical" => {
            "Infrastructure from separate, older Candiru campaigns. Interpret \
             dated evidence in the cited report's context; current ownership \
             and activity are not established."
        }
        "sample" => {
            "The file fingerprint of a published Candiru sample. A match here \
             is conclusive, not circumstantial."
        }
        "candiru-pattern" => {
            "A published Candiru detection rule matched patterns inside a file. \
             This needs expert verification; it is not an exact sample \
             identification or proof that spyware ran."
        }
        "vuln-driver" => {
            "A LEGITIMATE, signed third-party driver that this actor abuses to \
             disable protections (bring-your-own-vulnerable-driver). The file \
             itself is not spyware and is present on clean machines that \
             genuinely use that hardware or software. This is a lead worth \
             checking - who installed it, and when - NOT evidence that spyware \
             is on this machine."
        }
        _ => return None,
    })
}

/// A short imperative headline per grade. The ones that are not
/// EV_REFERENCED are serious and each gets its own, so a sample on disk and a
/// persistence entry can never be rendered as "probably nothing".
fn evidence_headline(evidence: &str) -> Option<&'static str> {
    Some(match evidence {
        EV_FILE_PATTERN => "A FILE MATCHED A CANDIRU DETECTION RULE - NEEDS REVIEW",
        EV_ON_DISK => "A KNOWN SPYWARE FILE IS ON THIS MACHINE",
        EV_PERSISTENCE => "SOMETHING IS SET TO RUN AUTOMATICALLY FROM THIS INFRASTRUCTURE",
        EV_CONTACTED => "THIS DEVICE CONTACTED THIS INFRASTRUCTURE",
        EV_DNS => "THIS INDICATOR APPEARS IN LOCAL DNS RECORDS",
        EV_ATTEMPTED => "THIS DEVICE TRIED TO REACH THIS INFRASTRUCTURE (a filter blocked it)",
        EV_CONFIGURED => "THIS INFRASTRUCTURE IS CONFIGURED ON THIS MACHINE",
        _ => return None,
    })
}

const ON_DISK_NOT_MALWARE_HEADLINE: &str =
    "A LEGITIMATE FILE THIS ATTACKER IS KNOWN TO ABUSE IS ON THIS MACHINE";
const ON_DISK_NOT_MALWARE_GLOSS: &str = "this file is NOT spyware - it is signed, legitimate \
     software that this actor loads to disable protections. It is also installed for honest \
     reasons. Worth establishing how it got here; not proof of anything";

/// The summary headline for one serious hit, chosen by grade AND tier.
fn headline_for(hit: &Value) -> String {
    let tier = hit["tier"].as_str().unwrap_or("");
    let evidence = hit["evidence"].as_str().unwrap_or("");
    if tier == "vuln-driver" && evidence == EV_ON_DISK {
        return ON_DISK_NOT_MALWARE_HEADLINE.to_string();
    }
    if evidence == EV_ON_DISK && tier != "sample" {
        return "A FILE FINGERPRINT MATCHED; ITS CLASSIFICATION NEEDS REVIEW".to_string();
    }
    if tier == "candiru-ip" && evidence == EV_CONTACTED {
        return "THIS DEVICE CONTACTED A HISTORICALLY ATTRIBUTED IP ADDRESS".to_string();
    }
    evidence_headline(evidence)
        .unwrap_or("A SERIOUS INDICATOR MATCHED")
        .to_string()
}

/// Human next steps, separate from evidence grades and the JSON verdict.
///
/// 0: saved context; 1: self-review; 2: qualified interpretation;
/// 3: prompt expert help. Unknown metadata never becomes reassurance.
fn recommended_action(hit: &Value) -> i64 {
    let evidence = hit["evidence"].as_str().unwrap_or("");
    let tier = hit["tier"].as_str().unwrap_or("");
    if evidence == EV_REFERENCED {
        return 0;
    }
    if evidence == EV_ON_DISK && tier == "vuln-driver" {
        return 1;
    }
    if evidence == EV_ON_DISK || evidence == EV_PERSISTENCE {
        return 3;
    }
    if (tier == "delivery" || tier == "candiru-ip")
        && matches!(
            evidence,
            EV_CONTACTED | EV_DNS | EV_ATTEMPTED | EV_CONFIGURED
        )
    {
        return 1;
    }
    2
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > width {
            lines.push(cur);
            cur = word.to_string();
        } else if cur.is_empty() {
            cur = word.to_string();
        } else {
            cur.push(' ');
            cur.push_str(word);
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

fn advice_paragraph(out: &mut Vec<String>, text: &str) {
    for line in wrap(text, 66) {
        out.push(format!("    {}", line));
    }
}

fn evidence_sort_key(evidence: &str) -> f64 {
    match evidence {
        EV_ON_DISK => 0.0,
        EV_FILE_PATTERN => 0.5,
        EV_PERSISTENCE => 1.0,
        EV_CONTACTED => 2.0,
        EV_DNS => 3.0,
        EV_ATTEMPTED => 4.0,
        EV_CONFIGURED => 5.0,
        EV_REFERENCED => 6.0,
        _ => 0.0,
    }
}

/// The part a person actually reads. Answers, in order: what was found, what
/// it means, what to do, and what this scan could not check.
pub fn render_summary(document: &Value) -> String {
    let document = human_document(document);
    let mut out: Vec<String> = Vec::new();
    let v = &document["verdict"];

    let mut all_hits: Vec<&Value> = Vec::new();
    if let Some(modules) = document["modules"].as_object() {
        for (_name, m) in modules {
            if let Some(hits) = m["hits"].as_array() {
                all_hits.extend(hits.iter());
            }
        }
    }
    let serious: Vec<&Value> = all_hits
        .iter()
        .copied()
        .filter(|h| is_serious(h["evidence"].as_str().unwrap_or("")))
        .collect();
    let benign: Vec<&Value> = all_hits
        .iter()
        .copied()
        .filter(|h| !is_serious(h["evidence"].as_str().unwrap_or("")))
        .collect();

    out.push(RULE.to_string());
    out.push("  SUMMARY  —  read this part".to_string());
    out.push(RULE.to_string());

    if all_hits.is_empty() {
        out.push("  RESULT: no known indicator was found in anything that could be".to_string());
        out.push("          checked.".to_string());
        out.push(String::new());
        out.push(
            "  This is NOT a clean bill of health. See the two sections below for".to_string(),
        );
        out.push("  what was searched and, more importantly, what could not be.".to_string());
    } else if !serious.is_empty() {
        let n = serious.len();
        let action = serious
            .iter()
            .map(|h| recommended_action(h))
            .max()
            .unwrap_or(0);
        if action == 3 {
            out.push("  RESULT: SERIOUS FINDING - seek expert help promptly.".to_string());
        } else if action == 2 {
            out.push(
                "  RESULT: potentially SERIOUS finding - qualified review recommended.".to_string(),
            );
        } else {
            out.push(format!(
                "  RESULT: {} finding{} to review; start with the saved context.",
                n,
                if n == 1 { "" } else { "s" }
            ));
        }
        if !benign.is_empty() {
            let nb = benign.len();
            out.push(format!(
                "          ({} further match{} {} only {} in saved page content.)",
                nb,
                if nb == 1 { "" } else { "es" },
                if nb == 1 { "is" } else { "are" },
                if nb == 1 { "a reference" } else { "references" }
            ));
        }
        out.push(String::new());
        out.push("  WHAT WAS FOUND".to_string());
        // Strongest grade first; collapse repeats of the same indicator+grade
        // so one domain in three cache files is not three lines.
        for h in dedup_serious(&serious) {
            let headline = headline_for(h);
            out.push(format!("    >> {}", headline));
            out.push(format!(
                "       {}  [{}]",
                defang(h["indicator"].as_str().unwrap_or("")),
                h["tier"].as_str().unwrap_or("")
            ));
            if let Some(meaning) = tier_meaning(h["tier"].as_str().unwrap_or("")) {
                for line in wrap(meaning, 64) {
                    out.push(format!("          {}", line));
                }
            }
            let profile = h["profile"].as_str().unwrap_or("");
            if !profile.is_empty() {
                out.push(format!("          Account: {}", profile));
            }
            let observed = h["observed"].as_str().unwrap_or("");
            if !observed.is_empty() {
                out.push(format!(
                    "          When: {}",
                    observed
                        .chars()
                        .take(19)
                        .collect::<String>()
                        .replace('T', " ")
                ));
            }
            out.push(format!(
                "          Where: {}",
                defang_text(
                    h["location"].as_str().unwrap_or(""),
                    h["indicator"].as_str().unwrap_or("")
                )
            ));
            out.push(String::new());
        }
        next_steps(&mut out, &serious);
        if !benign.is_empty() {
            let n_b = benign.len();
            out.push(String::new());
            out.push(format!(
                "    The {} reference-only match{} {} listed in DETAIL. Saved text",
                n_b,
                if n_b == 1 { "" } else { "es" },
                if n_b == 1 { "is" } else { "are" }
            ));
            out.push("    can mention an indicator without a connection to it.".to_string());
        }
    } else {
        let n = benign.len();
        out.push(format!(
            "  RESULT: {} match{} found, all of them reference-only.",
            n,
            if n == 1 { "" } else { "es" }
        ));
        out.push(String::new());
        out.push("  WHAT THIS PROBABLY IS".to_string());
        for line in wrap(
            "These matches are names found in saved content, such as page text, \
             an unvisited bookmark or browser storage. A reference does not \
             establish a connection, execution or infection. Check the saved \
             title, location and date in DETAIL without opening the indicator \
             address. A reference alone is probably not a sign of compromise; \
             it does not clear the device either.",
            68,
        ) {
            out.push(format!("    {}", line));
        }
        out.push(String::new());
        advice_paragraph(
            &mut out,
            "A reference alone does not call for a helpline referral. If you have \
             a credible targeting concern or a genuine security notification, \
             seek qualified help directly regardless of this result.",
        );
    }

    let gaps: Vec<String> = v["gaps"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|g| g.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if !gaps.is_empty() {
        out.push(String::new());
        out.push(format!(
            "  WHAT COULD NOT BE CHECKED  ({} gap{})",
            gaps.len(),
            if gaps.len() == 1 { "" } else { "s" }
        ));
        let shown = &gaps[..gaps.len().min(4)];
        for g in shown {
            for (i, line) in wrap(g, 66).into_iter().enumerate() {
                out.push(format!("    {}{}", if i == 0 { "- " } else { "  " }, line));
            }
        }
        if gaps.len() > shown.len() {
            out.push(format!(
                "    ... and {} more, listed in full at the end of this report.",
                gaps.len() - shown.len()
            ));
        }
        // The DNS gap is the one a reader can actually close - but only point
        // at the instructions if they were actually rendered (they are not on
        // a non-Windows host), or the pointer dangles.
        let dns_howto = document["_dns_howto"].as_bool().unwrap_or(false);
        if dns_howto && gaps.iter().any(|g| g.to_lowercase().contains("dns")) {
            out.push(String::new());
            out.push("    -> You can fix the DNS gap for next time, in one command.".to_string());
            out.push(
                "       See \"HOW TO TURN ON DNS HISTORY\" further down. It tells you".to_string(),
            );
            out.push("       nothing about the past, but it means a future check can".to_string());
            out.push("       actually answer the question.".to_string());
        }
    }
    // Every report, not only one with findings. A clean or reference-only
    // result is the one people are most relaxed about posting publicly to say
    // "I'm fine" - and it carries the same usernames, profile names and paths.
    out.push(String::new());
    for line in wrap(PRIVACY_NOTE, 68) {
        out.push(format!("  {}", line));
    }
    out.push(RULE.to_string());
    out.push(String::new());
    defang_report(&out.join("\n"), &document)
}

const PRIVACY_NOTE: &str = "Before you share this report: it can contain your Windows username, \
     browser profile names, file paths and browsing details. Ask a responder how to share \
     evidence securely; do not post the full report publicly.";

/// Collapse repeats of the same indicator at the same grade, strongest grade
/// first, so one domain found in three cache files is one line, not three.
fn dedup_serious<'a>(hits: &[&'a Value]) -> Vec<&'a Value> {
    let order = |evidence: &str| -> i64 {
        match evidence {
            EV_ON_DISK => 0,
            EV_PERSISTENCE => 1,
            EV_CONTACTED => 2,
            EV_DNS => 3,
            EV_ATTEMPTED => 4,
            EV_CONFIGURED => 5,
            _ => 99,
        }
    };
    let mut seen: Vec<(String, String, &Value)> = Vec::new();
    for h in hits {
        let key = (
            h["indicator"].as_str().unwrap_or("").to_string(),
            h["evidence"].as_str().unwrap_or("").to_string(),
        );
        if !seen.iter().any(|(k, _e, _)| *k == key.0 && *_e == key.1) {
            seen.push((key.0, key.1, h));
        }
    }
    let mut out: Vec<&Value> = seen.into_iter().map(|(_, _, h)| h).collect();
    out.sort_by_key(|h| order(h["evidence"].as_str().unwrap_or("")));
    out
}

fn next_steps(out: &mut Vec<String>, hits: &[&Value]) {
    let action = hits
        .iter()
        .map(|h| recommended_action(h))
        .max()
        .unwrap_or(0);
    out.push("  WHAT TO DO".to_string());
    if hits
        .iter()
        .any(|h| h["evidence"].as_str().unwrap_or("") == EV_FILE_PATTERN)
    {
        advice_paragraph(
            out,
            "A file matched a Candiru pattern rule. Ask a qualified incident \
             responder to verify the named file and rule. Preserve the file and \
             this report; do not open, run or delete the file. A pattern match \
             alone does not prove infection or that the file executed.",
        );
        out.push(String::new());
        if hits.iter().all(|h| {
            matches!(
                h["evidence"].as_str().unwrap_or(""),
                EV_FILE_PATTERN | EV_REFERENCED
            )
        }) {
            return;
        }
    }
    if action == 3 {
        advice_paragraph(
            out,
            "Seek expert help promptly. Preserve this report and the named files \
             or registrations. Do NOT delete, move, run or try to clean them. A \
             file match establishes presence; a registration establishes \
             configuration. Neither alone establishes that spyware executed.",
        );
        out.push(String::new());
        advice_paragraph(
            out,
            "Contact a qualified incident responder or your organisation's \
             security team. You do not need to finish investigating first. \
             Support options are at the end of this report.",
        );
    } else if action == 2 {
        advice_paragraph(
            out,
            "Qualified interpretation is recommended. Review the evidence type, \
             saved date and location below. A DNS record may be a failed \
             lookup; it does not establish a connection. Missing or \
             unrecognised evidence labels also need review, not reassurance.",
        );
        out.push(String::new());
        advice_paragraph(
            out,
            "A connection record for command-and-control, validator or other \
             attributed spyware infrastructure warrants specialist review. For \
             a DNS-only or configuration finding, seek qualified help if the \
             local context does not explain it, or if you have a credible \
             reason to believe you are being targeted. These records do not by \
             themselves establish infection.",
        );
        out.push(String::new());
        advice_paragraph(
            out,
            "Keep the report and original records. Do NOT delete or clean them \
             while arranging review. Your organisation's security team or a \
             qualified incident responder can help.",
        );
    } else {
        advice_paragraph(
            out,
            "Start with the saved evidence below. Check the indicator's role, \
             evidence type, browser/profile, date (if available), and file or \
             record that matched. Use the report and existing records; do not \
             visit the indicator to investigate it.",
        );
        if hits.iter().any(|h| {
            h["tier"].as_str().unwrap_or("") == "delivery"
                && matches!(
                    h["evidence"].as_str().unwrap_or(""),
                    EV_CONTACTED | EV_DNS | EV_ATTEMPTED
                )
        }) {
            out.push(String::new());
            advice_paragraph(
                out,
                "Advertising-network records alone do not show that you were \
                 selected for an exploit or infected. A connection can result \
                 from an ordinary ad; a DNS record does not even establish that \
                 connection. This finding alone does not call for a spyware \
                 helpline referral.",
            );
        }
        if hits.iter().any(|h| {
            h["tier"].as_str().unwrap_or("") == "vuln-driver"
                && h["evidence"].as_str().unwrap_or("") == EV_ON_DISK
        }) {
            out.push(String::new());
            advice_paragraph(
                out,
                "For the legitimate driver, check whether its location and \
                 installation history match hardware or software you use. Your \
                 IT support or the software vendor can help identify it. Do not \
                 delete it solely because of this match.",
            );
        }
        if hits
            .iter()
            .any(|h| h["tier"].as_str().unwrap_or("") == "candiru-ip")
        {
            out.push(String::new());
            advice_paragraph(
                out,
                "For a historical IP address, ownership can change. The tool has \
                 not established who controlled it at the time of this record. \
                 Check the saved date against the cited research; an absent date \
                 leaves that question unresolved.",
            );
        }
        if hits
            .iter()
            .any(|h| h["evidence"].as_str().unwrap_or("") == EV_CONFIGURED)
        {
            out.push(String::new());
            advice_paragraph(
                out,
                "For a configuration entry, check who or what created it and why. \
                 An ordinary ad impression does not explain a local hosts-file \
                 entry. Do not edit it merely to make this finding disappear.",
            );
        }
        out.push(String::new());
        advice_paragraph(
            out,
            "Keep the report. If you cannot explain a finding, ask trusted IT \
             support for help interpreting it. Stronger findings or a credible \
             targeting concern warrant qualified security help directly; you do \
             not have to complete these steps first.",
        );
    }
    out.push(String::new());
    advice_paragraph(
        out,
        "Do NOT open, visit or look up indicator addresses. Keep the [.] \
         spelling when sharing them.",
    );
}

fn support_options(out: &mut Vec<String>) {
    out.push("WHEN TO SEEK SUPPORT".to_string());
    out.push(
        "A credible targeting concern or a genuine security notification warrants".to_string(),
    );
    out.push("qualified help regardless of this scan's result. You do not need to".to_string());
    out.push("complete self-checks first. Contact your organisation's security team".to_string());
    out.push("or a qualified incident responder.".to_string());
    out.push(String::new());
    out.push("For journalists, activists, human-rights defenders and other civil".to_string());
    out.push("society members, Access Now offers a Digital Security Helpline:".to_string());
    out.push("  https://www.accessnow.org/help/".to_string());
    out.push("  Eligibility and support: https://www.accessnow.org/help/helpline-faq/".to_string());
    out.push("Check its intake instructions before sending private evidence.".to_string());
    out.push(String::new());
    out.push("Research and further guidance:".to_string());
    out.push("  Amnesty International Security Lab  https://securitylab.amnesty.org/".to_string());
    out.push("  The Citizen Lab                     https://citizenlab.ca/".to_string());
    out.push(String::new());
    out.push("A saved reference or advertising-network trace alone is not a reason".to_string());
    out.push("to assume spyware infection. No result from this tool rules it out.".to_string());
}

/// Cover every occurrence, including notes and another hit's details.
fn defang_report(text: &str, document: &Value) -> String {
    let mut indicators: Vec<String> = document["_indicators"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if let Some(modules) = document["modules"].as_object() {
        for (_name, m) in modules {
            if let Some(hits) = m["hits"].as_array() {
                for h in hits {
                    if let Some(i) = h["indicator"].as_str() {
                        indicators.push(i.to_string());
                    }
                }
            }
        }
    }
    indicators.sort_by_key(|i| std::cmp::Reverse(i.len()));
    indicators.dedup();
    let mut text = text.to_string();
    for indicator in &indicators {
        if !indicator.is_empty() && defang(indicator) != *indicator {
            text = replace_ci(&text, indicator, defang);
        }
    }
    text
}

/// The window the AdFection campaign was actually active, from the Citizen Lab
/// report: at least 45 targeted devices at Al Jazeera during 2024-2025.
pub const CAMPAIGN_FROM: CivilDate = CivilDate {
    year: 2024,
    month: 1,
    day: 1,
};
pub const CAMPAIGN_TO: CivilDate = CivilDate {
    year: 2025,
    month: 12,
    day: 31,
};
pub const CAMPAIGN_LABEL: &str = "2024-2025 (the documented campaign period)";

/// Compare the dates reported by this scan with the campaign window.
///
/// Unread or out-of-scope records may be older; an oldest date does not prove
/// that records cover every day since then or that missing evidence is gone.
pub fn overlap_statement(earliest: CivilDate, source: &str) -> Vec<String> {
    if earliest > CAMPAIGN_TO {
        return vec![
            format!(
                "** The oldest dated evidence reported by this scan is {} ({}).",
                source,
                earliest.iso()
            ),
            format!(
                "   The campaign this tool searches for was active in {}.",
                CAMPAIGN_LABEL
            ),
            "   Those dates DO NOT OVERLAP. The dates reported here do not reach".to_string(),
            "   the campaign period. Older or unread records may still exist;".to_string(),
            "   this scan cannot rule out past contact during that period. **".to_string(),
        ];
    }
    if earliest > CAMPAIGN_FROM {
        return vec![
            format!(
                "** The oldest dated evidence reported by this scan is {} ({}).",
                source,
                earliest.iso()
            ),
            format!(
                "   That reaches PART of the campaign period ({}),",
                CAMPAIGN_LABEL
            ),
            format!(
                "   from {} onwards, and only through that one kind of record.",
                earliest.iso()
            ),
            "   This does not establish continuous coverage from that date.".to_string(),
            "   Older or unread records may still exist. A clean result cannot".to_string(),
            "   rule out past contact during the campaign period. **".to_string(),
        ];
    }
    vec![
        format!(
            "** The oldest dated evidence reported by this scan is {} ({}), which predates",
            source,
            earliest.iso()
        ),
        "   the campaign period. This does not establish continuous coverage".to_string(),
        "   through that period. Surviving records are never everything, and a".to_string(),
        "   clean result cannot rule out past contact during that period. **".to_string(),
    ]
}

fn render_reach(out: &mut Vec<String>, document: &Value) {
    let mut entries: Vec<(&str, &str, &Value)> = Vec::new();
    if let Some(modules) = document["modules"].as_object() {
        for (mod_name, m) in modules {
            if let Some(reach) = m.get("reach").and_then(|r| r.as_object()) {
                for (label, info) in reach {
                    entries.push((mod_name.as_str(), label.as_str(), info));
                }
            }
        }
    }
    if entries.is_empty() {
        return;
    }

    out.push(RULE.to_string());
    out.push("HOW FAR BACK THIS SCAN COULD SEE".to_string());
    out.push(String::new());
    out.push("  These dates come from the records examined by this scan. They do not".to_string());
    out.push(
        "  establish a complete history; older or unread records may still exist:".to_string(),
    );
    out.push(String::new());

    let mut earliest_overall: Option<CivilDate> = None;
    let mut earliest_source = String::new();
    for (mod_name, label, info) in &entries {
        let earliest = info.get("earliest").and_then(|e| e.as_str()).unwrap_or("");
        let days = info.get("days").and_then(|d| d.as_i64());
        let when = if earliest.is_empty() {
            "unknown (no date established)".to_string()
        } else {
            earliest.chars().take(10).collect()
        };
        let mut age = String::new();
        if let (Some(d), true) = (days, !earliest.is_empty()) {
            age = format!("  ({} days ago)", d);
        }
        out.push(format!("{}/{}", mod_name, label));
        out.push(format!("      reaches back to : {}{}", when, age));
        out.push(format!(
            "      basis           : {}",
            info.get("basis").and_then(|b| b.as_str()).unwrap_or("")
        ));
        if let Some(note) = info.get("note").and_then(|n| n.as_str()) {
            if !note.is_empty() {
                out.push(format!("      {}", note));
            }
        }
        out.push(String::new());
        if !earliest.is_empty() {
            if let Some(d) = datetime::parse_iso_date_prefix(earliest) {
                if earliest_overall.map(|e| d < e).unwrap_or(true) {
                    earliest_overall = Some(d);
                    earliest_source = format!("{}/{}", mod_name, label);
                }
            }
        }
    }

    // How many artifacts actually date from inside the campaign window.
    let mut in_window = 0i64;
    let mut total_dated = 0i64;
    for (_m, _l, info) in &entries {
        if let Some(by_year) = info.get("by_year").and_then(|b| b.as_object()) {
            for (year, count) in by_year {
                let year: i64 = year.parse().unwrap_or(0);
                let count = count.as_i64().unwrap_or(0);
                total_dated += count;
                if (CAMPAIGN_FROM.year..=CAMPAIGN_TO.year).contains(&year) {
                    in_window += count;
                }
            }
        }
    }

    if let Some(earliest) = earliest_overall {
        for line in overlap_statement(earliest, &earliest_source) {
            out.push(format!("  {}", line));
        }
        out.push(String::new());
    }

    // Does ANY reach record - cookie ages, DNS, not just the cache files that
    // carry by_year - reach into the campaign window?
    let mut something_in_window = false;
    for (_m, _l, info) in &entries {
        if let Some(earliest) = info.get("earliest").and_then(|e| e.as_str()) {
            if let Some(d) = datetime::parse_iso_date_prefix(earliest) {
                if d <= CAMPAIGN_TO {
                    something_in_window = true;
                }
            }
        }
    }

    if total_dated > 0 {
        let mut merged: std::collections::BTreeMap<i64, i64> = Default::default();
        for (_m, _l, info) in &entries {
            if let Some(by_year) = info.get("by_year").and_then(|b| b.as_object()) {
                for (year, count) in by_year {
                    let year: i64 = year.parse().unwrap_or(0);
                    *merged.entry(year).or_insert(0) += count.as_i64().unwrap_or(0);
                }
            }
        }
        out.push(
            "  Age of the browser cache files searched, by year (cache files only,".to_string(),
        );
        out.push("  not cookies or DNS - those are summarised above):".to_string());
        let year_strs: Vec<String> = merged
            .iter()
            .map(|(y, c)| format!("{}: {}", y, crate::text::fmt_count_i(*c)))
            .collect();
        out.push(format!("      {}", year_strs.join("   ")));
        out.push(String::new());
        let pct = 100.0 * in_window as f64 / total_dated as f64;
        out.push(format!(
            "  Of those cache files, dating from the campaign period ({}-{}): {} of {} ({:.1}%).",
            CAMPAIGN_FROM.year,
            CAMPAIGN_TO.year,
            crate::text::fmt_count_i(in_window),
            crate::text::fmt_count_i(total_dated),
            pct
        ));

        // A per-year floor matters more than the total: the campaign ran
        // across several years, and a year with almost nothing left is a year
        // this scan cannot speak about.
        let sparse: Vec<i64> = (CAMPAIGN_FROM.year..=CAMPAIGN_TO.year)
            .filter(|y| merged.get(y).copied().unwrap_or(0) < 100)
            .collect();
        if in_window == 0 && !something_in_window {
            out.push(
                "  No dated evidence summarised here reaches the campaign period.".to_string(),
            );
            out.push(
                "  Older or unread records may still exist. A clean result cannot".to_string(),
            );
            out.push("  rule out past contact during that period.".to_string());
        } else if in_window == 0 && something_in_window {
            out.push(
                "  No browser CACHE file examined dates from the campaign period, though some"
                    .to_string(),
            );
            out.push(
                "  older evidence (shown above) does. Cache is the thinnest record;".to_string(),
            );
            out.push("  the window above is the one to read.".to_string());
        } else if !sparse.is_empty() {
            out.push(
                "  BUT cache coverage is uneven. These campaign years have almost no".to_string(),
            );
            out.push("  surviving cache, so a clean result says little about them:".to_string());
            for y in &sparse {
                out.push(format!(
                    "      {}: {} cache file(s)",
                    y,
                    crate::text::fmt_count_i(merged.get(y).copied().unwrap_or(0))
                ));
            }
        }
        out.push(String::new());
    }

    // The actionable part, rendered as its own ruled-off section.
    let mut howto: Vec<String> = Vec::new();
    for (_m, _l, info) in &entries {
        if let Some(Value::Array(lines)) = info.get("how_to_enable") {
            for line in lines {
                if let Some(s) = line.as_str() {
                    howto.push(s.to_string());
                }
            }
        }
    }
    if !howto.is_empty() {
        out.push(String::new());
        out.push(RULE.to_string());
        for line in howto {
            out.push(line);
        }
        out.push(RULE.to_string());
    }
    out.push(String::new());
}

/// The full human report.
pub fn render_human(document: &Value) -> String {
    let document = human_document(document);
    let mut out: Vec<String> = Vec::new();

    out.push(RULE.to_string());
    out.push(format!(
        "  Zero Breach {}  —  AdFection / Candiru indicator check",
        document["tool"]["version"].as_str().unwrap_or("?")
    ));
    // The name must not be read as a promise. The tagline carries the tool's
    // one non-negotiable caveat right next to it, so a screenshot of the top
    // of the report cannot imply "you are safe".
    out.push("  Checks for TRACES of ad-delivered spyware. A clean result is NOT a".to_string());
    out.push("  clean bill of health - see what could not be checked, below.".to_string());
    out.push(format!(
        "  {}   {} {}",
        document["timestamp"].as_str().unwrap_or(""),
        document["platform"]["system"].as_str().unwrap_or(""),
        document["platform"]["release"].as_str().unwrap_or("")
    ));
    out.push(RULE.to_string());
    out.push(String::new());

    // The answer first. Everything after it is the supporting evidence.
    out.extend(render_summary(&document).lines().map(String::from));

    let ioc = &document["ioc_set"];
    let age = ioc["age_days"].as_i64();
    let age_txt = match age {
        None => "unknown age".to_string(),
        Some(a) => format!("{} day(s) old", a),
    };
    out.push(format!(
        "Indicator set : {} indicators, {}",
        ioc["count"], age_txt
    ));
    if ioc["stale"].as_bool().unwrap_or(false) {
        out.push(
            "  ** WARNING: this indicator set is more than 30 days old. Update it \
             before trusting a clean result. **"
                .to_string(),
        );
    }
    out.push(String::new());

    // Put the full indicator evidence after the coverage/DNS-history
    // instructions. The concise result and urgent next steps remain visible in
    // the summary.
    render_reach(&mut out, &document);

    out.push("DETAIL  —  what was examined, and the evidence behind the summary".to_string());
    out.push(String::new());
    if let Some(modules) = document["modules"].as_object() {
        for (name, m) in modules {
            let took = match m["duration_s"].as_f64() {
                Some(d) if d != 0.0 => format!(" in {:.0}s", d),
                _ => String::new(),
            };
            out.push(format!(
                "--- {} check  [{}]{} ---",
                name,
                m["status"].as_str().unwrap_or(""),
                took
            ));
            out.push(format!(
                "    examined: {}    could not read: {}",
                crate::text::fmt_count_i(m["checked"].as_i64().unwrap_or(0)),
                crate::text::fmt_count_i(m["skipped"].as_i64().unwrap_or(0))
            ));
            if let Some(submetrics) = m["submetrics"].as_object() {
                for line in describe_metrics(submetrics) {
                    out.push(format!("    {}", line));
                }
            }
            if let Some(notes) = m["notes"].as_array() {
                for note in notes {
                    out.push(format!("    note   : {}", note.as_str().unwrap_or("")));
                }
            }
            if let Some(hits) = m["hits"].as_array() {
                if !hits.is_empty() {
                    // Strongest evidence first: someone reading this should see
                    // a sample on disk or a proven contact before a string that
                    // merely appeared in cached page text.
                    let mut sorted_hits: Vec<&Value> = hits.iter().collect();
                    sorted_hits.sort_by(|a, b| {
                        let ka = evidence_sort_key(a["evidence"].as_str().unwrap_or(""));
                        let kb = evidence_sort_key(b["evidence"].as_str().unwrap_or(""));
                        ka.partial_cmp(&kb).unwrap_or(std::cmp::Ordering::Equal)
                    });
                    for h in sorted_hits {
                        let tier = h["tier"].as_str().unwrap_or("");
                        let prov = if tier.is_empty() {
                            "?".to_string()
                        } else {
                            format!("{}/{}", tier, h["confidence"].as_str().unwrap_or(""))
                        };
                        let ev = match h["evidence"].as_str() {
                            Some(e) if !e.is_empty() => e.to_string(),
                            _ => "unclassified".to_string(),
                        };
                        out.push(format!(
                            "    !! HIT  {}  [{}]  evidence: {}",
                            defang(h["indicator"].as_str().unwrap_or("")),
                            prov,
                            ev.to_uppercase()
                        ));
                        let gloss = evidence_gloss(tier, h["evidence"].as_str().unwrap_or(""));
                        if !gloss.is_empty() {
                            out.push(format!("            meaning: {}", gloss));
                        }
                        let profile = h["profile"].as_str().unwrap_or("");
                        if !profile.is_empty() {
                            out.push(format!("            account: {}", profile));
                        }
                        out.push(format!(
                            "            at     : {}",
                            defang_text(
                                h["location"].as_str().unwrap_or(""),
                                h["indicator"].as_str().unwrap_or("")
                            )
                        ));
                        out.push(format!(
                            "            detail : {}",
                            defang_text(
                                h["detail"].as_str().unwrap_or(""),
                                h["indicator"].as_str().unwrap_or("")
                            )
                        ));
                        let observed = h["observed"].as_str().unwrap_or("");
                        if !observed.is_empty() {
                            out.push(format!(
                                "            when   : {}",
                                defang_text(observed, h["indicator"].as_str().unwrap_or(""))
                            ));
                        }
                        let source = h["source"].as_str().unwrap_or("");
                        if !source.is_empty() {
                            out.push(format!("            source : {}", source));
                        }
                    }
                }
            }
            out.push(String::new());
        }
    }

    let v = &document["verdict"];
    out.push(RULE.to_string());
    if v["status"].as_str() == Some(V_HITS) {
        out.push(format!(
            "VERDICT: {} indicator(s) matched.",
            v["hits_total"].as_i64().unwrap_or(0)
        ));
        out.push(String::new());
        let mut counts: std::collections::BTreeMap<String, i64> = Default::default();
        if let Some(modules) = document["modules"].as_object() {
            for (_name, m) in modules {
                if let Some(hits) = m["hits"].as_array() {
                    for h in hits {
                        let key = match h["evidence"].as_str() {
                            Some(e) if !e.is_empty() => e.to_string(),
                            _ => "unclassified".to_string(),
                        };
                        *counts.entry(key).or_insert(0) += 1;
                    }
                }
            }
        }
        let counts_str: Vec<String> = counts.iter().map(|(k, n)| format!("{} {}", n, k)).collect();
        out.push(format!("  By evidence strength: {}", counts_str.join(", ")));
        out.push(String::new());
        out.push(
            "  Follow the next steps in the summary. The indicator's role and the".to_string(),
        );
        out.push(
            "  evidence type determine those steps; the number of matches does not.".to_string(),
        );
        out.push("  A match means INVESTIGATE, not 'you are compromised'.".to_string());
        out.push(
            "  A match does not by itself establish that spyware ran on this device.".to_string(),
        );
    } else {
        let gaps: Vec<String> = v["gaps"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|g| g.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if !gaps.is_empty() {
            out.push("VERDICT: no known indicators found IN WHAT COULD BE CHECKED.".to_string());
            out.push(String::new());
            out.push("Checks that could NOT run (a gap is not a clean result):".to_string());
            for g in &gaps {
                out.push(format!("  - {}", g));
            }
            out.push(String::new());
        } else {
            out.push("VERDICT: no known indicators found in any check that ran.".to_string());
            out.push(String::new());
        }
        // D1: the mandatory closing line, verbatim.
        out.push(
            document["doctrine_line"]
                .as_str()
                .unwrap_or(D1_LINE)
                .to_string(),
        );
        out.push(String::new());
    }
    out.push(String::new());
    support_options(&mut out);
    out.push(RULE.to_string());
    defang_report(&out.join("\n"), &document)
}
