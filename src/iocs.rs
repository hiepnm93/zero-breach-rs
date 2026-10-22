//! IOC loading, type inference, freshness and the shared matcher.
//! Ported from zero-breach scan/adint_scan/iocs.py (Apache-2.0).
//!
//! Data contract (matching iocs/adfection_iocs.txt):
//!
//! ```text
//! indicator <TAB> tier <TAB> confidence [<TAB> source]
//! ```
//!
//! `tier` = cc | validator | delivery | historical | sample | vuln-driver |
//! candiru | candiru-ip; `confidence` = primary | secondary. `#` lines are
//! comments. Indicator *type* is inferred from shape, not stored, so the file
//! stays three (or four) columns: 64 hex chars → sha256, IPv4/IPv6 → ip,
//! otherwise domain.
//!
//! All matching is plain text comparison. Nothing here ever resolves or
//! contacts anything.

use std::collections::HashMap;
use std::path::Path;

use crate::datetime;

pub const VALID_TIERS: [&str; 8] = [
    "cc",         // Candiru command-and-control (Citizen Lab, named in body)
    "validator",  // Candiru validator / target-selection servers
    "delivery",   // Discover-Tech / Controlium ad infrastructure
    "historical", // older, separate Candiru campaigns
    "sample",     // file hashes of the spyware itself
    // A legitimate, signed third-party driver or utility that this actor
    // abuses (bring-your-own-vulnerable-driver). Never proof of infection.
    "vuln-driver",
    // Candiru-attributed server infrastructure whose individual ROLE is not
    // stated by the source (Recorded Future, Aug 2025).
    "candiru",
    // Same, but IP addresses — an IP indicator decays in a way a domain does
    // not, so a hit is only meaningful if it is DATED.
    "candiru-ip",
];
pub const VALID_CONFIDENCE: [&str; 2] = ["primary", "secondary"];

pub const TYPE_DOMAIN: &str = "domain";
pub const TYPE_IP: &str = "ip";
pub const TYPE_SHA256: &str = "sha256";

const MAX_INDICATORS: usize = 20_000;

/// An error while loading an indicator file. The message text follows the
/// Python `IocError` strings so reports stay comparable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IocError(pub String);

impl std::fmt::Display for IocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for IocError {}

/// One indicator. `value` is normalised: lower-case for domains/ips/hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Indicator {
    pub value: String,
    pub tier: String,
    pub confidence: String,
    pub kind: String,
    /// Which published report this came from (optional 4th column): a hit
    /// without a citation is unusable, so the citation travels per indicator.
    pub source: String,
}

impl Indicator {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "indicator": self.value,
            "tier": self.tier,
            "confidence": self.confidence,
            "type": self.kind,
            "source": self.source,
        })
    }
}

/// Which encoding an occurrence in a binary haystack was found in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// Single-byte text (or a str haystack).
    Narrow,
    /// UTF-16LE code units — how Chromium and much of Windows store strings.
    Wide,
    /// A plain `str` haystack (the text matcher).
    Str,
}

/// Is `c` (as a byte of the haystack) in the ASCII boundary set named?
fn in_set(c: u8, set: &str) -> bool {
    // `set` holds ASCII characters only; a non-ASCII haystack byte is never a
    // member, which is exactly how the Python per-character sets behave for a
    // non-ASCII character.
    set.as_bytes().contains(&c)
}

const LABEL_SET: &str = "abcdefghijklmnopqrstuvwxyz0123456789-";
const LABEL_OR_UNDER: &str = "abcdefghijklmnopqrstuvwxyz0123456789-_";
const DIGITS: &str = "0123456789";
const DIGIT_DOT: &str = "0123456789.";
const HEX: &str = "0123456789abcdef";
const HEX_COLON: &str = "0123456789abcdef:";

/// (left_bad, right_bad, continues) for one indicator. `continues` is what may
/// not follow a trailing dot — a trailing dot is allowed only when what follows
/// it does not continue the name.
fn bad_sets(kind: &str, needle: &str) -> (&'static str, &'static str, &'static str) {
    if kind == TYPE_IP {
        if needle.contains(':') {
            return (":0123456789abcdef.", HEX_COLON, HEX);
        }
        return (DIGIT_DOT, DIGITS, DIGITS);
    }
    (LABEL_OR_UNDER, LABEL_OR_UNDER, LABEL_SET)
}

/// One UTF-16LE code unit starting at byte `pos`, as its ASCII byte, or the
/// placeholder 0xFF that is in none of the boundary sets.
#[inline]
fn char_at16(hay: &[u8], pos: usize) -> Option<u8> {
    // Python returns None when pos < 0 or pos + 1 >= len(hay); the caller
    // never passes a negative position here.
    if pos + 1 >= hay.len() {
        return None;
    }
    let (lo, hi) = (hay[pos], hay[pos + 1]);
    Some(if hi == 0 && lo < 0x80 { lo } else { 0xFF })
}

/// One byte of a narrow haystack, or None out of range.
#[inline]
fn char_at(hay: &[u8], pos: usize) -> Option<u8> {
    hay.get(pos).copied()
}

/// Every offset at which `needle` occurs in `hay` as a whole indicator rather
/// than as part of a longer name or number.
///
/// Domains: the character before must not continue a label (so
/// notcontrolium.net does not match controlium.net) and the character after
/// must not either (so controlium.network does not match). IPs: neither side
/// may continue the number, so 152.174.65.771 does not match 52.174.65.77, and
/// an IPv6 address may not sit inside a longer one.
///
/// Offsets are BYTE offsets; boundary decisions read single bytes, which is
/// equivalent to the Python per-character sets because every member of those
/// sets is ASCII.
fn positions(hay: &[u8], needle: &[u8], kind: &str, wide: bool) -> Vec<usize> {
    let (left_bad, right_bad, cont) = bad_sets(kind, std::str::from_utf8(needle).unwrap_or(""));
    let unit = if wide { 2 } else { 1 };
    let at = |pos: isize| -> Option<u8> {
        if pos < 0 {
            None
        } else if wide {
            char_at16(hay, pos as usize)
        } else {
            char_at(hay, pos as usize)
        }
    };
    let mut out = Vec::new();
    let mut start = 0usize;
    while let Some(rel) = find_from(hay, needle, start) {
        let idx = rel;
        let before = at(idx as isize - unit as isize);
        let after_pos = idx + needle.len();
        let after = at(after_pos as isize);
        let mut ok = before.is_none_or(|b| !in_set(b, left_bad));
        if ok {
            if let Some(a) = after {
                if in_set(a, right_bad) {
                    ok = false;
                } else if a == b'.' {
                    let nxt = at((after_pos + unit) as isize);
                    ok = nxt.is_none_or(|n| !in_set(n, cont));
                }
            }
        }
        if ok {
            out.push(idx);
        }
        start = idx + 1;
    }
    out
}

fn find_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn prune_parents(found: Vec<(Indicator, Vec<(Encoding, usize)>)>, hay: &[u8]) -> Vec<Indicator> {
    // Drop a parent domain whose every occurrence is just the tail of a
    // matched child. "noas.powerium.net" in a cookie also contains
    // "powerium.net", and both are indicators — but it is ONE contact, and
    // reporting it as two servers that reached the device doubles the alarm
    // for no reason. A parent that also occurs on its own somewhere in the
    // same artifact is kept.
    let values: Vec<String> = found.iter().map(|(i, _)| i.value.clone()).collect();
    let mut keep = Vec::new();
    for (ind, occ) in found {
        let children: Vec<&String> = values
            .iter()
            .filter(|v| **v != ind.value && v.ends_with(&format!(".{}", ind.value)))
            .collect();
        if ind.kind != TYPE_DOMAIN || children.is_empty() {
            keep.push(ind);
            continue;
        }
        let mut standalone = false;
        for (enc, pos) in occ {
            let mut tail_of_child = false;
            for child in &children {
                let extra = child.len() - ind.value.len();
                match enc {
                    Encoding::Wide => {
                        if pos >= 2 * extra && pos + 2 * ind.value.len() <= hay.len() {
                            let start = pos - 2 * extra;
                            let seg = &hay[start..pos + 2 * ind.value.len()];
                            tail_of_child = seg == child.encode_utf16_le().as_slice();
                        }
                    }
                    Encoding::Narrow | Encoding::Str => {
                        if pos >= extra && pos + ind.value.len() <= hay.len() {
                            let start = pos - extra;
                            let seg = &hay[start..pos + ind.value.len()];
                            tail_of_child = seg == child.as_bytes();
                        }
                    }
                }
                if tail_of_child {
                    break;
                }
            }
            if !tail_of_child {
                standalone = true;
                break;
            }
        }
        if standalone {
            keep.push(ind);
        }
    }
    keep
}

/// Helper mirroring Python's `str.encode("utf-16-le")`.
trait Utf16Le {
    fn encode_utf16_le(&self) -> Vec<u8>;
}

impl Utf16Le for str {
    fn encode_utf16_le(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len() * 2);
        for unit in self.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }
}

/// Infer the indicator type from shape, not from a stored column.
pub fn infer_type(indicator: &str) -> &'static str {
    let s = indicator.trim().to_lowercase();
    if s.len() == 64 && s.bytes().all(|b| in_set(b, HEX)) {
        return TYPE_SHA256;
    }
    if is_ipv4(&s) || (s.contains(':') && s.bytes().all(|b| in_set(b, HEX_COLON))) {
        return TYPE_IP;
    }
    TYPE_DOMAIN
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The indicator set: what every module matches against.
#[derive(Clone, Debug)]
pub struct IocSet {
    pub indicators: Vec<Indicator>,
    pub source_path: String,
    pub asof: Option<String>,
    mtime: Option<i64>,
    /// (ascii needle, utf-16le needle) per value, for binary searching.
    needles: HashMap<String, (Vec<u8>, Vec<u8>)>,
}

impl IocSet {
    /// Build a set from already-parsed indicators (used by tests and the
    /// updater); the loaders go through [`load`].
    pub fn new(indicators: Vec<Indicator>, source_path: &str, mtime: Option<i64>) -> Self {
        let mut needles = HashMap::new();
        for ind in &indicators {
            needles
                .entry(ind.value.clone())
                .or_insert_with(|| (ind.value.as_bytes().to_vec(), ind.value.encode_utf16_le()));
        }
        IocSet {
            indicators,
            source_path: source_path.to_string(),
            asof: None,
            mtime,
            needles,
        }
    }

    pub fn len(&self) -> usize {
        self.indicators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.indicators.is_empty()
    }

    pub fn domains(&self) -> Vec<&Indicator> {
        self.indicators
            .iter()
            .filter(|i| i.kind == TYPE_DOMAIN)
            .collect()
    }

    pub fn ips(&self) -> Vec<&Indicator> {
        self.indicators
            .iter()
            .filter(|i| i.kind == TYPE_IP)
            .collect()
    }

    pub fn hashes(&self) -> Vec<&Indicator> {
        self.indicators
            .iter()
            .filter(|i| i.kind == TYPE_SHA256)
            .collect()
    }

    /// Lower-case domain + IP strings, for substring matching in artifacts.
    /// Sorted for deterministic output. Never used to RESOLVE anything.
    pub fn network_strings(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .indicators
            .iter()
            .filter(|i| i.kind == TYPE_DOMAIN || i.kind == TYPE_IP)
            .map(|i| i.value.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    pub fn lookup(&self, value: &str) -> Option<&Indicator> {
        let key = value.trim().to_lowercase();
        self.indicators.iter().find(|i| i.value == key)
    }

    fn net_indicators(&self) -> impl Iterator<Item = &Indicator> {
        self.indicators
            .iter()
            .filter(|i| i.kind == TYPE_DOMAIN || i.kind == TYPE_IP)
    }

    /// Indicators genuinely present in the text, with type-aware boundaries.
    /// The haystack must ALREADY be lower-cased.
    pub fn search(&self, haystack_lower: &str) -> Vec<Indicator> {
        let hay = haystack_lower.as_bytes();
        let mut found = Vec::new();
        for ind in self.net_indicators() {
            let needle = ind.value.as_bytes();
            let pos = positions(hay, needle, &ind.kind, false);
            if !pos.is_empty() {
                found.push((
                    ind.clone(),
                    pos.into_iter().map(|p| (Encoding::Str, p)).collect(),
                ));
            }
        }
        prune_parents(found, hay)
    }

    /// As [`search`](IocSet::search), for raw binary artifacts (HTTP cache,
    /// LevelDB). Searches both single-byte text and UTF-16LE, because
    /// Chromium's storage and many Windows artifacts keep strings as UTF-16 —
    /// "c\0o\0n\0..." — which a plain byte search walks straight past.
    /// Lower-casing the ASCII letters in both encodings is what the caller's
    /// lower-casing of the buffer did upstream.
    pub fn search_bytes(&self, haystack_lower: &[u8]) -> Vec<Indicator> {
        let mut found = Vec::new();
        for ind in self.net_indicators() {
            let (narrow, wide) =
                self.needles.get(&ind.value).cloned().unwrap_or_else(|| {
                    (ind.value.as_bytes().to_vec(), ind.value.encode_utf16_le())
                });
            let mut occ = Vec::new();
            if find_from(haystack_lower, &narrow, 0).is_some() {
                occ.extend(
                    positions(haystack_lower, &narrow, &ind.kind, false)
                        .into_iter()
                        .map(|p| (Encoding::Narrow, p)),
                );
            }
            if find_from(haystack_lower, &wide, 0).is_some() {
                occ.extend(
                    positions(haystack_lower, &wide, &ind.kind, true)
                        .into_iter()
                        .map(|p| (Encoding::Wide, p)),
                );
            }
            if !occ.is_empty() {
                found.push((ind.clone(), occ));
            }
        }
        prune_parents(found, haystack_lower)
    }

    /// For ONE record (a cookie, an HSTS entry, a URL) that matched several
    /// indicators: keep only the most specific. A cookie for noas.powerium.net
    /// matches both noas.powerium.net and powerium.net, but it is one contact.
    pub fn most_specific(&self, matched: Vec<Indicator>) -> Vec<Indicator> {
        let values: Vec<String> = matched.iter().map(|i| i.value.clone()).collect();
        matched
            .into_iter()
            .filter(|i| {
                !(i.kind == TYPE_DOMAIN
                    && values
                        .iter()
                        .any(|v| *v != i.value && v.ends_with(&format!(".{}", i.value))))
            })
            .collect()
    }

    /// Lower-case a byte buffer the way `bytes.lower()` did: ASCII letters
    /// only, which is exactly what matters for ASCII needles in either
    /// encoding.
    pub fn lower_bytes(data: &[u8]) -> Vec<u8> {
        data.to_ascii_lowercase()
    }

    // --- freshness ---------------------------------------------------------

    /// When this set was last curated, in unix days, or None if unknowable.
    ///
    /// The '# as-of:' date is preferred over the file's modification time
    /// because mtime is a property of the COPY, not of the data: a fresh
    /// clone, an unzip or a plain file copy resets it to now. The header date
    /// is content, so it survives being copied.
    fn curated_at_days(&self) -> Option<i64> {
        if let Some(asof) = &self.asof {
            if let Some(d) = datetime::parse_date(asof) {
                return Some(d.to_days());
            }
            // A malformed header must degrade to the mtime, never raise in
            // the middle of a scan.
        }
        self.mtime.map(|m| m.div_euclid(86_400))
    }

    pub fn age_days(&self) -> Option<i64> {
        let curated = self.curated_at_days()?;
        Some((datetime::now_days() - curated).max(0))
    }

    pub fn is_stale(&self) -> bool {
        self.age_days().map(|a| a > 30).unwrap_or(false)
    }
}

/// Why an indicator value is unsafe to scan for, or None.
///
/// Real indicators are hostnames, IP addresses and hex digests. A hostile or
/// corrupted feed could pass a lone "." (which matches between every pair of
/// bytes), a lone ":" (parses as an IP that matches every URL) or "0.0.0.0"
/// (would match every BLOCKED lookup). Anything else is refused, loudly,
/// rather than scanned for.
fn value_problem(value: &str, kind: &str) -> Option<String> {
    if kind == TYPE_IP {
        return match value.parse::<std::net::IpAddr>() {
            Err(_) => Some("not a valid IP address".to_string()),
            Ok(addr) => {
                if addr.is_unspecified() || value.len() < 7 {
                    Some("would match far more than the intended host".to_string())
                } else {
                    None
                }
            }
        };
    }
    if kind == TYPE_DOMAIN {
        if !(4..=253).contains(&value.len()) {
            return Some("not the length of a hostname".to_string());
        }
        let labels: Vec<&str> = value.split('.').collect();
        if labels.len() < 2 {
            return Some("a hostname needs at least one dot".to_string());
        }
        for label in labels {
            let ok = (1..=63).contains(&label.len()) && is_hostname_label(label);
            if !ok {
                let short: String = label.chars().take(70).collect();
                return Some(format!("label '{}' is not a valid hostname label", short));
            }
        }
        return None;
    }
    None // hashes are already pinned to 64 hex digits by infer_type
}

/// `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`
fn is_hostname_label(label: &str) -> bool {
    let b = label.as_bytes();
    if b.is_empty() {
        return false;
    }
    if !b[0].is_ascii_lowercase() && !b[0].is_ascii_digit() {
        return false;
    }
    if b.len() == 1 {
        return true;
    }
    if !b[b.len() - 1].is_ascii_lowercase() && !b[b.len() - 1].is_ascii_digit() {
        return false;
    }
    b[1..b.len() - 1]
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Load and validate an indicator file. Every failure is an [`IocError`] with
/// the same text the Python loader produced, so an operator sees the same
/// diagnosis.
pub fn load(path: &Path) -> Result<IocSet, IocError> {
    if !path.exists() {
        return Err(IocError(format!("IOC file not found: {}", path.display())));
    }
    let raw = std::fs::read(path).map_err(|e| IocError(format!("IOC file not readable: {}", e)))?;
    // utf-8-sig, not utf-8: Windows editors save a byte-order mark, and
    // U+FEFF is not whitespace to a strip(). With plain utf-8 the first
    // indicator in a user's own list silently became "﻿controlium.net",
    // matched nothing, and the scan then reported finding nothing without
    // ever having looked.
    let raw = raw.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(&raw);
    let text = String::from_utf8(raw.to_vec())
        .map_err(|_| IocError(format!("IOC file is not valid UTF-8: {}", path.display())))?;
    let mtime = std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64);
    parse(&text, &path.to_string_lossy(), mtime)
}

/// Parse indicator text (already BOM-stripped and UTF-8) into a set.
pub fn parse(text: &str, source_path: &str, mtime: Option<i64>) -> Result<IocSet, IocError> {
    let mut seen: HashMap<String, Indicator> = HashMap::new();
    let mut asof: Option<String> = None;

    for (idx, raw_line) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            // The '# as-of: YYYY-MM-DD' header is the set's curated date.
            if let Some(date) = parse_asof(line) {
                asof = Some(date);
            }
            continue;
        }
        let parts: Vec<&str> = line
            .split('\t')
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .collect();
        if parts.len() < 3 {
            return Err(IocError(format!(
                "line {}: expected 3 or 4 tab-separated columns, got '{}'",
                lineno, line
            )));
        }
        let value = parts[0].to_lowercase();
        let tier = parts[1];
        let confidence = parts[2];
        // 4th column is an optional source tag; files written before it
        // existed stay valid.
        let source = if parts.len() > 3 { parts[3] } else { "" };
        if !VALID_TIERS.contains(&tier) {
            return Err(IocError(format!(
                "line {}: unknown tier '{}'",
                lineno, tier
            )));
        }
        if !VALID_CONFIDENCE.contains(&confidence) {
            return Err(IocError(format!(
                "line {}: unknown confidence '{}'",
                lineno, confidence
            )));
        }
        if value.starts_with('\u{FEFF}')
            || value.contains('\u{200B}')
            || value.contains('\u{200C}')
            || value.contains('\u{200D}')
            || value.contains('\u{2060}')
        {
            return Err(IocError(format!(
                "line {}: invisible character in '{}' - the file was probably \
                 re-saved by an editor",
                lineno, value
            )));
        }
        let kind = infer_type(&value);
        let mut value = value;
        if kind == TYPE_DOMAIN {
            value = value.trim_end_matches('.').to_string();
            if !value.is_ascii() {
                // Store internationalised names in the punycode form that
                // browsers and DNS actually record, so matching is exact.
                value = idna_to_ascii(&value).ok_or_else(|| {
                    IocError(format!(
                        "line {}: '{}' is not a valid domain name",
                        lineno, value
                    ))
                })?;
            }
        }
        if let Some(problem) = value_problem(&value, kind) {
            let short: String = value.chars().take(80).collect();
            return Err(IocError(format!(
                "line {}: '{}': {}",
                lineno, short, problem
            )));
        }
        seen.insert(
            value.clone(),
            Indicator {
                value,
                tier: tier.to_string(),
                confidence: confidence.to_string(),
                kind: kind.to_string(),
                source: source.to_string(),
            },
        );
        if seen.len() > MAX_INDICATORS {
            return Err(IocError(format!(
                "more than {} indicators - refusing what looks like a \
                 corrupted or hostile feed",
                MAX_INDICATORS
            )));
        }
    }
    if seen.is_empty() {
        // An empty list must never produce a report. A truncated download or
        // an emptied file would otherwise run a full scan, search for
        // nothing, and print a result that reads as reassurance.
        return Err(IocError(format!(
            "indicator file contains no indicators: {}",
            source_path
        )));
    }
    let mut indicators: Vec<Indicator> = seen.into_values().collect();
    indicators.sort_by(|a, b| a.value.cmp(&b.value));
    let mut set = IocSet::new(indicators, source_path, mtime);
    set.asof = asof;
    Ok(set)
}

/// `^#\s*as-of:\s*(\d{4}-\d{2}-\d{2})\s*$`
fn parse_asof(line: &str) -> Option<String> {
    let rest = line.strip_prefix('#')?.trim_start();
    let rest = rest.strip_prefix("as-of:")?;
    let rest = rest.trim();
    if datetime::parse_date(rest).is_some() {
        Some(rest.to_string())
    } else {
        None
    }
}

/// Store internationalised names in the punycode form browsers and DNS
/// actually record. A small RFC 3492 punycode encoder stands in for Python's
/// `str.encode("idna")` — which keeps the tool dependency-free.
pub fn idna_to_ascii(domain: &str) -> Option<String> {
    let mut out: Vec<String> = Vec::new();
    for label in domain.split('.') {
        if label.is_empty() {
            return None;
        }
        if label.is_ascii() {
            out.push(label.to_string());
        } else {
            let lowered: String = label.to_lowercase();
            out.push(format!("xn--{}", punycode_encode(&lowercased(&lowered))?));
        }
    }
    Some(out.join("."))
}

fn lowercased(s: &str) -> String {
    // punycode operates on code points; to_lowercase is the nameprep stand-in.
    s.to_lowercase()
}

fn punycode_encode(input: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    const INITIAL_BIAS: u32 = 72;
    const INITIAL_N: u32 = 128;

    let chars: Vec<char> = input.chars().collect();
    let mut output = String::new();
    let basic: u32 = chars.iter().filter(|c| c.is_ascii()).count() as u32;
    for c in chars.iter().filter(|c| c.is_ascii()) {
        output.push(*c);
    }
    let b = basic;
    if b > 0 {
        output.push('-');
    }
    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut h = b;
    let total = chars.len() as u32;
    while h < total {
        let m = chars.iter().map(|c| *c as u32).filter(|c| *c >= n).min()?;
        delta = delta.checked_add((m - n).checked_mul(h + 1)?)?;
        n = m;
        for c in &chars {
            let cp = *c as u32;
            if cp < n {
                delta = delta.checked_add(1)?;
            }
            if cp == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    let digit = t + (q - t) % (BASE - t);
                    output.push(digit_to_char(digit));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(digit_to_char(q));
                bias = adapt(delta, h + 1, h == b);
                delta = 0;
                h += 1;
            }
        }
        delta += 1;
        n += 1;
    }
    Some(output)
}

fn adapt(mut delta: u32, numpoints: u32, firsttime: bool) -> u32 {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    delta = if firsttime { delta / DAMP } else { delta / 2 };
    delta += delta / numpoints;
    let mut k = 0;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }
    k + (((BASE - TMIN + 1) * delta) / (delta + SKEW))
}

fn digit_to_char(d: u32) -> char {
    if d < 26 {
        (b'a' + d as u8) as char
    } else {
        (b'0' + (d - 26) as u8) as char
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ind(value: &str, kind: &str) -> Indicator {
        Indicator {
            value: value.to_string(),
            tier: "cc".to_string(),
            confidence: "primary".to_string(),
            kind: kind.to_string(),
            source: String::new(),
        }
    }

    #[test]
    fn type_inference() {
        assert_eq!(infer_type("AABB".repeat(16).as_str()), TYPE_SHA256);
        assert_eq!(infer_type("52.174.65.77"), TYPE_IP);
        assert_eq!(infer_type("2a02:db8::1"), TYPE_IP);
        assert_eq!(infer_type("controlium.net"), TYPE_DOMAIN);
    }

    #[test]
    fn ip_boundaries() {
        let s = IocSet::new(vec![ind("52.174.65.77", TYPE_IP)], "t", None);
        assert_eq!(s.search("connected to 52.174.65.77 today").len(), 1);
        assert_eq!(s.search("52.174.65.77").len(), 1);
        assert_eq!(s.search("x 152.174.65.771 y").len(), 0);
        assert_eq!(s.search("52.174.65.771").len(), 0);
        assert_eq!(s.search("152.174.65.77").len(), 0);
        assert_eq!(s.search("52.174.65.77.9").len(), 0);
        assert_eq!(s.search("52.174.65.77:443").len(), 1);
        assert_eq!(s.search("152.174.65.771 and also 52.174.65.77").len(), 1);
    }

    #[test]
    fn domain_boundaries() {
        let s = IocSet::new(vec![ind("controlium.net", TYPE_DOMAIN)], "t", None);
        assert_eq!(s.search("https://controlium.net/x").len(), 1);
        assert_eq!(s.search("noas.controlium.net").len(), 1);
        assert_eq!(s.search("notcontrolium.net").len(), 0);
        assert_eq!(s.search("controlium.network").len(), 0);
        assert_eq!(s.search("safe-controlium.net").len(), 0);
        assert_eq!(s.search("controlium.net.evil.example").len(), 0);
    }

    #[test]
    fn bytes_and_text_agree() {
        let s = IocSet::new(
            vec![
                ind("52.174.65.77", TYPE_IP),
                ind("controlium.net", TYPE_DOMAIN),
            ],
            "t",
            None,
        );
        for text in [
            "152.174.65.771 notcontrolium.net",
            "52.174.65.77 noas.controlium.net",
            "controlium.network",
        ] {
            let a: Vec<String> = s.search(text).into_iter().map(|i| i.value).collect();
            let b: Vec<String> = s
                .search_bytes(text.as_bytes())
                .into_iter()
                .map(|i| i.value)
                .collect();
            assert_eq!(a, b, "text and binary matching disagree on {:?}", text);
        }
    }

    #[test]
    fn utf16le_matches_and_respects_boundaries() {
        let s = IocSet::new(vec![ind("controlium.net", TYPE_DOMAIN)], "t", None);
        let buf: Vec<u8> = "visited controlium.net today"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .map(|b| b.to_ascii_lowercase())
            .collect();
        assert_eq!(s.search_bytes(&buf).len(), 1);
        let bad: Vec<u8> = "notcontrolium.network"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(s.search_bytes(&bad).len(), 0);
    }

    #[test]
    fn ipv6_exact_and_boundary() {
        let s = IocSet::new(vec![ind("2a02:db8::1", TYPE_IP)], "t", None);
        assert_eq!(s.search("peer 2a02:db8::1 seen").len(), 1);
        assert_eq!(s.search("2a02:db8::1a").len(), 0);
    }

    #[test]
    fn parent_and_child_collapse_to_one_contact() {
        let s = IocSet::new(
            vec![
                ind("powerium.net", TYPE_DOMAIN),
                ind("noas.powerium.net", TYPE_DOMAIN),
            ],
            "t",
            None,
        );
        let got: Vec<String> = s
            .search("cookie for .noas.powerium.net")
            .into_iter()
            .map(|i| i.value)
            .collect();
        assert_eq!(got, vec!["noas.powerium.net".to_string()]);
    }

    #[test]
    fn most_specific_keeps_the_child() {
        let s = IocSet::new(
            vec![
                ind("powerium.net", TYPE_DOMAIN),
                ind("noas.powerium.net", TYPE_DOMAIN),
            ],
            "t",
            None,
        );
        let got = s.most_specific(s.search("noas.powerium.net"));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].value, "noas.powerium.net");
    }

    #[test]
    fn punycode_matches_python_idna() {
        assert_eq!(
            idna_to_ascii("müller.example").as_deref(),
            Some("xn--mller-kva.example")
        );
    }

    #[test]
    fn value_validation() {
        assert_eq!(
            value_problem(".", TYPE_DOMAIN).unwrap(),
            "not the length of a hostname"
        );
        assert_eq!(
            value_problem("example", TYPE_DOMAIN).unwrap(),
            "a hostname needs at least one dot"
        );
        assert_eq!(value_problem("a.example", TYPE_DOMAIN), None);
        assert!(value_problem("-bad.example", TYPE_DOMAIN).is_some());
        assert!(value_problem("0.0.0.0", TYPE_IP).is_some());
        assert_eq!(
            value_problem("0.0", TYPE_IP).unwrap(),
            "not a valid IP address"
        );
        assert_eq!(value_problem("52.174.65.77", TYPE_IP), None);
    }

    #[test]
    fn asof_header_is_read() {
        assert_eq!(
            parse_asof("# as-of: 2026-10-18").as_deref(),
            Some("2026-10-18")
        );
        assert_eq!(
            parse_asof("#as-of:2026-10-18").as_deref(),
            Some("2026-10-18")
        );
        assert_eq!(parse_asof("# something else"), None);
    }
}
