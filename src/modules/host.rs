//! Host module — per-user COM persistence, DNS cache, DNS history, hosts file
//! and known fixed-path drops. Ported from zero-breach
//! scan/adint_scan/modules/host.py (Apache-2.0).
//!
//! Four checks, and the reason each one exists:
//!
//! 1. com-persistence. The documented Candiru chain persists via a per-user
//!    COM hijack: a CLSID under HKCU whose InprocServer32 points at a DLL in a
//!    user-writable directory is loaded into every process that instantiates
//!    the class, with no admin rights and no Run key to find. Legitimate
//!    per-user registrations absolutely do exist, so this check LISTS them for
//!    review; a Hit is emitted only when a registered path contains an actual
//!    indicator string.
//! 2. dns-cache. The local resolver cache — a record of what this boot has
//!    already looked up. Reading it resolves nothing (D2).
//! 3. dns-log. Usually the most important check, and it usually FAILS:
//!    Microsoft-Windows-DNS-Client/Operational is disabled by default on
//!    Windows, so there is normally no DNS history to query. Reporting that
//!    gap out loud is the point.
//! 4. hosts-file. An indicator pointed at a sink address is a deliberate
//!    *block* (protective, not reported as a hit); only a mapping to a real
//!    address is a finding.
//!
//! Read-only throughout: this module never writes the registry, never enables
//! the log, and needs no administrator. The Windows-only implementation lives
//! behind `#[cfg(windows)]`; on any other platform every check reports
//! "not supported on <os>" — never a fake CLEAN.

use std::path::{Path, PathBuf};

use crate::context::ScanContext;
use crate::localpaths::path_problem;
use crate::result::{Hit, ModuleResult, EV_CONFIGURED, EV_DNS, EV_ON_DISK, EV_PERSISTENCE};

pub const NAME: &str = "host";

const UNC_PREFIX: &str = "\\\\";
const EXTENDED_PREFIX: &str = "\\\\?\\";
const DEVICE_PREFIX: &str = "\\\\.\\";
const UNC_AFTER_PREFIX: &str = "unc\\";

/// Addresses that mean "this name was deliberately pointed nowhere". Shared by
/// the hosts-file check and the resolver-cache check, because the two have to
/// make the SAME judgement about the same address: a name answered with one of
/// these was blocked by a filter, not reached.
pub const SINK_ADDRESSES: [&str; 5] = ["0.0.0.0", "127.0.0.1", "::1", "::", "0:0:0:0:0:0:0:1"];

/// The sub-keys under a CLSID that name a server binary, in the order the
/// proof-of-concept checks them.
pub const SERVER_KINDS: [&str; 3] = ["InprocServer32", "LocalServer32", "InprocHandler32"];

#[cfg(windows)]
pub const CLSID_PATH: &str = "Software\\Classes\\CLSID";
/// DRIVE_REMOTE from winbase.h: GetDriveTypeW's answer for a letter bound to
/// a network share.
#[cfg(windows)]
const DRIVE_REMOTE: u32 = 4;

/// Exact text required when there is no DNS history to query. Do not reword:
/// this gap is the single most important finding the tool can report.
pub const DNS_LOG_GAP: &str = "DNS-Client/Operational log is disabled (the Windows default) — \
     there is no queryable DNS history, so past activity cannot be checked retrospectively \
     from this host";

pub const ARM_HINT: &str = "dns-log: Windows is not recording DNS history on this machine. See \
     \"HOW TO TURN ON DNS HISTORY\" in this report to start a record a future scan can search. \
     It cannot answer the question for the past.";

/// Spelled out, because "enable DNS logging" is not an instruction most people
/// can act on. One manual command only: the tool deliberately does not write
/// to the system, so there is nothing here that could get the step wrong.
pub fn how_to_enable() -> Vec<String> {
    vec![
        "HOW TO TURN ON DNS HISTORY (so a future scan can answer this):".to_string(),
        "  One command, in an Administrator PowerShell:".to_string(),
        "    1. Click Start, type \"PowerShell\", right-click it, \"Run as administrator\"."
            .to_string(),
        "    2. Paste this line and press Enter:".to_string(),
        "         wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true /ms:67108864"
            .to_string(),
        "  (/e:true turns the log on; /ms sets it to 64 MB so it holds months, not".to_string(),
        "   hours. To turn it back off later, run the same line with /e:false.)".to_string(),
        "  This does NOT protect you and tells you nothing about the past. It means that"
            .to_string(),
        "   next time, there is a record to search instead of an empty attic.".to_string(),
    ]
}

/// Files this campaign and its tooling drop at a FIXED path, where the path
/// itself is the lead. HW.sys is the signed-but-vulnerable kernel driver
/// Candiru brings to disable protections; Avast documented its path.
pub const KNOWN_DROPS: [(&[&str], &str); 1] = [(
    &["System32", "drivers", "HW.sys"],
    "the signed-but-vulnerable driver Candiru uses to disable protections \
     (bring-your-own-vulnerable-driver); documented by Avast, CVE-2022-2294",
)];

/// Cap on how many registered COM files are handed to the optional pattern
/// check.
pub const COM_PATTERN_CANDIDATE_CAP: usize = 128;

fn sysroot_default() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string())
}

// --- shared matching --------------------------------------------------------

/// Case-insensitive match of every network IOC against one blob of local
/// text. Each hit carries its own tier/confidence provenance.
///
/// `detail_fmt` is substituted with a plain replace rather than a format
/// string so that artifact text containing braces can never break the detail
/// line.
pub fn match_blob(
    r: &mut ModuleResult,
    ctx: &ScanContext,
    haystack: &str,
    location: &str,
    detail_fmt: &str,
    evidence: &str,
    observed: &str,
) -> i64 {
    let mut found = 0;
    let low = haystack.to_lowercase();
    if low.is_empty() {
        return 0;
    }
    for ind in ctx.iocs.search(&low) {
        r.add_hit(Hit {
            indicator: ind.value.clone(),
            location: location.to_string(),
            detail: detail_fmt.replace("{ioc}", &ind.value),
            tier: ind.tier.clone(),
            confidence: ind.confidence.clone(),
            source: ind.source.clone(),
            evidence: evidence.to_string(),
            observed: observed.to_string(),
            profile: String::new(),
        });
        found += 1;
    }
    found
}

// --- COM registrations ------------------------------------------------------

/// One per-user COM registration read out of HKCU.
#[derive(Clone, Debug, Default)]
pub struct ComEntry {
    pub clsid: String,
    pub kind: String,
    pub raw: String,
    pub view: String,
    // Computed by check_com:
    pub path: String,
    pub remote_reason: String,
    pub exists: bool,
    pub user_writable: bool,
    pub sig: String,
    pub signer: String,
}

/// Directories a normal user can drop a DLL into without elevation.
pub fn user_writable_dirs() -> Vec<String> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from);
    let mut candidates: Vec<Option<String>> = vec![
        std::env::var("APPDATA").ok(),
        std::env::var("LOCALAPPDATA").ok(),
        std::env::var("TEMP").ok(),
        std::env::var("PROGRAMDATA").ok(),
        home.map(|h| h.join("Downloads").to_string_lossy().into_owned()),
    ];
    candidates.retain(|c| c.is_some());
    candidates
        .into_iter()
        .flatten()
        .map(|d| {
            crate::localpaths::normcase(&crate::localpaths::normpath(std::path::Path::new(&d)))
                .to_string_lossy()
                .trim_end_matches(['\\', '/'])
                .to_lowercase()
        })
        .collect()
}

/// Turn a registered server value into the path of the binary it names.
///
/// InprocServer32/InprocHandler32 hold a bare DLL path. LocalServer32 holds a
/// COMMAND LINE: `"C:\...\App.exe" -Embedding`. Only text is parsed here —
/// even an existence check would contact a UNC server before check_com has
/// had a chance to reject the path.
pub fn server_path(raw: &str, kind: &str) -> String {
    let mut s = expand_vars(raw).trim().to_string();
    if let Some(stripped) = s.strip_prefix('"') {
        if let Some(end) = stripped.find('"') {
            return stripped[..end].trim().to_string();
        }
    }
    s = s.trim_matches('"').trim().to_string();
    if kind == "LocalServer32" && !s.is_empty() {
        // An extension inside a directory (tool.exe\payload.bat) or a longer
        // filename (tool.exe.backup\app.exe) is not the binary's end. Match
        // extensions in command order, not by extension preference: arguments
        // may themselves contain a later .exe path.
        if let Some(end) = command_extension_end(&s) {
            return s[..end].trim().to_string();
        }
    }
    s
}

/// Find the end offset of the first `\.(?:exe|com|bat|cmd)(?=\s|$)` match,
/// case-insensitive.
fn command_extension_end(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = 0;
    while i + 4 <= b.len() {
        if b[i] == b'.' {
            let ext = &s[i + 1..(i + 4).min(s.len())];
            if ext.len() == 3
                && (ext.eq_ignore_ascii_case("exe")
                    || ext.eq_ignore_ascii_case("com")
                    || ext.eq_ignore_ascii_case("bat")
                    || ext.eq_ignore_ascii_case("cmd"))
            {
                // (?=\s|$): the extension must be followed by whitespace or
                // end of string.
                let after_ok = i + 4 == b.len() || b[i + 4].is_ascii_whitespace();
                if after_ok {
                    return Some(i + 4);
                }
            }
        }
        i += 1;
    }
    None
}

/// `os.path.expandvars`: `$VAR` / `${VAR}` (and `%VAR%` on Windows, which is
/// how the Python tool behaved there).
pub fn expand_vars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '$' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'{' {
                if let Some(end) = s[i + 2..].find('}') {
                    let name = &s[i + 2..i + 2 + end];
                    if let Ok(v) = std::env::var(name) {
                        out.push_str(&v);
                    } else {
                        out.push_str(&s[i..i + end + 3]);
                    }
                    i += end + 3;
                    continue;
                }
            } else {
                let mut j = i + 1;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                if j > i + 1 {
                    let name = &s[i + 1..j];
                    if let Ok(v) = std::env::var(name) {
                        out.push_str(&v);
                    } else {
                        out.push_str(&s[i..j]);
                    }
                    i = j;
                    continue;
                }
            }
        } else if cfg!(windows) && c == '%' {
            if let Some(end) = s[i + 1..].find('%') {
                let name = &s[i + 1..i + 1 + end];
                if let Ok(v) = std::env::var(name) {
                    out.push_str(&v);
                } else {
                    out.push_str(&s[i..i + end + 2]);
                }
                i += end + 2;
                continue;
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Why this registered path must NOT be touched, or "" if it is local.
///
/// Asked BEFORE any existence test, because on a UNC path the existence test
/// IS the connection; there is no safe way to ask afterwards.
pub fn remote_path_reason(path: &str, remote_letters: &[char], drives_known: bool) -> String {
    if path.is_empty() {
        return String::new();
    }
    let s = path.replace("/", "\\");
    let low = s.to_lowercase();
    if low.starts_with(EXTENDED_PREFIX) || low.starts_with(DEVICE_PREFIX) {
        // Extended-length prefix. The UNC long-form spelling and an ordinary
        // local path wear the same prefix, so the prefix alone settles nothing:
        // the part after it has to be read.
        if low[4..].starts_with(UNC_AFTER_PREFIX) {
            return "it is a UNC path to a remote share (\\\\?\\UNC\\...)".to_string();
        }
        let rest = &s[4..];
        return drive_letter_problem(rest, remote_letters, drives_known);
    }
    if s.starts_with(UNC_PREFIX) {
        return "it is a UNC path to a remote share (\\\\server\\share)".to_string();
    }
    drive_letter_problem(&s, remote_letters, drives_known)
}

/// A drive letter bound to a remote share must not be touched either; the
/// OS mount table knows, and asking it opens nothing.
fn drive_letter_problem(rest: &str, remote_letters: &[char], drives_known: bool) -> String {
    let rb = rest.as_bytes();
    if rb.len() >= 2 && rb[0].is_ascii_alphabetic() && rb[1] == b':' {
        let letter = rb[0].to_ascii_uppercase() as char;
        if remote_letters.contains(&letter) {
            return format!("drive {}: is mapped to a remote share", letter);
        }
        if !drives_known {
            return format!(
                "drive {}: could not be classified as a local disk or a network \
                 mapping on this host",
                letter
            );
        }
    }
    String::new()
}

/// Leave signatures unverified: the OS verifier may retrieve network data.
///
/// Signature inventory is optional context, never an indicator match. Until a
/// strictly offline verifier is available, no verification subprocess is run.
pub fn signature_status(
    paths: &[String],
) -> (std::collections::HashMap<String, (String, String)>, String) {
    let mut map = std::collections::HashMap::new();
    for p in paths {
        map.insert(p.to_lowercase(), ("NotChecked".to_string(), String::new()));
    }
    let reason = if paths.is_empty() {
        String::new()
    } else {
        "signature verification was not performed because the OS verifier may \
         contact the network; signature status is unknown"
            .to_string()
    };
    (map, reason)
}

/// Run the COM check over an explicit set of registrations. The registry walk
/// itself is Windows-only; everything after it is pure local-path judgement,
/// which is why the refusal tests can run on any platform.
pub fn check_com(
    r: &mut ModuleResult,
    ctx: &mut ScanContext,
    entries: Vec<ComEntry>,
    remote_letters: &[char],
    drives_known: bool,
    partial: &[String],
) -> Vec<ComEntry> {
    let mut entries = entries;
    ctx.emit("[host] enumerating per-user COM registrations (HKCU CLSID)");

    // Expand, de-quote and test each registered path before asking about
    // signatures, so a batched call would only cover files that exist on disk.
    let writable = user_writable_dirs();
    let mut on_disk: Vec<String> = Vec::new();
    for e in entries.iter_mut() {
        let expanded = server_path(&e.raw, &e.kind);
        e.path = expanded.clone();
        let low = if expanded.is_empty() {
            String::new()
        } else {
            crate::localpaths::normcase(&crate::localpaths::normpath(Path::new(&expanded)))
                .to_string_lossy()
                .to_lowercase()
        };
        // Decided before the path is touched: an existence test on a remote
        // path is itself the network contact this tool promises never to make.
        e.remote_reason = remote_path_reason(&expanded, remote_letters, drives_known);
        if e.remote_reason.is_empty() && !expanded.is_empty() {
            e.remote_reason = path_problem(Path::new(&expanded)).unwrap_or_default();
        }
        if !e.remote_reason.is_empty() {
            e.exists = false;
            e.user_writable = false;
            continue;
        }
        e.exists = !expanded.is_empty() && Path::new(&expanded).exists();
        e.user_writable = writable
            .iter()
            .any(|d| low == *d || low.starts_with(&format!("{}\\", d)));
        if e.exists {
            on_disk.push(expanded);
        }
    }

    let (sigs, sig_err) = signature_status(&on_disk);
    if !sig_err.is_empty() {
        r.could_not_run("com-signatures", &sig_err);
    }

    // Pass only bounded, local, user-writable file paths to the optional
    // pattern module; it rechecks each path before reading.
    if ctx.patterns && ctx.pattern_paths.is_empty() {
        let mut unique: std::collections::BTreeMap<String, String> = Default::default();
        for e in &entries {
            if !e.exists || !e.user_writable || !e.remote_reason.is_empty() {
                continue;
            }
            if !Path::new(&e.path).is_file() {
                continue;
            }
            let key = crate::localpaths::normcase(&crate::localpaths::normpath(Path::new(&e.path)))
                .to_string_lossy()
                .into_owned();
            unique.entry(key).or_insert_with(|| e.path.clone());
        }
        let candidates: Vec<String> = unique.into_values().collect();
        let omitted = candidates.len().saturating_sub(COM_PATTERN_CANDIDATE_CAP);
        ctx.pattern_candidate_paths = candidates
            .into_iter()
            .take(COM_PATTERN_CANDIDATE_CAP)
            .map(PathBuf::from)
            .collect();
        ctx.pattern_candidate_omitted = omitted as i64;
    }

    let mut user_writable = 0i64;
    // (location, path, exists, sig, signer) for the reviewable inventory, and
    // (location, path, reason) for the refused ones — collected rather than
    // noted inline, so the lists can be capped the way the Python capped them.
    let mut reviewable: Vec<(String, String, bool, String, String)> = Vec::new();
    let mut unreachable: Vec<(String, String, String)> = Vec::new();
    for e in entries.iter_mut() {
        let status = if !e.remote_reason.is_empty() {
            // NOT "not on disk": nobody looked. Rendering a refusal to look as
            // a measurement is exactly the collapse D3 forbids.
            "not checked (path is not on a local disk)".to_string()
        } else if e.exists {
            sigs.get(&e.path.to_lowercase())
                .map(|(s, _)| s.clone())
                .unwrap_or_else(|| "Unknown".to_string())
        } else {
            "n/a (not on disk)".to_string()
        };
        e.sig = status.clone();
        if e.user_writable {
            user_writable += 1;
        }

        let location = format!(
            "HKCU\\{}\\{}\\{}",
            if e.view == "wow6432" {
                "Software\\Classes\\WOW6432Node\\CLSID"
            } else {
                "Software\\Classes\\CLSID"
            },
            e.clsid,
            e.kind
        );

        // D4: the only COM finding worth calling a Hit is a registered path
        // that actually contains an indicator. "Unsigned DLL in AppData" is a
        // description of a lot of legitimate software, not of this implant.
        match_blob(
            r,
            ctx,
            &format!("{} {}", e.raw, e.path),
            &location,
            "per-user COM server registration references indicator {ioc} — a COM \
             hijack is this chain's documented persistence; investigate the \
             registration and the binary",
            EV_PERSISTENCE,
            "",
        );

        // The string match above is pure text and costs nothing, so a remote
        // registration is still matched against the indicator set — it is only
        // the FILE behind it that is left alone.
        if !e.remote_reason.is_empty() {
            unreachable.push((location.clone(), e.path.clone(), e.remote_reason.clone()));
        }

        // Reviewable inventory, deliberately narrowed: an entry is only worth
        // a human's attention if it is BOTH in a user-writable directory AND
        // not validly signed.
        if e.user_writable && status != "Valid" && status != "Unknown" && status != "NotChecked" {
            reviewable.push((location, e.path.clone(), e.exists, status, e.signer.clone()));
        }
    }

    if !reviewable.is_empty() {
        r.note(&format!(
            "com-persistence: {} per-user COM registration(s) are in a folder you can \
             write to and are not validly signed. Legitimate software does this too - \
             these are pointers for a reviewer, NOT findings, and none of them matched \
             an indicator.",
            reviewable.len()
        ));
        for (location, path, exists, sig, signer) in reviewable.iter().take(3) {
            r.note(&format!(
                "    - {} -> {} [on disk: {}; signature: {}{}]",
                location,
                if path.is_empty() { "(empty)" } else { path },
                if *exists { "yes" } else { "no" },
                sig,
                if signer.is_empty() {
                    String::new()
                } else {
                    format!("; signer: {}", signer)
                }
            ));
        }
        if reviewable.len() > 3 {
            r.note(&format!(
                "    - ... and {} more, listed in full in the JSON report.",
                reviewable.len() - 3
            ));
        }
    }

    if !unreachable.is_empty() {
        // Refusing to touch the path is the right call, but a refusal is a
        // GAP, not a clean entry, and the user is owed both facts.
        r.note(&format!(
            "com-persistence: {} per-user COM registration(s) name a path that is not on \
             a local disk. The scanner did NOT open them. Merely testing whether such a \
             path exists makes Windows open a connection to the remote host - and can \
             hand that host this account's network credentials - which is the one thing \
             this tool promises never to do. These entries are UNVERIFIED: their file \
             was not fingerprinted and its signature was not checked.",
            unreachable.len()
        ));
        for (location, path, reason) in unreachable.iter().take(3) {
            r.note(&format!(
                "    - {} -> {} [not checked: {}]",
                location,
                if path.is_empty() { "(empty)" } else { path },
                reason
            ));
        }
        if unreachable.len() > 3 {
            r.note(&format!(
                "    - ... and {} more, listed in full in the JSON report.",
                unreachable.len() - 3
            ));
        }
    }

    r.checked += entries.len() as i64;
    r.set_metric("com_registrations", entries.len() as i64);
    r.set_metric("com_user_writable", user_writable);
    if !unreachable.is_empty() {
        r.set_metric("com_remote_paths", unreachable.len() as i64);
    }

    // A truncated enumeration must not pass as a complete one (D3).
    if !partial.is_empty() {
        r.could_not_run(
            "com-persistence",
            &format!(
                "the registry could not be fully enumerated, so an auto-start entry may \
                 have been missed: {}",
                partial.join("; ")
            ),
        );
    } else if !unreachable.is_empty() {
        // Same doctrine, different cause: the registry was read in full, but
        // some of what it named was deliberately not opened.
        let mut reasons: Vec<String> = unreachable
            .iter()
            .map(|(_l, _p, reason)| reason.clone())
            .collect();
        reasons.sort();
        reasons.dedup();
        r.could_not_run(
            "com-persistence",
            &format!(
                "{} registered path(s) are not on a local disk and were deliberately not \
                 opened (contacting them is what this tool promises not to do), so those \
                 entries were not verified: {}",
                unreachable.len(),
                reasons.join("; ")
            ),
        );
    } else {
        r.ran("com-persistence");
    }
    ctx.emit(&format!(
        "[host] COM registrations: {} ({} in user-writable dirs)",
        entries.len(),
        user_writable
    ));
    entries
}

// --- DNS resolver cache -----------------------------------------------------

/// One row of `Get-DnsClientCache` output.
#[derive(Clone, Debug, Default)]
pub struct DnsCacheRow {
    pub entry: String,
    pub name: String,
    pub data: String,
}

/// Grade the resolver cache the scanner was handed (Windows fetches it with
/// PowerShell; the grading itself is platform-independent and testable).
pub fn check_dns_cache(
    r: &mut ModuleResult,
    ctx: &mut ScanContext,
    rows: &[DnsCacheRow],
    boot: Option<String>,
    boot_err: &str,
) {
    ctx.emit("[host] reading local DNS resolver cache");
    let mut hits = 0i64;
    let mut blocked = 0i64;
    for row in rows {
        // Windows preloads hosts-file mappings into the resolver cache when
        // the DNS Client starts, even if no application looked up that name.
        // A sink entry is therefore protective state, not proof of an
        // attempted connection.
        let was_blocked = SINK_ADDRESSES.contains(&row.data.trim().to_lowercase().as_str());
        let haystack = format!("{} {} {}", row.entry, row.name, row.data);
        if was_blocked {
            blocked += ctx.iocs.search(&haystack.to_lowercase()).len() as i64;
            continue;
        }
        let detail = format!(
            "indicator {{ioc}} appears as a name or address in this boot's DNS \
             resolver cache (Entry={} Name={} Data={}) — this is a resolver record; \
             endpoint contact is unverified",
            if row.entry.is_empty() {
                "-"
            } else {
                &row.entry
            },
            if row.name.is_empty() { "-" } else { &row.name },
            if row.data.is_empty() { "-" } else { &row.data }
        );
        hits += match_blob(r, ctx, &haystack, "DNS resolver cache", &detail, EV_DNS, "");
    }

    r.checked += rows.len() as i64;
    r.set_metric("dns_cache_entries", rows.len() as i64);
    if blocked > 0 {
        r.set_metric("dns_cache_blocked_indicators", blocked);
        r.note(&format!(
            "dns-cache: {} indicator entry/entries point to a sink address. This is \
             protective state, not a finding. Windows can preload these entries from \
             the hosts file without any lookup; no attempt or contact is established.",
            blocked
        ));
    }

    // The resolver cache is wiped by a reboot, so its whole window is "since
    // last boot". Stating that plainly stops a clean cache being read as a
    // clean history.
    r.reach_set(
        "dns-cache",
        serde_json::json!({
            "earliest": boot,
            "days": serde_json::Value::Null,
            "basis": format!(
                "the resolver cache holds only this boot session{}",
                if boot_err.is_empty() {
                    String::new()
                } else {
                    format!(" (boot time unavailable: {})", boot_err)
                }
            ),
            "note": "The cache includes hosts-file mappings loaded at startup and records \
                     obtained during this boot. An entry alone does not establish that an \
                     application looked it up or connected.",
        }),
    );
    r.ran("dns-cache");
    ctx.emit(&format!(
        "[host] DNS cache entries: {} ({} DNS findings, {} protective sink entries)",
        rows.len(),
        hits,
        blocked
    ));
}

// --- retrospective DNS history ---------------------------------------------

/// `Get-WinEvent -ListLog` metadata for the DNS-Client channel.
#[derive(Clone, Copy, Debug)]
pub struct DnsLogMeta {
    pub is_enabled: bool,
    pub record_count: i64,
}

/// One DNS-Client/Operational event.
#[derive(Clone, Debug, Default)]
pub struct DnsEvent {
    pub time: String,
    pub message: String,
}

/// Grade the DNS history check. `meta` is Err when the log could not be
/// queried at all; `fetch_events` is the second PowerShell call on Windows
/// and a fixture in tests.
pub fn check_dns_log(
    r: &mut ModuleResult,
    ctx: &mut ScanContext,
    meta: Result<DnsLogMeta, String>,
    fetch_events: &mut dyn FnMut() -> (Vec<DnsEvent>, String),
) {
    ctx.emit("[host] checking whether DNS-Client/Operational history exists");
    let meta = match meta {
        Ok(m) => m,
        Err(err) => {
            // Log absent or unreadable: the consequence for the user is
            // identical to it being disabled, so it is reported as the same
            // gap, not as an incidental error.
            r.set_metric("dns_log_enabled", 0);
            r.set_metric("dns_log_records", 0);
            r.could_not_run("dns-log", DNS_LOG_GAP);
            r.note(&format!(
                "dns-log: {} could not be queried ({})",
                DNS_CHANNEL,
                if err.is_empty() {
                    "log not present on this host".to_string()
                } else {
                    err
                }
            ));
            r.note(ARM_HINT);
            r.reach_set(
                "dns-log",
                serde_json::json!({
                    "earliest": serde_json::Value::Null,
                    "days": 0,
                    "basis": "DNS log metadata could not be read",
                    "note": "No historical window could be established. Older or unread \
                             records may still exist.",
                    "how_to_enable": how_to_enable(),
                }),
            );
            return;
        }
    };
    let enabled = meta.is_enabled;
    let records = meta.record_count;
    r.set_metric("dns_log_enabled", if enabled { 1 } else { 0 });
    r.set_metric("dns_log_records", records);

    if records <= 0 {
        // The important branch, and the common one. This must never read clean.
        r.could_not_run("dns-log", DNS_LOG_GAP);
        r.note(&format!(
            "dns-log: {} enabled={} records={} — forward-looking checks are possible, \
             retrospective ones are not.",
            DNS_CHANNEL, enabled, records
        ));
        r.note(ARM_HINT);
        r.reach_set(
            "dns-log",
            serde_json::json!({
                "earliest": serde_json::Value::Null,
                "days": 0,
                "basis": format!(
                    "DNS logging is {} and holds {} records",
                    if enabled { "enabled" } else { "disabled" },
                    records
                ),
                "note": "No saved DNS events were available for this scan. This does not \
                         establish whether older events existed or were cleared.",
                "how_to_enable": how_to_enable(),
            }),
        );
        return;
    }

    // IsEnabled controls current collection, not whether retained events can
    // be read. Disabling logging must not hide existing historical evidence.
    if !enabled {
        r.could_not_run(
            "dns-log-recording",
            "DNS logging is currently off; queries made while logging was off may be \
             missing",
        );
        r.note(&format!(
            "dns-log: logging is off; the log reports {} saved event(s). Checking them \
             does not enable logging.",
            records
        ));
    }
    ctx.emit(&format!(
        "[host] DNS-Client/Operational logging is {} ({} retained records); scanning \
         messages",
        if enabled { "on" } else { "off" },
        records
    ));
    let (events, ev_err) = fetch_events();
    if (!ev_err.is_empty() && events.is_empty()) || (records > 0 && events.is_empty()) {
        let reason = format!(
            "log has {} retained records but none could be read{} - this machine's DNS \
             history was NOT searched, so nothing here is cleared",
            records,
            if ev_err.is_empty() {
                String::new()
            } else {
                format!(": {}", ev_err)
            }
        );
        r.could_not_run("dns-log", &reason);
        return;
    }

    let times: Vec<String> = events
        .iter()
        .map(|ev| ev.time.clone())
        .filter(|t| !t.is_empty())
        .collect();
    if !times.is_empty() {
        // Retained records have dates even when logging is currently disabled.
        let mut earliest = times.clone();
        earliest.sort();
        let mut note = "Queries before this are either rotated out of the log or beyond \
                        the bounded event read."
            .to_string();
        if !enabled {
            note.push_str(
                " Logging is currently off; queries during unrecorded periods may be \
                 missing.",
            );
        }
        let mut reach = serde_json::json!({
            "earliest": earliest[0],
            "days": serde_json::Value::Null,
            "basis": format!(
                "oldest of {} DNS events read (cap {})",
                crate::text::fmt_count_i(times.len() as i64),
                crate::text::fmt_count_i(DNS_EVENT_CAP)
            ),
            "note": note,
        });
        if !enabled {
            reach["how_to_enable"] = serde_json::json!(how_to_enable());
        }
        r.reach_set("dns-log", reach);
    }
    let mut hits = 0i64;
    for ev in &events {
        let when = ev.time.clone();
        let detail = format!(
            "indicator {{ioc}} appears as a name or address in a \
             DNS-Client/Operational event{} — the event alone does not establish \
             successful resolution or endpoint contact",
            if when.is_empty() {
                String::new()
            } else {
                format!(" at {}", when)
            }
        );
        hits += match_blob(
            r,
            ctx,
            &ev.message,
            &format!(
                "{} @ {}",
                DNS_CHANNEL,
                if when.is_empty() {
                    "unknown time".to_string()
                } else {
                    when.clone()
                }
            ),
            &detail,
            EV_DNS,
            &when,
        );
    }

    r.checked += events.len() as i64;
    r.set_metric("dns_log_events_scanned", events.len() as i64);
    r.ran("dns-log");
    if records > events.len() as i64 {
        // A note alone let the overall check appear complete and clean even
        // though older retained DNS records were never examined.
        r.could_not_run(
            "dns-log-older-events",
            &format!(
                "examined the most recent {} of {} retained records (read cap {}); older \
                 entries were not checked",
                events.len(),
                records,
                crate::text::fmt_count_i(DNS_EVENT_CAP)
            ),
        );
    }
    ctx.emit(&format!(
        "[host] DNS log events scanned: {} ({} indicator matches)",
        events.len(),
        hits
    ));
}

pub const DNS_CHANNEL: &str = "Microsoft-Windows-DNS-Client/Operational";
pub const DNS_EVENT_CAP: i64 = 50_000;

// --- hosts file -------------------------------------------------------------

/// Read and grade the hosts file under `root` (System32/drivers/etc/hosts).
pub fn check_hosts(r: &mut ModuleResult, ctx: &mut ScanContext, root: &str) {
    let path = std::path::Path::new(root)
        .join("System32")
        .join("drivers")
        .join("etc")
        .join("hosts");
    ctx.emit(&format!("[host] reading {}", path.display()));
    if let Some(problem) = path_problem(&path) {
        r.could_not_run("hosts-file", &problem);
        return;
    }
    if !path.exists() {
        r.could_not_run(
            "hosts-file",
            &format!("no hosts file at {}", path.display()),
        );
        return;
    }
    let raw = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            r.could_not_run(
                "hosts-file",
                &format!("could not read {}: {}", path.display(), e),
            );
            return;
        }
    };

    let active: Vec<String> = raw
        .lines()
        .map(|ln| ln.trim())
        .filter(|ln| !ln.is_empty() && !ln.starts_with('#'))
        .map(String::from)
        .collect();
    // A hosts line is "<address> <hostname...>". Pointing an indicator at one
    // of the sink addresses is a deliberate BLOCK — protective, the OPPOSITE
    // of a compromise — so it is not reported as a hit at all, only counted.
    let mut hits = 0i64;
    let mut blocked = 0i64;
    for line in &active {
        let addr = line.split_whitespace().next().unwrap_or("").to_string();
        if SINK_ADDRESSES.contains(&addr.as_str()) {
            // Still check it DOES contain an indicator, for the block count,
            // but never raise a hit on a protective entry.
            if !ctx.iocs.search(&line.to_lowercase()).is_empty() {
                blocked += 1;
            }
            continue;
        }
        hits += match_blob(
            r,
            ctx,
            line,
            &path.to_string_lossy(),
            &format!(
                "indicator {{ioc}} is mapped in the hosts file to {} (line: {}). This is \
                 NOT a sink/block address, so the name has been pointed at a real host on \
                 this machine - unusual, and worth checking who added it.",
                addr, line
            ),
            EV_CONFIGURED,
            "",
        );
    }

    r.checked += 1;
    r.set_metric("hosts_entries", active.len() as i64);
    if blocked > 0 {
        r.set_metric("hosts_blocked_indicators", blocked);
        r.note(&format!(
            "hosts-file: {} indicator(s) are BLOCKED in the hosts file (pointed at a \
             sink address). That is protective, not a finding.",
            blocked
        ));
    }
    r.ran("hosts-file");
    ctx.emit(&format!(
        "[host] active hosts entries: {} ({} indicator matches, {} blocked)",
        active.len(),
        hits,
        blocked
    ));
}

// --- known fixed-path file drops -------------------------------------------

/// Check the known fixed drop paths under `root`. A file at a known malware
/// path is a lead, but the path alone is not proof — the name can be
/// legitimate, so the check fingerprints it and raises a serious hit ONLY when
/// the fingerprint matches a known-bad hash.
pub fn check_known_paths(r: &mut ModuleResult, ctx: &mut ScanContext, root: &str) {
    let known_hashes: std::collections::HashSet<String> = ctx
        .iocs
        .hashes()
        .into_iter()
        .map(|h| h.value.clone())
        .collect();
    let mut found = 0i64;
    let mut unavailable = 0i64;
    for (parts, why) in KNOWN_DROPS {
        let mut path = std::path::PathBuf::from(root);
        for part in parts {
            path.push(part);
        }
        let path_text = path.to_string_lossy().into_owned();
        if let Some(problem) = path_problem(&path) {
            unavailable += 1;
            r.skipped += 1;
            r.could_not_run(
                &format!("known-path:{}", path_text),
                &format!("could not inspect this path: {}", problem),
            );
            continue;
        }
        if let Err(e) = std::fs::metadata(&path) {
            if e.kind() == std::io::ErrorKind::NotFound {
                continue;
            }
            unavailable += 1;
            r.skipped += 1;
            r.could_not_run(
                &format!("known-path:{}", path_text),
                &format!("could not inspect this path: {}", e),
            );
            continue;
        }
        found += 1;
        let digest = match fingerprint_file(&path) {
            Ok(d) => d,
            Err(e) => {
                unavailable += 1;
                r.skipped += 1;
                r.could_not_run(
                    &format!("known-path:{}", path_text),
                    &format!("file exists but its fingerprint is unavailable: {}", e),
                );
                continue;
            }
        };
        if !digest.is_empty() && known_hashes.contains(&digest) {
            let ind = ctx.iocs.lookup(&digest);
            let tier = ind
                .map(|i| i.tier.clone())
                .unwrap_or_else(|| "sample".to_string());
            // A `vuln-driver` match is legitimate signed software this actor
            // abuses - present on clean machines too. Calling that "KNOWN-BAD"
            // would tell an innocent owner they are infected, so the wording is
            // chosen from the tier.
            let detail = if tier == "vuln-driver" {
                format!(
                    "the file at {} matches a published indicator for {}. This file is \
                     LEGITIMATE, signed software that is also installed for honest reasons \
                     - its presence is NOT proof of spyware. Worth establishing how and \
                     when it was installed. Do not delete it.",
                    path_text, why
                )
            } else {
                format!(
                    "the file at {} is the KNOWN-BAD build - {}. Its SHA-256 matches a \
                     published indicator. Do not delete it; it is evidence.",
                    path_text, why
                )
            };
            r.add_hit(Hit {
                indicator: digest.clone(),
                location: path_text.clone(),
                detail,
                tier,
                confidence: ind
                    .map(|i| i.confidence.clone())
                    .unwrap_or_else(|| "secondary".to_string()),
                source: ind.map(|i| i.source.clone()).unwrap_or_default(),
                evidence: EV_ON_DISK.to_string(),
                observed: String::new(),
                profile: String::new(),
            });
        } else {
            // Present, but not the known-bad hash. A legitimate driver of the
            // same name exists, so this is a POINTER, not a hit.
            r.note(&format!(
                "known-paths: a file exists at {} ({}). This path is {}. Its fingerprint \
                 does NOT match the known-bad build{}, so it is most likely a legitimate \
                 same-named file - but given the path it is worth a look.",
                path_text,
                if digest.is_empty() {
                    "unreadable".to_string()
                } else {
                    format!("SHA-256 {}...", &digest[..16.min(digest.len())])
                },
                why,
                if digest.is_empty() {
                    " (could not read it)"
                } else {
                    ""
                }
            ));
        }
    }
    r.checked += KNOWN_DROPS.len() as i64 - unavailable;
    r.set_metric(
        "known_paths_checked",
        KNOWN_DROPS.len() as i64 - unavailable,
    );
    if found > 0 {
        r.set_metric("known_paths_present", found);
    }
    if unavailable < KNOWN_DROPS.len() as i64 {
        r.ran("known-paths");
    }
    ctx.emit(&format!(
        "[host] known fixed-path drops: {} checked, {} present",
        KNOWN_DROPS.len(),
        found
    ));
}

fn fingerprint_file(path: &std::path::Path) -> Result<String, String> {
    use sha2::Digest;
    use std::io::Read;
    let mut h = sha2::Sha256::new();
    let mut fh = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = fh.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

// --- module entry point -----------------------------------------------------

/// Run the host module for this platform. On anything but Windows every check
/// is reported as not supported — never a fake CLEAN.
pub fn run(ctx: &mut ScanContext) -> ModuleResult {
    let mut r = ModuleResult::new(NAME);
    ctx.publish_partial(&r);

    if !cfg!(windows) {
        // Never a fake CLEAN on a platform where nothing was observed.
        let reason = format!("not supported on {}", crate::report::system_name());
        for name in [
            "com-persistence",
            "dns-cache",
            "dns-log",
            "hosts-file",
            "known-paths",
        ] {
            r.could_not_run(name, &reason);
        }
        return r;
    }
    #[cfg(windows)]
    {
        run_windows(ctx, &mut r);
    }
    r
}

/// Per-check isolation: one failure must not cost the others.
#[cfg(windows)]
fn run_windows(ctx: &mut ScanContext, r: &mut ModuleResult) {
    let checks: [(&str, fn(&mut ModuleResult, &mut ScanContext)); 5] = [
        ("com-persistence", check_com_live),
        ("dns-cache", check_dns_cache_live),
        ("dns-log", check_dns_log_live),
        ("hosts-file", check_hosts_live),
        ("known-paths", check_known_paths_live),
    ];
    for (name, f) in checks {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(r, ctx)));
        if outcome.is_err() {
            r.skipped += 1;
            r.could_not_run(name, "module error: check panicked");
        }
    }
}

#[cfg(windows)]
fn check_com_live(r: &mut ModuleResult, ctx: &mut ScanContext) {
    let (entries, partial) = enum_com_registrations();
    let (letters, known) = network_drive_letters();
    check_com(r, ctx, entries, &letters, known, &partial);
}

#[cfg(windows)]
fn check_dns_cache_live(r: &mut ModuleResult, ctx: &mut ScanContext) {
    let (rows, err) = ps_json(
        "Get-DnsClientCache -ErrorAction Stop | Select-Object Entry,Name,Data,Type | \
         ConvertTo-Json -Depth 3 -Compress",
        60,
    );
    if !err.is_empty() {
        r.could_not_run(
            "dns-cache",
            &format!("Get-DnsClientCache unavailable: {}", err),
        );
        return;
    }
    let rows: Vec<DnsCacheRow> = rows
        .iter()
        .map(|row| DnsCacheRow {
            entry: ps_str(row, &["Entry"]),
            name: ps_str(row, &["Name"]),
            data: ps_str(row, &["Data"]),
        })
        .collect();
    let (boot, boot_err) = boot_time();
    check_dns_cache(r, ctx, &rows, boot, &boot_err);
}

#[cfg(windows)]
fn check_dns_log_live(r: &mut ModuleResult, ctx: &mut ScanContext) {
    let (rows, err) = ps_json(
        &format!(
            "Get-WinEvent -ListLog '{}' -ErrorAction Stop | Select-Object \
             @{{n='IsEnabled';e={{[bool]$_.IsEnabled}}}}, \
             @{{n='RecordCount';e={{[int]$_.RecordCount}}}} | ConvertTo-Json -Depth 3 -Compress",
            DNS_CHANNEL
        ),
        60,
    );
    let meta = if !err.is_empty() || rows.is_empty() {
        Err(err)
    } else {
        Ok(DnsLogMeta {
            is_enabled: rows[0]
                .get("IsEnabled")
                .map(|v| !matches!(v, serde_json::Value::Null | serde_json::Value::Bool(false)))
                .unwrap_or(false),
            record_count: rows[0]
                .get("RecordCount")
                .and_then(|v| {
                    v.as_i64()
                        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                })
                .unwrap_or(0),
        })
    };
    check_dns_log(r, ctx, meta, &mut || {
        let (events, ev_err) = ps_json(
            &format!(
                "Get-WinEvent -LogName '{}' -MaxEvents {} -ErrorAction Stop | \
                 Select-Object @{{n='Time';e={{$_.TimeCreated.ToString('o')}}}}, \
                 @{{n='Message';e={{[string]$_.Message}}}} | ConvertTo-Json -Depth 3 -Compress",
                DNS_CHANNEL, DNS_EVENT_CAP
            ),
            300,
        );
        let events: Vec<DnsEvent> = events
            .iter()
            .map(|row| DnsEvent {
                time: ps_str(row, &["Time"]),
                message: ps_str(row, &["Message"]),
            })
            .collect();
        (events, ev_err)
    });
}

#[cfg(windows)]
fn check_hosts_live(r: &mut ModuleResult, ctx: &mut ScanContext) {
    check_hosts(r, ctx, &sysroot_default());
}

#[cfg(windows)]
fn check_known_paths_live(r: &mut ModuleResult, ctx: &mut ScanContext) {
    check_known_paths(r, ctx, &sysroot_default());
}

// --- Windows-only plumbing --------------------------------------------------

#[cfg(windows)]
/// Resolve PowerShell by its absolute path, never the bare name. Invoked as
/// "powershell", Windows resolves it through the executable search order —
/// which includes the CURRENT DIRECTORY before System32, and users are told
/// to run this tool from their Downloads folder. An absolute path is never
/// resolved through that search.
fn ps_exe() -> std::path::PathBuf {
    std::path::Path::new(&sysroot_default())
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe")
}

#[cfg(windows)]
fn ps(cmd: &str, timeout_secs: u64) -> Result<(i32, String, String), String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    // Ask PowerShell to actually write UTF-8, so the decode has nothing to
    // repair. errors="replace" is load-bearing: a mangled character in a
    // signer name is a far better outcome than a phantom gap.
    let full = format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; {}",
        cmd
    );
    let mut child = Command::new(ps_exe())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &full,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A directory the scanner does not control, so the child cannot
        // inherit a hostile working directory either.
        .current_dir(sysroot_default())
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                let mut err = String::new();
                if let Some(mut o) = child.stdout.take() {
                    let _ = o.read_to_string(&mut out);
                }
                if let Some(mut e) = child.stderr.take() {
                    let _ = e.read_to_string(&mut err);
                }
                let _ = status;
                return Ok((0, out, err));
            }
            Ok(None) => {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    return Err(format!("PowerShell timed out after {}s", timeout_secs));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

#[cfg(windows)]
/// Run a PowerShell command whose output is ConvertTo-Json. Returns (rows,
/// error). `rows` is always a list: ConvertTo-Json emits a bare object (not an
/// array) for a single result and nothing at all for an empty one.
fn ps_json(cmd: &str, timeout_secs: u64) -> (Vec<serde_json::Value>, String) {
    let (rc, out, err) = match ps(cmd, timeout_secs) {
        Ok(v) => v,
        Err(e) => return (Vec::new(), e),
    };
    let text = out.trim().to_string();
    if rc != 0 {
        let reason = err
            .trim()
            .lines()
            .next()
            .unwrap_or(&format!("PowerShell exited {}", rc))
            .to_string();
        return (Vec::new(), reason);
    }
    if text.is_empty() || text == "null" {
        return (Vec::new(), String::new());
    }
    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(serde_json::Value::Array(list)) => (list, String::new()),
        Ok(v @ serde_json::Value::Object(_)) => (vec![v], String::new()),
        Ok(_) => (
            Vec::new(),
            "unexpected JSON shape from PowerShell".to_string(),
        ),
        Err(e) => (
            Vec::new(),
            format!("unparseable JSON from PowerShell: {}", e),
        ),
    }
}

#[cfg(windows)]
fn ps_str(row: &serde_json::Value, names: &[&str]) -> String {
    for name in names {
        let val = row.get(*name);
        if let Some(v) = val {
            match v {
                serde_json::Value::Null => {}
                serde_json::Value::String(s) if s.is_empty() => {}
                other => return other.to_string().trim_matches('"').to_string(),
            }
        }
    }
    String::new()
}

#[cfg(windows)]
fn boot_time() -> (Option<String>, String) {
    let (rows, err) = ps_json(
        "Get-CimInstance Win32_OperatingSystem | Select-Object \
         @{n='Boot';e={$_.LastBootUpTime.ToString('o')}} | ConvertTo-Json -Depth 2 -Compress",
        60,
    );
    if !err.is_empty() || rows.is_empty() {
        return (
            None,
            if err.is_empty() {
                "no result".to_string()
            } else {
                err
            },
        );
    }
    (Some(ps_str(&rows[0], &["Boot"])), String::new())
}

#[cfg(windows)]
fn network_drive_letters() -> (Vec<char>, bool) {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    let mut letters = Vec::new();
    for code in b'A'..=b'Z' {
        let letter = code as char;
        let path = format!("{}:\\", letter);
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let kind = unsafe { GetDriveTypeW(wide.as_ptr()) };
        if kind == DRIVE_REMOTE {
            letters.push(letter);
        }
    }
    (letters, true)
}

#[cfg(windows)]
/// Walk HKCU CLSID (both views) and collect every registered server path.
///
/// Uses winreg rather than PowerShell: this is thousands of key opens and
/// spawning a shell for it would dominate the module's runtime. Both the
/// 64-bit and 32-bit registry views are read via explicit KEY_WOW64_*KEY
/// flags on the ONE logical path.
fn enum_com_registrations() -> (Vec<ComEntry>, Vec<String>) {
    use winreg::enums::{KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    use winreg::RegKey;

    let mut entries: Vec<ComEntry> = Vec::new();
    let mut partial: Vec<String> = Vec::new();
    let views = [("native", KEY_WOW64_64KEY), ("wow6432", KEY_WOW64_32KEY)];
    for (view_name, view_flag) in views {
        let hk = RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        let base = match hk.open_subkey_with_flags(CLSID_PATH, KEY_READ | view_flag) {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                continue; // this view genuinely has no CLSID key - not a failure
            }
            Err(e) => {
                partial.push(format!("{} view could not be opened ({})", view_name, e));
                continue;
            }
        };
        // ERROR_NO_MORE_ITEMS ends this iterator; any other error is an
        // ABORTED walk, not an exhausted one, and is recorded so a truncated
        // enumeration cannot pass as complete.
        let mut index = 0u32;
        for entry in base.enum_keys() {
            let clsid = match entry {
                Ok(k) => k,
                Err(e) => {
                    partial.push(format!(
                        "{} view enumeration stopped after {} keys ({})",
                        view_name, index, e
                    ));
                    break;
                }
            };
            index += 1;
            for kind in SERVER_KINDS {
                let sub = format!("{}\\{}", clsid, kind);
                let key = match base.open_subkey_with_flags(&sub, KEY_READ | view_flag) {
                    Ok(k) => k,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => {
                        partial.push(format!("{} {} could not be read ({})", view_name, sub, e));
                        continue;
                    }
                };
                let value: Result<String, _> = key.get_value("");
                match value {
                    Ok(v) if !v.trim().is_empty() => entries.push(ComEntry {
                        clsid: clsid.clone(),
                        kind: kind.to_string(),
                        raw: v,
                        view: view_name.to_string(),
                        ..Default::default()
                    }),
                    _ => continue,
                }
            }
        }
    }
    (entries, partial)
}

// The Windows-only plumbing above (winreg / PowerShell / GetDriveTypeW) is
// compiled nowhere else; everything before it is deliberately platform-
// independent so the refusal and grading tests can run on any OS.
