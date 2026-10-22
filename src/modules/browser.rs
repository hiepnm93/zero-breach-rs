//! Search this machine's browser artifacts for AdFection / Candiru IOC
//! domains. Ported from zero-breach scan/adint_scan/modules/browser.py
//! (Apache-2.0).
//!
//! Why several artifact types and not just history: browser HISTORY only
//! records top-level navigations, and an ad is a subresource inside an iframe.
//! A real AdFection impression would almost certainly never appear in history.
//! The HTTP cache, the cookie stores and the local-storage LevelDB files do
//! record subresource origins, so they are where a retrospective trace would
//! actually survive.
//!
//! Read-only. Databases are copied before being opened, because a running
//! browser holds a write lock on them; the copy is opened and the temp dir is
//! always cleaned up. No network, ever (doctrine D2) — needles are matched as
//! plain substrings and never resolved. Cookie VALUES are never selected:
//! only host names and timestamps (see the not-infostealer tests).
//!
//! Honest gaps (D3). A browser's databases are often locked because the
//! browser is running. That is NOT a clean result, it is a gap. So this module
//! tracks, per (browser label, artifact kind), whether at least one profile
//! could actually be read; a kind that was present somewhere but could never
//! be read becomes a `could_not_run` gap, and a kind that is simply ABSENT is
//! recorded as nothing at all.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};
use serde_json::Value;

use crate::context::ScanContext;
use crate::datetime;
use crate::iocs::{Indicator, IocSet, TYPE_DOMAIN};
use crate::localpaths::{local_temp_dir, path_problem, walk_local, WalkHandler, WalkProblem};
use crate::result::{
    Hit, ModuleResult, EV_CONTACTED, EV_REFERENCED,
};
use crate::text::{fmt_count, sha256_b64};

pub const NAME: &str = "browser";

/// Largest browser database we will snapshot, siblings included. Real
/// History / Cookies files are tens of MB; 1 GiB leaves generous headroom.
const MAX_SNAPSHOT_BYTES: u64 = 1024 * 1024 * 1024;

const BLOB_MAX_BYTES: u64 = 400 * 1024 * 1024;

/// Files that mark a directory as a real Firefox profile (as opposed to a
/// sibling folder like Crash Reports / Pending Pings that lives in the same
/// root on Linux). Any one is enough.
const FF_PROFILE_MARKERS: [&str; 8] = [
    "prefs.js",
    "places.sqlite",
    "cookies.sqlite",
    "favicons.sqlite",
    "SiteSecurityServiceState.txt",
    "cert9.db",
    "key4.db",
    "logins.json",
];

/// `sys.platform`-style names, so gap texts match the Python tool's wording.
pub fn sys_platform() -> &'static str {
    if cfg!(windows) {
        "win32"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}

/// Chromium user-data roots as (label, path), chosen by platform.
pub fn chromium_roots() -> Vec<(String, PathBuf)> {
    chromium_roots_for(
        sys_platform(),
        &home_dir(),
        &env_path("LOCALAPPDATA"),
    )
}

/// The same table, parameterised so tests can point it at a fixture tree.
pub fn chromium_roots_for(platform: &str, home: &Path, local: &Path) -> Vec<(String, PathBuf)> {
    let join = |parts: &[&str]| -> PathBuf {
        let mut p = local.to_path_buf();
        for part in parts {
            p.push(part);
        }
        p
    };
    let home_join = |parts: &[&str]| -> PathBuf {
        let mut p = home.to_path_buf();
        for part in parts {
            p.push(part);
        }
        p
    };
    match platform {
        "win32" => vec![
            ("chrome", join(&["Google", "Chrome", "User Data"])),
            ("edge", join(&["Microsoft", "Edge", "User Data"])),
            (
                "brave",
                join(&["BraveSoftware", "Brave-Browser", "User Data"]),
            ),
            ("chromium", join(&["Chromium", "User Data"])),
            ("vivaldi", join(&["Vivaldi", "User Data"])),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b))
        .collect(),
        "darwin" => {
            let asup = home_join(&["Library", "Application Support"]);
            vec![
                ("chrome", asup.join("Google").join("Chrome")),
                ("edge", asup.join("Microsoft Edge")),
                ("brave", asup.join("BraveSoftware").join("Brave-Browser")),
                ("chromium", asup.join("Chromium")),
                ("vivaldi", asup.join("Vivaldi")),
            ]
            .into_iter()
            .map(|(a, b)| (a.to_string(), b))
            .collect()
        }
        p if p.starts_with("linux") => {
            let cfg = home_join(&[".config"]);
            let var = home_join(&[".var", "app"]);
            let snap = home_join(&["snap"]);
            vec![
                ("chrome", cfg.join("google-chrome")),
                ("chromium", cfg.join("chromium")),
                ("brave", cfg.join("BraveSoftware").join("Brave-Browser")),
                ("edge", cfg.join("microsoft-edge")),
                ("vivaldi", cfg.join("vivaldi")),
                ("vivaldi-snapshot", cfg.join("vivaldi-snapshot")),
                // snap packaging
                (
                    "chromium-snap",
                    snap.join("chromium").join("common").join("chromium"),
                ),
                // flatpak packaging
                (
                    "chrome-flatpak",
                    var.join("com.google.Chrome")
                        .join("config")
                        .join("google-chrome"),
                ),
                (
                    "brave-flatpak",
                    var.join("com.brave.Browser")
                        .join("config")
                        .join("BraveSoftware")
                        .join("Brave-Browser"),
                ),
                (
                    "chromium-flatpak",
                    var.join("org.chromium.Chromium").join("config").join("chromium"),
                ),
                (
                    "vivaldi-flatpak",
                    var.join("com.vivaldi.Vivaldi").join("config").join("vivaldi"),
                ),
            ]
            .into_iter()
            .map(|(a, b)| (a.to_string(), b))
            .collect()
        }
        _ => Vec::new(),
    }
}

/// Firefox (profiles_dir, cache_dir) pairs by platform. Empty on a platform
/// with no known Firefox location.
pub fn firefox_roots() -> Vec<(PathBuf, PathBuf)> {
    let home = home_dir();
    if cfg!(windows) {
        let roaming = env_path("APPDATA");
        let local = env_path("LOCALAPPDATA");
        return vec![(
            roaming.join("Mozilla").join("Firefox").join("Profiles"),
            local.join("Mozilla").join("Firefox").join("Profiles"),
        )];
    }
    if cfg!(target_os = "macos") {
        return vec![(
            home.join("Library")
                .join("Application Support")
                .join("Firefox")
                .join("Profiles"),
            home.join("Library").join("Caches").join("Firefox").join("Profiles"),
        )];
    }
    if sys_platform().starts_with("linux") {
        return vec![
            (
                home.join(".mozilla").join("firefox"),
                home.join(".cache").join("mozilla").join("firefox"),
            ),
            // snap packaging
            (
                home.join("snap")
                    .join("firefox")
                    .join("common")
                    .join(".mozilla")
                    .join("firefox"),
                home.join("snap")
                    .join("firefox")
                    .join("common")
                    .join(".cache")
                    .join("mozilla")
                    .join("firefox"),
            ),
            // flatpak packaging
            (
                home.join(".var")
                    .join("app")
                    .join("org.mozilla.firefox")
                    .join(".mozilla")
                    .join("firefox"),
                home.join(".var")
                    .join("app")
                    .join("org.mozilla.firefox")
                    .join(".cache")
                    .join("mozilla")
                    .join("firefox"),
            ),
        ];
    }
    Vec::new()
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn env_path(key: &str) -> PathBuf {
    std::env::var_os(key).map(PathBuf::from).unwrap_or_default()
}

/// A failed snapshot: what went wrong, whether it looked like a browser lock,
/// and whether a temp copy could not be removed (which the report must own).
#[derive(Clone, Debug)]
pub struct SnapError {
    pub message: String,
    pub is_lock: bool,
    pub leftover: Option<PathBuf>,
}

impl SnapError {
    pub fn io(e: &std::io::Error) -> SnapError {
        SnapError {
            message: e.to_string(),
            is_lock: e.kind() == std::io::ErrorKind::PermissionDenied
                || e.raw_os_error() == Some(13),
            leftover: None,
        }
    }
    pub fn plain(message: impl Into<String>) -> SnapError {
        SnapError {
            message: message.into(),
            is_lock: false,
            leftover: None,
        }
    }
    pub fn locked(message: impl Into<String>) -> SnapError {
        SnapError {
            message: message.into(),
            is_lock: true,
            leftover: None,
        }
    }
}

/// A temporary copy of a possibly-locked SQLite database and its write-ahead
/// log / journal siblings. The directory is removed on drop; `discard` also
/// reports whether the removal actually happened, because a copy holds cookie
/// VALUES even though the queries only read metadata.
pub struct Snapshot {
    dir: Option<tempfile::TempDir>,
}

impl Snapshot {
    pub fn db_path(&self) -> PathBuf {
        self.dir
            .as_ref()
            .expect("snapshot present")
            .path()
            .to_path_buf()
    }

    /// Close the open handle, then delete the snapshot — and check it is gone.
    /// Returns false if a copy may remain (the caller records that).
    pub fn discard(mut self, con: Option<Connection>) -> bool {
        drop(con);
        let path = self.dir.take().map(|d| d.keep());
        match path {
            Some(p) => {
                if p.exists() {
                    // One retry: on Windows an antivirus or indexer can hold a
                    // file open for a moment after the handle closes.
                    std::fs::remove_dir_all(&p).ok();
                }
                !p.exists()
            }
            None => true,
        }
    }
}

/// Copy a possibly-locked SQLite db (plus -wal/-shm/-journal) to a temp dir.
///
/// Returns (snapshot, incomplete) where `incomplete` lists the sibling
/// suffixes that existed but could not be copied — a non-empty list means the
/// snapshot is missing data the live database has, and that is the MOST
/// RECENT evidence.
pub fn copy_locked(path: &Path) -> Result<(Snapshot, Vec<String>), SnapError> {
    if let Some(problem) = path_problem(path) {
        return Err(SnapError {
            message: problem,
            is_lock: false,
            leftover: None,
        });
    }
    // Refuse an implausibly large database before copying anything. A profile
    // database the attacker can write could otherwise fill the temp drive —
    // an unbounded write by a tool that promises it only reads.
    let mut total: u64 = 0;
    let mut sized = true;
    match std::fs::metadata(path) {
        Ok(m) => total += m.len(),
        Err(_) => sized = false,
    }
    if sized {
        for suffix in ["-wal", "-shm", "-journal"] {
            let sibling = sibling_path(path, suffix);
            if sibling.exists() {
                match std::fs::metadata(&sibling) {
                    Ok(m) => total += m.len(),
                    Err(_) => {
                        sized = false;
                        break;
                    }
                }
            }
        }
    }
    if sized && total > MAX_SNAPSHOT_BYTES {
        return Err(SnapError::plain(format!(
            "database is {} bytes, over the {}-byte snapshot limit, so it was not copied",
            fmt_count(total),
            fmt_count(MAX_SNAPSHOT_BYTES)
        )));
    }
    let base_name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("database"));
    let tmpdir = match local_temp_dir() {
        Ok(dir) => dir,
        Err(e) => return Err(SnapError::plain(e)),
    };
    let tmpdir = match tempfile::Builder::new()
        .prefix("bscan_")
        .tempdir_in(&tmpdir)
    {
        Ok(d) => d,
        Err(e) => return Err(SnapError::io(&e)),
    };
    let base = tmpdir.path().join(&base_name);
    if let Err(e) = std::fs::copy(path, &base) {
        // The one place that makes the temp dir is also the one place that
        // removes it when it never hands it over. TempDir's drop does this.
        return Err(SnapError::io(&e));
    }
    // A failed sibling copy is NOT cosmetic. A write-ahead log holds rows that
    // are committed but not yet folded into the main file, so losing it
    // silently drops the MOST RECENT evidence. Report which ones failed.
    let mut incomplete = Vec::new();
    for suffix in ["-wal", "-shm", "-journal"] {
        let sibling = sibling_path(path, suffix);
        if let Some(problem) = path_problem(&sibling) {
            incomplete.push(format!("{} ({})", suffix, problem));
            continue;
        }
        if sibling.exists() {
            if let Err(_) = std::fs::copy(&sibling, sibling_path(&base, suffix)) {
                incomplete.push(suffix.to_string());
            }
        }
    }
    Ok((
        Snapshot {
            dir: Some(tmpdir),
        },
        incomplete,
    ))
}

fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Map profile folder -> display name, from the browser's own Local State.
///
/// Only the display name is read. The signed-in email address is in the same
/// structure and is deliberately left alone — the name is enough to identify
/// the account, and a report may be forwarded to other people.
pub fn chromium_profile_names(user_data: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let path = user_data.join("Local State");
    if path_problem(&path).is_some() {
        return out;
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return out,
    };
    let data: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return out, // malformed is malformed: fall back to folder names
    };
    let cache = data
        .get("profile")
        .and_then(|p| p.get("info_cache"))
        .and_then(|c| c.as_object());
    if let Some(cache) = cache {
        for (folder, info) in cache {
            if let Some(name) = info.get("name").and_then(|n| n.as_str()) {
                out.insert(folder.clone(), name.to_string());
            }
        }
    }
    out
}

/// Parse Firefox's profiles.ini. Returns ({folder: display_name}, {folder
/// basenames profiles.ini lists as profiles}). profiles.ini sits INSIDE
/// profiles_dir on Linux but one level ABOVE it on Windows/macOS: try both,
/// the first readable one wins.
pub fn firefox_ini(profiles_dir: &Path) -> (HashMap<String, String>, std::collections::HashSet<String>) {
    let mut names = HashMap::new();
    let mut known = std::collections::HashSet::new();
    let mut flush = |sec: &HashMap<String, String>| {
        if let Some(path) = sec.get("Path") {
            let base = Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !base.is_empty() {
                known.insert(base.clone());
                if let Some(name) = sec.get("Name") {
                    names.insert(base, name.clone());
                }
            }
        }
    };
    let mut ini_paths: Vec<PathBuf> = vec![profiles_dir.join("profiles.ini")];
    if let Some(parent) = profiles_dir.parent() {
        ini_paths.push(parent.join("profiles.ini"));
    }
    for ini in ini_paths {
        if path_problem(&ini).is_some() {
            continue;
        }
        let text = match std::fs::read_to_string(&ini) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let mut section: HashMap<String, String> = HashMap::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.starts_with('[') {
                flush(&section);
                section.clear();
            } else if let Some((key, value)) = line.split_once('=') {
                section.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        flush(&section);
        break;
    }
    (names, known)
}

/// True if `path` looks like a real Firefox profile (holds a marker file).
/// Err carries a refused-path reason.
pub fn is_ff_profile_dir(path: &Path) -> Result<bool, String> {
    for marker in FF_PROFILE_MARKERS {
        let full = path.join(marker);
        if let Some(problem) = path_problem(&full) {
            return Err(problem);
        }
        if full.symlink_metadata().is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A locked database is the most common non-error a user will see, so say
/// what it means and what to do rather than printing a raw errno.
pub fn locked_note(path: &Path, err: &SnapError) -> String {
    let cleanup_warning = match &err.leftover {
        Some(leftover) => format!(
            " WARNING: temporary snapshot cleanup failed; a copy of browser data \
             may remain at {}. Remove this temporary directory when its files can \
             be released.",
            leftover.display()
        ),
        None => String::new(),
    };
    let lowered = path.to_string_lossy().to_lowercase();
    let browser_name = if lowered.contains("bravesoftware") {
        "Brave"
    } else if lowered.contains("vivaldi") {
        "Vivaldi"
    } else if lowered.contains("google") {
        "Chrome"
    } else if lowered.contains("microsoft") {
        "Edge"
    } else if lowered.contains("mozilla") {
        "Firefox"
    } else {
        "the browser"
    };
    let basename = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if err.is_lock || err.message.to_lowercase().contains("locked") {
        format!(
            "{} was running, so one of its databases was locked and could not be \
             checked ({}). Close {} and run again to cover it.{}",
            browser_name, basename, browser_name, cleanup_warning
        )
    } else {
        format!(
            "could not read {}: {}{}",
            path.display(),
            err.message,
            cleanup_warning
        )
    }
}

/// True for the benign "this browser version lacks that table/column" error,
/// as opposed to real corruption or a lock. Only the former is safe to skip.
pub fn is_schema_drift(message: &str) -> bool {
    let msg = message.to_lowercase();
    msg.contains("no such table") || msg.contains("no such column")
}

/// Chromium stores HSTS hostnames as base64(sha256(DNS wire form)).
///
/// The wire form is each label prefixed by its length, terminated by a zero
/// byte: "a.example" -> b"\x01a\x07example\x00". Hashing our indicators the
/// same way lets us match an EXACT hostname without ever learning any other
/// host the person visited — the file is deliberately a one-way set, and this
/// respects that. It also means zero substring false positives.
pub fn hsts_fingerprint(host: &str) -> String {
    let mut wire: Vec<u8> = Vec::new();
    for label in host.trim_matches('.').to_lowercase().split('.') {
        let payload = label.as_bytes();
        wire.push(payload.len() as u8);
        wire.extend_from_slice(payload);
    }
    wire.push(0);
    sha256_b64(&wire)
}

/// Host part of an origin like "https://example.org:443". A lexical parser;
/// it never resolves or opens a URL.
pub fn host_of(origin: &str) -> String {
    let s = origin.trim();
    if s.is_empty() {
        return String::new();
    }
    let rest = if s.contains("://") || s.starts_with("//") {
        s
    } else {
        // Strip a leading scheme-less path form the way urlsplit("//" + s) did.
        s
    };
    let after_scheme = match rest.find("://") {
        Some(i) => &rest[i + 3..],
        None => rest.trim_start_matches('/'),
    };
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(rest) = authority.strip_prefix('[') {
        match rest.split_once(']') {
            Some((h, _)) => h,
            None => authority,
        }
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    host.to_lowercase()
}

/// Exact host match, or a subdomain of an indicator. Not a substring test:
/// these artifacts give us a real hostname, so we can compare properly.
pub fn host_matches(host: &str, ioc_set: &IocSet) -> Option<Indicator> {
    let host = host.to_lowercase();
    let host = host.trim_matches('.').to_string();
    if let Some(ind) = ioc_set.lookup(&host) {
        return Some(ind.clone());
    }
    // MOST specific wins, not first-found: the indicator set holds both
    // parents and children, and returning the parent while most_specific()
    // keeps the child would make a genuine contact disagree with its own
    // "is this the host?" comparison.
    let mut best: Option<Indicator> = None;
    for candidate in &ioc_set.indicators {
        if candidate.kind == TYPE_DOMAIN
            && host.ends_with(&format!(".{}", candidate.value))
            && best
                .as_ref()
                .map(|b| candidate.value.len() > b.value.len())
                .unwrap_or(true)
        {
            best = Some(candidate.clone());
        }
    }
    best
}

/// Every Default / Guest / Profile* directory under a Chromium user-data
/// root. Err when the root exists but cannot be enumerated (a bad ACL).
pub fn chromium_profiles(user_data: &Path) -> Result<Vec<PathBuf>, String> {
    if let Some(problem) = path_problem(user_data) {
        return Err(format!("{}: {}", user_data.display(), problem));
    }
    if !user_data.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(user_data).map_err(|e| e.to_string())? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "Default" || name == "Guest Profile" || name.starts_with("Profile") {
            out.push(entry.path());
        }
    }
    Ok(out)
}

/// A cell of a SQLite row, decoded the way the Python reader saw it
/// (text decoded with errors="replace").
#[derive(Clone, Debug)]
pub enum Cell {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl Cell {
    pub fn text(&self) -> String {
        match self {
            Cell::Null => String::new(),
            Cell::Int(i) => i.to_string(),
            Cell::Real(f) => {
                let s = f.to_string();
                s
            }
            Cell::Text(t) => t.clone(),
            Cell::Blob(b) => String::from_utf8_lossy(b).into_owned(),
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Cell::Int(i) => Some(*i),
            Cell::Real(f) => Some(*f as i64),
            Cell::Text(t) => t.trim().parse::<i64>().ok(),
            _ => None,
        }
    }

    pub fn truthy(&self) -> bool {
        match self {
            Cell::Null => false,
            Cell::Int(0) => false,
            Cell::Text(t) => !t.is_empty(),
            Cell::Blob(b) => !b.is_empty(),
            Cell::Real(f) => *f != 0.0,
            _ => true,
        }
    }
}

/// Python's `a or b` over named columns: the first truthy value, else the
/// last value examined.
fn cell_or<'a>(record: &'a [(String, Cell)], keys: &[&str]) -> Cell {
    let mut last = Cell::Null;
    for key in keys {
        if let Some((_, v)) = record.iter().find(|(k, _)| k == key) {
            if v.truthy() {
                return v.clone();
            }
            last = v.clone();
        }
    }
    last
}

fn get<'a>(record: &'a [(String, Cell)], key: &str) -> Cell {
    record
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
        .unwrap_or(Cell::Null)
}

fn read_row(row: &rusqlite::Row<'_>, ncols: usize) -> rusqlite::Result<Vec<Cell>> {
    let mut cells = Vec::with_capacity(ncols);
    for i in 0..ncols {
        let vr = row.get_ref(i)?;
        cells.push(match vr {
            rusqlite::types::ValueRef::Null => Cell::Null,
            rusqlite::types::ValueRef::Integer(v) => Cell::Int(v),
            rusqlite::types::ValueRef::Real(v) => Cell::Real(v),
            rusqlite::types::ValueRef::Text(b) => {
                Cell::Text(String::from_utf8_lossy(b).into_owned())
            }
            rusqlite::types::ValueRef::Blob(b) => Cell::Blob(b.to_vec()),
        });
    }
    Ok(cells)
}

fn present_columns(con: &Connection, table: &str) -> Result<std::collections::HashSet<String>, String> {
    let sql = format!("PRAGMA table_info({})", table);
    let mut stmt = con.prepare(&sql).map_err(|e| e.to_string())?;
    let ncols = stmt.column_count();
    let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
    let mut out = std::collections::HashSet::new();
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let cells = read_row(row, ncols).map_err(|e| e.to_string())?;
        if let Some(Cell::Text(name)) = cells.get(1) {
            out.insert(name.clone());
        }
    }
    Ok(out)
}

fn select_all(con: &Connection, sql: &str) -> Result<Vec<Vec<Cell>>, String> {
    let mut stmt = con.prepare(sql).map_err(|e| e.to_string())?;
    let ncols = stmt.column_count();
    let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        out.push(read_row(row, ncols).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Render an artifact timestamp, or "" if it is missing or unreadable.
fn fmt_time(flavour: &str, raw: &Cell) -> String {
    let us = match raw {
        Cell::Null => return String::new(),
        Cell::Int(0) => return String::new(),
        Cell::Text(t) if t.is_empty() || t == "0" => return String::new(),
        cell => match cell.as_int() {
            Some(v) if v != 0 => v,
            _ => return String::new(),
        },
    };
    let secs = if flavour == "chromium" {
        datetime::chrome_time_to_unix(us)
    } else {
        datetime::unix_us_to_unix(us)
    };
    // Overflowing or absurd dates render as "" (Python caught OSError/Overflow).
    if !(-62_167_219_200..=253_402_300_799).contains(&secs) {
        return String::new();
    }
    datetime::iso_from_unix(secs)
}

/// The state shared across one browser-module run, standing in for the nested
/// closures of the Python original.
struct BrowserScanner<'a, 'b> {
    ctx: &'a mut ScanContext<'b>,
    r: ModuleResult,
    seen_mtimes: Vec<i64>,
    cookie_times: Vec<i64>,
    cookie_stores: i64,
    history_rows: bool,
    current: String,
    kinds: Vec<((String, String), KindState)>,
    snapshot: Box<dyn FnMut(&Path) -> Result<(Snapshot, Vec<String>), SnapError>>,
}

#[derive(Default, Clone, Debug)]
struct KindState {
    ok: bool,
    reason: String,
    failures: Vec<(String, String)>,
}

impl<'a, 'b> BrowserScanner<'a, 'b> {
    fn touch(&mut self, label: &str, kind: &str) -> &mut KindState {
        let key = (label.to_string(), kind.to_string());
        if !self.kinds.iter().any(|(k, _)| *k == key) {
            self.kinds.push((key.clone(), KindState::default()));
        }
        &mut self
            .kinds
            .iter_mut()
            .find(|(k, _)| *k == key)
            .unwrap()
            .1
    }

    fn mark_ok(&mut self, label: &str, kind: &str) {
        self.touch(label, kind).ok = true;
    }

    fn mark_fail(&mut self, label: &str, kind: &str, reason: &str) {
        // Every failure is kept, with the profile it happened in. Keeping only
        // a single flag let one readable profile mask another profile's locked
        // database, and the scan came out CLEAN with no gap at all.
        let profile = self.current.clone();
        let entry = self.touch(label, kind);
        if entry.reason.is_empty() {
            entry.reason = reason.to_string();
        }
        entry.failures.push((profile, reason.to_string()));
    }

    fn count_db(&mut self) {
        self.r.bump_metric("sqlite", 1);
        self.r.checked += 1;
    }

    fn record_hit(&mut self, path: &Path, ind: &Indicator, detail: &str, evidence: &str, observed: &str) {
        self.r.add_hit(Hit {
            indicator: ind.value.clone(),
            location: path.to_string_lossy().into_owned(),
            detail: detail.to_string(),
            tier: ind.tier.clone(),
            confidence: ind.confidence.clone(),
            source: ind.source.clone(),
            evidence: evidence.to_string(),
            observed: observed.to_string(),
            profile: self.current.clone(),
        });
    }

    /// Snapshot and open a possibly-locked SQLite db read-only.
    ///
    /// Returns None when the artifact is absent (not a gap) or unreadable
    /// (recorded as a failure for this (label, kind), promoted to a gap only
    /// if no profile ever reads it).
    #[allow(clippy::type_complexity)]
    fn open_db(
        &mut self,
        path: &Path,
        label: &str,
        kind: &str,
    ) -> Option<(Connection, Snapshot)> {
        if let Some(problem) = path_problem(path) {
            self.r.skipped += 1;
            let note = format!("{}: {}", path.display(), problem);
            self.mark_fail(label, kind, &note);
            return None;
        }
        if let Err(e) = std::fs::metadata(path) {
            if e.kind() == std::io::ErrorKind::NotFound {
                return None; // artifact simply absent for this profile
            }
            self.r.skipped += 1;
            let err = SnapError::io(&e);
            let note = locked_note(path, &err);
            self.r.note(&note);
            self.mark_fail(label, kind, &note);
            return None;
        }
        let (snapshot, incomplete) = match (self.snapshot)(path) {
            Ok(v) => v,
            Err(e) => {
                // A locked db we could not even snapshot is a gap, not a clean item.
                self.r.skipped += 1;
                let note = locked_note(path, &e);
                self.r.note(&note);
                self.mark_fail(label, kind, &note);
                return None;
            }
        };
        let tmp = snapshot.db_path();
        let con = match Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY) {
            Ok(con) => con,
            Err(e) => {
                let leftover = snapshot.dir.as_ref().map(|d| d.path().to_path_buf());
                let kept = snapshot.discard(None);
                let mut err = SnapError {
                    message: e.to_string(),
                    is_lock: e.to_string().to_lowercase().contains("locked"),
                    leftover: if kept { None } else { leftover },
                };
                let _ = &mut err;
                self.r.skipped += 1;
                let note = locked_note(path, &err);
                self.r.note(&note);
                self.mark_fail(label, kind, &note);
                return None;
            }
        };
        if !incomplete.is_empty() {
            // The main file opened, but a write-ahead log or journal that the
            // live database HAS could not be copied. Whatever was committed
            // there is missing from this snapshot — and that is the newest
            // evidence, not the oldest. Reading the short file and calling it
            // clean would be a false negative, so this is a gap.
            let note = format!(
                "{}: snapshot is incomplete - could not copy {} alongside it, so \
                 recently written rows may be missing from this read",
                path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(),
                incomplete.join(", ")
            );
            self.r.note(&note);
            self.mark_fail(label, kind, &note);
        }
        Some((con, snapshot))
    }

    /// History / moz_places, host-graded.
    ///
    /// A history row whose URL HOST is the indicator means the browser actually
    /// went there, so it grades as contacted and carries the row's own visit
    /// date as the observed time. A match only in the query string or page
    /// title is a reference — often a search for the name — so it stays
    /// referenced. Chromium's download records live in the same db and stay
    /// referenced (a saved path/URL, not proof of contact).
    fn scan_history(&mut self, label: &str, path: &Path, flavour: &str) {
        let kind = "history";
        let (con, snapshot) = match self.open_db(path, label, kind) {
            Some(v) => v,
            None => return,
        };
        let mut read_ok = false;
        let mut failed = false;
        let (table, visit_col) = if flavour == "chromium" {
            ("urls", "last_visit_time")
        } else {
            ("moz_places", "last_visit_date")
        };
        let present = match present_columns(&con, table) {
            Ok(p) => p,
            Err(e) => {
                if !is_schema_drift(&e) {
                    let err = SnapError {
                        message: e,
                        is_lock: false,
                        leftover: None,
                    };
                    let note = locked_note(path, &err);
                    self.mark_fail(label, kind, &note);
                    failed = true;
                }
                std::collections::HashSet::new()
            }
        };
        if !failed && !present.contains("url") {
            self.mark_fail(
                label,
                kind,
                "the history store has no supported URL column, so navigation \
                 history could not be searched",
            );
            failed = true;
        }
        if !failed && present.contains("url") {
            let mut cols = vec!["url".to_string()];
            if present.contains("title") {
                cols.push("title".to_string());
            }
            if present.contains(visit_col) {
                cols.push(visit_col.to_string());
            }
            if flavour == "firefox" && present.contains("visit_count") {
                cols.push("visit_count".to_string());
            }
            let sql = format!("SELECT {} FROM {}", cols.join(", "), table);
            match select_all(&con, &sql) {
                Err(e) => {
                    if !is_schema_drift(&e) {
                        let err = SnapError {
                            message: e,
                            is_lock: false,
                            leftover: None,
                        };
                        let note = locked_note(path, &err);
                        self.mark_fail(label, kind, &note);
                        failed = true;
                    }
                }
                Ok(rows) => {
                    read_ok = true;
                    if !rows.is_empty() {
                        self.history_rows = true;
                    }
                    for row in rows {
                        let record: Vec<(String, Cell)> = cols
                            .iter()
                            .cloned()
                            .zip(row.into_iter())
                            .collect();
                        let url = get(&record, "url").text();
                        let title = get(&record, "title").text();
                        let blob = format!("{} {}", url, title).to_lowercase();
                        let observed = fmt_time(
                            flavour,
                            &get(&record, visit_col),
                        );
                        // Firefox's places database also stores never-visited
                        // bookmarks. A URL row alone does not establish a visit.
                        let mut has_visit = flavour != "firefox";
                        if flavour == "firefox" {
                            for key in [visit_col, "visit_count"] {
                                if let Some(v) = get(&record, key).as_int() {
                                    has_visit = has_visit || v > 0;
                                }
                            }
                        }
                        let host_ind = host_matches(&host_of(&url), self.ctx.iocs);
                        let matched = self.ctx.iocs.most_specific(self.ctx.iocs.search(&blob));
                        for ind in matched {
                            if has_visit
                                && host_ind
                                    .as_ref()
                                    .map(|h| h.value == ind.value)
                                    .unwrap_or(false)
                            {
                                self.record_hit(
                                    path,
                                    &ind,
                                    &format!("history: {}", truncate_chars(&blob, 160)),
                                    EV_CONTACTED,
                                    &observed,
                                );
                            } else {
                                self.record_hit(
                                    path,
                                    &ind,
                                    &format!("history: {}", truncate_chars(&blob, 160)),
                                    EV_REFERENCED,
                                    &observed,
                                );
                            }
                        }
                    }
                }
            }
        }

        if flavour == "chromium" && !failed {
            match select_all(&con, "SELECT current_path, tab_url, referrer FROM downloads") {
                Err(e) => {
                    if !is_schema_drift(&e) {
                        let err = SnapError {
                            message: e,
                            is_lock: false,
                            leftover: None,
                        };
                        let note = locked_note(path, &err);
                        self.mark_fail(label, kind, &note);
                    }
                }
                Ok(rows) => {
                    read_ok = true;
                    for row in rows {
                        let blob: String = row
                            .iter()
                            .filter(|c| !matches!(c, Cell::Null))
                            .map(|c| c.text())
                            .collect::<Vec<_>>()
                            .join(" ")
                            .to_lowercase();
                        let matched =
                            self.ctx.iocs.most_specific(self.ctx.iocs.search(&blob));
                        for ind in matched {
                            self.record_hit(
                                path,
                                &ind,
                                &format!("download: {}", truncate_chars(&blob, 160)),
                                EV_REFERENCED,
                                "",
                            );
                        }
                    }
                }
            }
        }

        if !failed {
            // Opened and queried without corruption: this artifact was read.
            self.mark_ok(label, kind);
            if read_ok {
                self.count_db();
            }
        }
        // Close the handle BEFORE removing, or Windows keeps the copy.
        if !snapshot.discard(Some(con)) {
            self.r.note(&format!(
                "could not remove the temporary snapshot of {} - a copy may \
                 remain in the system temp directory",
                path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
            ));
        }
    }

    /// Favicons. For Chromium, a favicon URL whose stored bitmap is present
    /// and non-empty means the browser actually fetched the icon from that
    /// host (contacted); a row with no image is only a reference. For Firefox
    /// the presence of a moz_icons entry already means the icon was fetched,
    /// so it grades as contacted.
    fn scan_favicons(&mut self, label: &str, path: &Path, flavour: &str) {
        let kind = "favicons";
        let (con, snapshot) = match self.open_db(path, label, kind) {
            Some(v) => v,
            None => return,
        };
        let sql = if flavour == "chromium" {
            (
                "SELECT favicons.url, \
                 CASE WHEN favicon_bitmaps.image_data IS NOT NULL \
                 AND length(favicon_bitmaps.image_data) > 0 \
                 THEN 1 ELSE 0 END \
                 FROM favicons \
                 LEFT JOIN favicon_bitmaps \
                 ON favicons.id = favicon_bitmaps.icon_id",
                true,
            )
        } else {
            ("SELECT icon_url FROM moz_icons", false)
        };
        match select_all(&con, sql.0) {
            Err(e) => {
                let err = SnapError {
                    message: e,
                    is_lock: false,
                    leftover: None,
                };
                let note = locked_note(path, &err);
                self.mark_fail(label, kind, &note);
            }
            Ok(rows) => {
                self.mark_ok(label, kind);
                self.count_db();
                for row in rows {
                    let (url, ev) = if sql.1 {
                        let url = row.first().map(|c| c.text()).unwrap_or_default();
                        let has_bitmap = row.get(1).map(|c| c.truthy()).unwrap_or(false);
                        let ev = if has_bitmap { EV_CONTACTED } else { EV_REFERENCED };
                        (url, ev)
                    } else {
                        let url = row.first().map(|c| c.text()).unwrap_or_default();
                        (url, EV_CONTACTED)
                    };
                    let blob = url.to_lowercase();
                    // Anchor to the HOST, the same way history does. A stored
                    // bitmap proves the browser fetched that icon - from the
                    // icon URL's own host. An indicator sitting in the query
                    // string of an otherwise innocent favicon URL proves
                    // contact with the innocent host, not with the indicator.
                    let host_ind = host_matches(&host_of(&blob), self.ctx.iocs);
                    let matched = self.ctx.iocs.most_specific(self.ctx.iocs.search(&blob));
                    for ind in matched {
                        let anchored = host_ind
                            .as_ref()
                            .map(|h| h.value == ind.value)
                            .unwrap_or(false);
                        let evidence = if anchored { ev } else { EV_REFERENCED };
                        self.record_hit(
                            path,
                            &ind,
                            &format!("favicon: {}", truncate_chars(&blob, 160)),
                            evidence,
                            "",
                        );
                    }
                }
            }
        }
        if !snapshot.discard(Some(con)) {
            self.r.note(&format!(
                "could not remove the temporary snapshot of {} - a copy may \
                 remain in the system temp directory",
                path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
            ));
        }
    }

    /// Cookies get their own reader because they are the richest artifact
    /// here, and the generic row-to-string match throws away the two things a
    /// person actually needs: WHEN the cookie was set, and WHICH page they
    /// were on when it happened.
    ///
    /// Chromium partitions third-party cookies by top-level site, so
    /// `top_frame_site_key` names the site that was being visited when an ad
    /// tracker set its cookie — for an ad-delivered indicator that is the
    /// single most useful field in the whole scan.
    ///
    /// The store is not counted as checked until rows are in hand: every early
    /// exit (unreadable schema, no usable columns, a failed SELECT) is a gap.
    ///
    /// Only host names and timestamps are ever selected; cookie values are not
    /// read, and no decryption path exists in this tool.
    fn scan_cookies(&mut self, label: &str, path: &Path, flavour: &str) {
        let kind = "cookies";
        let (con, snapshot) = match self.open_db(path, label, kind) {
            Some(v) => v,
            None => return,
        };
        let table = if flavour == "chromium" { "cookies" } else { "moz_cookies" };
        let present = match present_columns(&con, table) {
            Ok(p) => p,
            Err(e) => {
                self.r.skipped += 1;
                let err = SnapError {
                    message: e,
                    is_lock: false,
                    leftover: None,
                };
                let note = locked_note(path, &err);
                self.mark_fail(label, kind, &note);
                snapshot.discard(Some(con));
                return;
            }
        };
        let candidates: Vec<&str> = if flavour == "chromium" {
            vec![
                "host_key",
                "name",
                "creation_utc",
                "last_access_utc",
                "top_frame_site_key",
            ]
        } else {
            vec!["host", "name", "creationTime", "lastAccessed"]
        };
        let host_column = if flavour == "chromium" { "host_key" } else { "host" };
        let wanted: Vec<String> = candidates
            .iter()
            .filter(|c| present.contains(**c))
            .map(|c| c.to_string())
            .collect();
        if !wanted.iter().any(|c| c == host_column) {
            self.r.skipped += 1;
            self.mark_fail(
                label,
                kind,
                &format!(
                    "the cookie store {} had no supported host column, so its \
                     cookie origins could not be searched",
                    path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
                ),
            );
            snapshot.discard(Some(con));
            return;
        }
        let sql = format!("SELECT {} FROM {}", wanted.join(", "), table);
        let rows = match select_all(&con, &sql) {
            Ok(rows) => rows,
            Err(e) => {
                self.r.skipped += 1;
                let err = SnapError {
                    message: e,
                    is_lock: false,
                    leftover: None,
                };
                let note = locked_note(path, &err);
                self.mark_fail(label, kind, &note);
                snapshot.discard(Some(con));
                return;
            }
        };

        // Rows are in hand: now the store genuinely counts as read.
        self.mark_ok(label, kind);
        self.count_db();
        self.cookie_stores += 1;

        for row in rows {
            let record: Vec<(String, Cell)> =
                wanted.iter().cloned().zip(row.into_iter()).collect();
            let host = cell_or(&record, &["host_key", "host"]).text();
            let host_lower = host.to_lowercase();
            let matched = self
                .ctx
                .iocs
                .most_specific(self.ctx.iocs.search(&host_lower));
            for ind in matched {
                let created = fmt_time(flavour, &cell_or(&record, &["creation_utc", "creationTime"]));
                let seen = fmt_time(flavour, &cell_or(&record, &["last_access_utc", "lastAccessed"]));
                let partition = get(&record, "top_frame_site_key").text().trim().to_string();
                let mut bits = vec![
                    format!("cookie set by {}", host),
                    format!("name {}", {
                        let n = get(&record, "name");
                        if n.truthy() { n.text() } else { "?".to_string() }
                    }),
                ];
                if !partition.is_empty() {
                    bits.push(format!("set while visiting {}", partition));
                }
                if !created.is_empty() {
                    bits.push(format!("first set {}", created));
                }
                if !seen.is_empty() && seen != created {
                    bits.push(format!("last used {}", seen));
                } else if !seen.is_empty() {
                    bits.push("never used again after that".to_string());
                }
                let observed = if !created.is_empty() {
                    created.clone()
                } else {
                    seen.clone()
                };
                self.record_hit(path, &ind, &bits.join("; "), EV_CONTACTED, &observed);
                if !created.is_empty() {
                    if let Some(us) = cell_or(&record, &["creation_utc", "creationTime"]).as_int() {
                        self.cookie_times.push(if flavour == "chromium" {
                            datetime::chrome_time_to_unix(us)
                        } else {
                            datetime::unix_us_to_unix(us)
                        });
                    }
                }
            }
        }
        // Oldest cookie overall, for the time-coverage section.
        let col = if flavour == "chromium" { "creation_utc" } else { "creationTime" };
        if present.contains(col) {
            let sql = format!("SELECT MIN({0}) FROM {1} WHERE {0} > 0", col, table);
            if let Ok(rows) = select_all(&con, &sql) {
                if let Some(row) = rows.into_iter().next() {
                    if let Some(us) = row.first().and_then(|c| c.as_int()) {
                        if us > 0 {
                            self.cookie_times.push(if flavour == "chromium" {
                                datetime::chrome_time_to_unix(us)
                            } else {
                                datetime::unix_us_to_unix(us)
                            });
                        }
                    }
                }
            }
        }
        if !snapshot.discard(Some(con)) {
            self.r.note(&format!(
                "could not remove the temporary snapshot of {} - a copy may \
                 remain in the system temp directory",
                path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
            ));
        }
    }

    /// Substring-search binary files (HTTP cache, LevelDB) for the needles.
    ///
    /// Raw bytes do not distinguish origin keys from saved page content. Every
    /// match here is referenced, even when it looks like a complete origin
    /// URL: Local Storage entries are keyed by origin, but these stores also
    /// hold page CONTENT, and an indicator inside a stored value proves
    /// someone read about this campaign, not that the device talked to it.
    ///
    /// A directory that exists and can be walked is a successful check of the
    /// "blobs" kind, even if it holds no files. A subtree that could not be
    /// walked at all, or a file too large to search, is a gap.
    fn scan_blobs(&mut self, label: &str, root: &Path, evidence: &str) {
        // The evidence argument exists for call-site parity with the Python
        // signature; the raw-byte search grades everything it finds as a
        // reference (see the comment above).
        let _ = evidence;
        let kind = "blobs";
        if let Some(problem) = path_problem(root) {
            self.r.skipped += 1;
            let note = format!("{}: {}", root.display(), problem);
            self.mark_fail(label, kind, &note);
            return;
        }
        if let Err(e) = std::fs::metadata(root) {
            if e.kind() == std::io::ErrorKind::NotFound {
                return; // artifact absent for this profile — not a gap
            }
            self.r.skipped += 1;
            let err = SnapError::io(&e);
            let note = locked_note(root, &err);
            self.r.note(&note);
            self.mark_fail(label, kind, &note);
            return;
        }

        // One handler owns both the walk errors and the files it reads, so
        // the result and the IOC set can be borrowed disjointly.
        struct BlobWalk<'s, 'a, 'b> {
            scanner: &'s mut BrowserScanner<'a, 'b>,
            failures: Vec<String>,
            mtimes: Vec<i64>,
            collected: Vec<(PathBuf, Indicator)>,
        }
        impl WalkHandler for BlobWalk<'_, '_, '_> {
            fn onerror(&mut self, p: WalkProblem) {
                self.failures.push(p.reason.clone());
                self.scanner.r.skipped += 1;
                self.scanner.r.note(&p.reason);
            }
            fn files(&mut self, _dir: &Path, files: &[PathBuf]) {
                for full in files {
                    match std::fs::metadata(full) {
                        Err(e) => {
                            let note = format!("could not read {}: {}", full.display(), e);
                            self.failures.push(note.clone());
                            self.scanner.r.skipped += 1;
                            self.scanner.r.note(&note);
                            continue;
                        }
                        Ok(st) => {
                            if st.len() > BLOB_MAX_BYTES {
                                // too large to search — a gap, not clean
                                self.scanner.r.skipped += 1;
                                let note = format!(
                                    "{} is larger than 400 MB and was not searched",
                                    full.display()
                                );
                                self.scanner.r.note(&note);
                                self.failures.push(format!(
                                    "{} exceeds the 400 MB search limit",
                                    full.display()
                                ));
                                continue;
                            }
                            match std::fs::read(full) {
                                Ok(data) => {
                                    // Oldest cache artifact = how far back this
                                    // check can possibly see. A measured window,
                                    // not a guess.
                                    let mtime = st
                                        .modified()
                                        .ok()
                                        .and_then(|t| {
                                            t.duration_since(std::time::UNIX_EPOCH).ok()
                                        })
                                        .map(|d| d.as_secs() as i64)
                                        .unwrap_or(0);
                                    self.mtimes.push(mtime);
                                    self.scanner.r.bump_metric("blob", 1);
                                    self.scanner.r.checked += 1;
                                    let lowered = data.to_ascii_lowercase();
                                    for ind in self.scanner.ctx.iocs.search_bytes(&lowered) {
                                        self.collected.push((full.clone(), ind));
                                    }
                                }
                                Err(e) => {
                                    // unreadable file — a gap, not clean
                                    self.scanner.r.skipped += 1;
                                    let note =
                                        format!("could not read {}: {}", full.display(), e);
                                    self.scanner.r.note(&note);
                                    self.failures.push(note);
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut walk = BlobWalk {
            scanner: self,
            failures: Vec::new(),
            mtimes: Vec::new(),
            collected: Vec::new(),
        };
        walk_local(root, &|_name| false, &mut walk);
        let read_any = !walk.mtimes.is_empty();
        let failures = std::mem::take(&mut walk.failures);
        let collected = std::mem::take(&mut walk.collected);
        let scanner = &mut *walk.scanner;
        scanner.seen_mtimes.extend(walk.mtimes);
        for (full, ind) in collected {
            scanner.record_hit(
                &full,
                &ind,
                "binary match in cache/leveldb; raw bytes do not establish whether \
                 this is an origin or saved content",
                EV_REFERENCED,
                "",
            );
        }

        if read_any || failures.is_empty() {
            scanner.mark_ok(label, kind);
        }
        if !failures.is_empty() {
            let head: Vec<String> = failures.iter().take(3).cloned().collect();
            let note = format!(
                "{} item(s) under {} were not searched: {}",
                failures.len(),
                root.display(),
                head.join("; ")
            );
            scanner.mark_fail(label, kind, &note);
        }
    }

    /// The two long-lived records of hosts the browser actually CONNECTED to.
    ///
    /// Why these matter more than the cache: the HTTP cache is recycled within
    /// weeks and a byte match in it may only be page content mentioning a
    /// name. These two files instead record that a connection happened, they
    /// survive far longer, and HSTS even carries the date it was observed.
    fn scan_connection_records(&mut self, label: &str, prof: &Path) {
        let net_dir = prof.join("Network");

        // --- TransportSecurity (HSTS) -------------------------------------
        let ts_path = net_dir.join("TransportSecurity");
        let mut ts_present = true;
        if let Some(problem) = path_problem(&ts_path) {
            self.r.skipped += 1;
            let err = SnapError {
                message: problem,
                is_lock: false,
                leftover: None,
            };
            let note = locked_note(&ts_path, &err);
            self.mark_fail(label, "hsts", &note);
            ts_present = false;
        } else if let Err(e) = std::fs::metadata(&ts_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                self.r.skipped += 1;
                let err = SnapError::io(&e);
                let note = locked_note(&ts_path, &err);
                self.mark_fail(label, "hsts", &note);
            }
            ts_present = false;
        }
        if ts_present {
            match self.read_hsts(&ts_path) {
                Ok(entries) => {
                    self.r.bump_metric("hsts_entries", entries.len() as i64);
                    self.r.checked += entries.len() as i64;
                    self.mark_ok(label, "hsts");
                    if !entries.is_empty() {
                        let mut held: HashMap<String, Value> = HashMap::new();
                        let mut malformed: Option<String> = None;
                        for e in &entries {
                            match e.get("host").and_then(|h| h.as_str()) {
                                Some(host) => {
                                    held.insert(host.to_string(), e.clone());
                                }
                                None => {
                                    malformed =
                                        Some("HSTS entry must contain a host string".to_string());
                                    break;
                                }
                            }
                        }
                        if let Some(msg) = malformed {
                            self.r.skipped += 1;
                            let err = SnapError {
                                message: msg,
                                is_lock: false,
                                leftover: None,
                            };
                            let note = locked_note(&ts_path, &err);
                            self.mark_fail(label, "hsts", &note);
                        } else {
                            let indicators: Vec<Indicator> = self
                                .ctx
                                .iocs
                                .indicators
                                .iter()
                                .filter(|i| i.kind == TYPE_DOMAIN)
                                .cloned()
                                .collect();
                            for ind in indicators {
                                let fingerprint = hsts_fingerprint(&ind.value);
                                let e = match held.get(&fingerprint) {
                                    Some(e) => e,
                                    None => continue,
                                };
                                let mut when = String::new();
                                if let Some(observed) = e.get("sts_observed").and_then(|v| {
                                    v.as_f64().or_else(|| {
                                        v.as_str().and_then(|s| s.trim().parse::<f64>().ok())
                                    })
                                }) {
                                    if observed.is_finite() {
                                        when = datetime::iso_from_unix(observed as i64);
                                    }
                                }
                                let mut detail = String::from(
                                    "HSTS state recorded for this exact host - the browser \
                                     received an HSTS header from it over HTTPS",
                                );
                                if !when.is_empty() {
                                    detail.push_str(&format!(" (observed {})", &when[..10.min(when.len())]));
                                }
                                self.record_hit(&ts_path, &ind, &detail, EV_CONTACTED, &when);
                            }
                        }
                    }
                }
                Err(msg) => {
                    self.r.skipped += 1;
                    let err = SnapError {
                        message: msg,
                        is_lock: false,
                        leftover: None,
                    };
                    let note = locked_note(&ts_path, &err);
                    self.mark_fail(label, "hsts", &note);
                }
            }
        }

        // --- Network Persistent State ------------------------------------
        let nps_path = net_dir.join("Network Persistent State");
        let mut nps_present = true;
        if let Some(problem) = path_problem(&nps_path) {
            self.r.skipped += 1;
            let err = SnapError {
                message: problem,
                is_lock: false,
                leftover: None,
            };
            let note = locked_note(&nps_path, &err);
            self.mark_fail(label, "connection-records", &note);
            nps_present = false;
        } else if let Err(e) = std::fs::metadata(&nps_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                self.r.skipped += 1;
                let err = SnapError::io(&e);
                let note = locked_note(&nps_path, &err);
                self.mark_fail(label, "connection-records", &note);
            }
            nps_present = false;
        }
        if nps_present {
            match self.read_nps(&nps_path) {
                Ok(origins) => {
                    self.r.bump_metric("connection_records", origins.len() as i64);
                    self.r.checked += origins.len() as i64;
                    self.mark_ok(label, "connection-records");
                    for (host, what) in origins {
                        if let Some(ind) = host_matches(&host, self.ctx.iocs) {
                            self.record_hit(
                                &nps_path,
                                &ind,
                                &format!(
                                    "{}: the browser has a connection record for {}",
                                    what, host
                                ),
                                EV_CONTACTED,
                                "",
                            );
                        }
                    }
                }
                Err(msg) => {
                    self.r.skipped += 1;
                    let err = SnapError {
                        message: msg,
                        is_lock: false,
                        leftover: None,
                    };
                    let note = locked_note(&nps_path, &err);
                    self.mark_fail(label, "connection-records", &note);
                }
            }
        }
    }

    fn read_json_file(&self, path: &Path) -> Result<Value, String> {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let data: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        if !data.is_object() {
            return Err("HSTS state must be an object".to_string());
        }
        Ok(data)
    }

    fn read_hsts(&self, path: &Path) -> Result<Vec<Value>, String> {
        let data = self.read_json_file(path).map_err(|e| {
            if e.contains("HSTS state must be an object") {
                e
            } else if e.contains("expected value") || e.contains("EOF") || e.contains("key must be a string") {
                format!("HSTS state must be an object: {}", e)
            } else {
                e
            }
        })?;
        let entries = data.get("sts").cloned().unwrap_or(Value::Null);
        match entries {
            Value::Array(list) => Ok(list),
            Value::Null => Ok(Vec::new()),
            other => Err(format!(
                "unexpected shape: 'sts' is {}, expected a list",
                json_type_name(&other)
            )),
        }
    }

    fn read_nps(&self, path: &Path) -> Result<Vec<(String, String)>, String> {
        let data = self.read_json_file(path)?;
        let net = data.get("net").cloned().unwrap_or(Value::Null);
        if !net.is_object() {
            return Err("network state 'net' must be an object".to_string());
        }
        let hsp = net.get("http_server_properties").cloned().unwrap_or(Value::Null);
        if !hsp.is_object() {
            return Err("http_server_properties must be an object".to_string());
        }
        for (field, host_field) in [("servers", "server"), ("broken_alternative_services", "host")] {
            let entries = hsp.get(field).cloned().unwrap_or(Value::Null);
            match entries {
                Value::Array(list) => {
                    for row in &list {
                        let ok = row.get(host_field).map(|h| h.is_string()).unwrap_or(false);
                        if !ok {
                            return Err(format!("{} contains an invalid host record", field));
                        }
                    }
                }
                Value::Null => {}
                other => {
                    return Err(format!(
                        "{} must be a list (got {})",
                        field,
                        json_type_name(&other)
                    ))
                }
            }
        }
        let mut origins = Vec::new();
        if let Some(Value::Array(servers)) = hsp.get("servers") {
            for row in servers {
                if let Some(server) = row.get("server").and_then(|s| s.as_str()) {
                    if !server.is_empty() {
                        origins.push((host_of(server), "connected server".to_string()));
                    }
                }
            }
        }
        if let Some(Value::Array(broken)) = hsp.get("broken_alternative_services") {
            for row in broken {
                if let Some(host) = row.get("host").and_then(|s| s.as_str()) {
                    if !host.is_empty() {
                        origins.push((host_of(host), "broken alternative service".to_string()));
                    }
                }
            }
        }
        Ok(origins)
    }

    /// Firefox's HSTS store, SiteSecurityServiceState.txt.
    ///
    /// Like Chromium's TransportSecurity, every hostname here is one the
    /// browser connected to over HTTPS and received an HSTS header from, so a
    /// match is proof of contact. Unlike Chromium's, Firefox keeps the
    /// hostnames in PLAINTEXT; only our indicators are searched for, so no
    /// other host from the file ever reaches the output.
    fn scan_firefox_hsts(&mut self, label: &str, path: &Path) {
        if let Some(problem) = path_problem(path) {
            self.r.skipped += 1;
            let err = SnapError {
                message: problem,
                is_lock: false,
                leftover: None,
            };
            let note = locked_note(path, &err);
            self.mark_fail(label, "hsts", &note);
            return;
        }
        if std::fs::metadata(path).is_err() {
            return;
        }
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                self.r.skipped += 1;
                let err = SnapError::io(&e);
                let note = locked_note(path, &err);
                self.mark_fail(label, "hsts", &note);
                return;
            }
        };
        let entries = text.matches(":HSTS").count() as i64;
        self.r.bump_metric("hsts_entries", entries);
        self.r.checked += entries;
        self.mark_ok(label, "hsts");
        let lower = text.to_lowercase();
        for ind in self.ctx.iocs.search(&lower) {
            self.record_hit(
                path,
                &ind,
                "Firefox HSTS state recorded for this host - the browser received \
                 an HSTS header from it over HTTPS",
                EV_CONTACTED,
                "",
            );
        }
    }
}

fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "None",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

fn collected_blob_count(mtimes: &[i64]) -> i64 {
    mtimes.len() as i64
}

/// Browser artifact locations, overridable for hermetic tests the way the
/// Python suite monkeypatched CHROMIUM_ROOTS / FIREFOX_ROOTS.
#[derive(Clone, Debug, Default)]
pub struct BrowserConfig {
    pub chromium: Vec<(String, PathBuf)>,
    /// None means "derive from the platform at run() time".
    pub firefox: Option<Vec<(PathBuf, PathBuf)>>,
}

impl BrowserConfig {
    pub fn detect() -> BrowserConfig {
        BrowserConfig {
            chromium: chromium_roots(),
            firefox: None,
        }
    }
}

/// The module entry point: scan the real, platform-detected browser roots.
pub fn run(ctx: &mut ScanContext) -> ModuleResult {
    let cfg = BrowserConfig::detect();
    run_with(ctx, &cfg)
}

/// Scan an explicit set of browser roots (tests, or a future --browser flag).
pub fn run_with(ctx: &mut ScanContext, cfg: &BrowserConfig) -> ModuleResult {
    let mut scanner = BrowserScanner {
        ctx,
        r: ModuleResult::new(NAME),
        seen_mtimes: Vec::new(),
        cookie_times: Vec::new(),
        cookie_stores: 0,
        history_rows: false,
        current: String::new(),
        kinds: Vec::new(),
        snapshot: Box::new(copy_locked),
    };
    scanner.ctx.publish_partial(&scanner.r);
    scanner.r.set_metric("sqlite", 0);
    scanner.r.set_metric("blob", 0);

    let ff_roots: Vec<(PathBuf, PathBuf)> = match &cfg.firefox {
        Some(roots) => roots.clone(),
        None => firefox_roots(),
    };

    // No browser profile location is known for this platform at all: say so
    // as a gap rather than returning an empty, falsely-clean result.
    if cfg.chromium.is_empty() && ff_roots.is_empty() {
        scanner.r.could_not_run(
            "browser",
            &format!(
                "no browser profile locations are known for {}",
                sys_platform()
            ),
        );
        return finish(scanner);
    }

    // --- Chromium family -------------------------------------------------
    for (label, root) in &cfg.chromium {
        if let Some(problem) = path_problem(root) {
            scanner
                .r
                .could_not_run(&format!("{}:profiles", label), &format!("{}: {}", root.display(), problem));
            continue;
        }
        if !root.is_dir() {
            continue; // browser not installed — absent, so no sub-check for it
        }
        let profs = match chromium_profiles(root) {
            Ok(p) => p,
            Err(e) => {
                // One bad ACL on the user-data root must not abort the module.
                let err = SnapError::plain(e);
                let note = locked_note(root, &err);
                scanner.r.could_not_run(&format!("{}:profiles", label), &note);
                continue;
            }
        };
        let names = chromium_profile_names(root);
        scanner.ctx.emit(&format!(
            "[*] {} ({} profile(s))",
            root.display(),
            profs.len()
        ));
        for prof in profs {
            if let Some(problem) = path_problem(&prof) {
                scanner.r.could_not_run(
                    &format!(
                        "{}:profile:{}",
                        label,
                        prof.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
                    ),
                    &problem,
                );
                continue;
            }
            if !prof.is_dir() {
                continue;
            }
            let folder = prof
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let display = names.get(&folder).cloned().unwrap_or_default();
            // Name the account in the hit, falling back to the folder when the
            // browser has no display name recorded for it.
            scanner.current = if display.is_empty() {
                folder.clone()
            } else {
                format!("{} ({})", display, folder)
            };
            scanner
                .ctx
                .emit(&format!("[*]   profile: {}", scanner.current));
            let prof_path = prof.clone();
            scanner.scan_history(label, &prof_path.join("History"), "chromium");
            scanner.scan_cookies(label, &prof_path.join("Network").join("Cookies"), "chromium");
            scanner.scan_cookies(label, &prof_path.join("Cookies"), "chromium");
            scanner.scan_favicons(label, &prof_path.join("Favicons"), "chromium");
            scanner.scan_connection_records(label, &prof_path);
            for sub in [
                (vec!["Cache", "Cache_Data"], EV_REFERENCED),
                (vec!["Code Cache", "js"], EV_REFERENCED),
                (vec!["Local Storage", "leveldb"], EV_CONTACTED),
                (vec!["Session Storage"], EV_CONTACTED),
                (vec!["Service Worker", "CacheStorage"], EV_CONTACTED),
            ] {
                let mut p = prof_path.clone();
                for part in &sub.0 {
                    p.push(part);
                }
                scanner.scan_blobs(label, &p, sub.1);
            }
        }
    }

    // --- Firefox ---------------------------------------------------------
    // A stray cross-profile hit must never be stamped with the last Chrome
    // profile, so reset attribution before the Firefox walk.
    scanner.current = String::new();
    for (profiles_dir, cache_dir) in &ff_roots {
        let refused = vec![
            (profiles_dir.clone(), path_problem(profiles_dir)),
            (cache_dir.clone(), path_problem(cache_dir)),
        ];
        if refused.iter().any(|(_, r)| r.is_some()) {
            for (p, reason) in &refused {
                if let Some(reason) = reason {
                    scanner.r.could_not_run(
                        &format!("firefox:profiles:{}", p.display()),
                        reason,
                    );
                }
            }
            continue;
        }
        let prof_is_dir = profiles_dir.is_dir();
        let cache_is_dir = cache_dir.is_dir();
        if !prof_is_dir && !cache_is_dir {
            continue;
        }
        let (ff_names, ff_known) = if prof_is_dir {
            firefox_ini(profiles_dir)
        } else {
            (HashMap::new(), std::collections::HashSet::new())
        };
        scanner.ctx.emit(&format!(
            "[*] {}",
            if prof_is_dir {
                profiles_dir.display().to_string()
            } else {
                cache_dir.display().to_string()
            }
        ));

        let mut folders: Vec<String> = Vec::new();
        if prof_is_dir {
            match std::fs::read_dir(profiles_dir) {
                Ok(entries) => {
                    for e in entries.flatten() {
                        folders.push(e.file_name().to_string_lossy().into_owned());
                    }
                }
                Err(e) => {
                    let err = SnapError::io(&e);
                    let note = locked_note(profiles_dir, &err);
                    scanner.r.could_not_run("firefox:profiles", &note);
                }
            }
        }
        if cache_is_dir {
            match std::fs::read_dir(cache_dir) {
                Ok(entries) => {
                    for e in entries.flatten() {
                        folders.push(e.file_name().to_string_lossy().into_owned());
                    }
                }
                Err(e) => {
                    let err = SnapError::io(&e);
                    let note = locked_note(cache_dir, &err);
                    scanner.r.could_not_run("firefox:cache-dir", &note);
                }
            }
        }
        folders.sort();
        folders.dedup();

        for name in folders {
            let prof = profiles_dir.join(&name);
            let cprof = cache_dir.join(&name);
            let refused = vec![
                (prof.clone(), path_problem(&prof)),
                (cprof.clone(), path_problem(&cprof)),
            ];
            if refused.iter().any(|(_, r)| r.is_some()) {
                for (p, reason) in &refused {
                    if let Some(reason) = reason {
                        scanner.r.could_not_run(
                            &format!("firefox:profile:{}", p.display()),
                            reason,
                        );
                    }
                }
                continue;
            }
            if !prof.is_dir() && !cprof.is_dir() {
                continue;
            }
            // On Linux the profiles root also holds non-profile folders (Crash
            // Reports, Pending Pings, Profile Groups). Only treat a folder as
            // a profile if profiles.ini lists it or it holds a marker file.
            if !ff_known.contains(&name) {
                match is_ff_profile_dir(&prof) {
                    Ok(false) => continue,
                    Err(e) => {
                        scanner.r.could_not_run(&format!("firefox:profile:{}", name), &e);
                        continue;
                    }
                    Ok(true) => {}
                }
            }
            let display = ff_names.get(&name).cloned().unwrap_or_default();
            scanner.current = if display.is_empty() {
                name.clone()
            } else {
                format!("{} ({})", display, name)
            };
            scanner
                .ctx
                .emit(&format!("[*]   profile: {}", scanner.current));
            if prof.is_dir() {
                scanner.scan_history("firefox", &prof.join("places.sqlite"), "firefox");
                scanner.scan_cookies("firefox", &prof.join("cookies.sqlite"), "firefox");
                scanner.scan_favicons("firefox", &prof.join("favicons.sqlite"), "firefox");
                scanner.scan_firefox_hsts("firefox", &prof.join("SiteSecurityServiceState.txt"));
            }
            if cprof.is_dir() {
                scanner.scan_blobs("firefox", &cprof, EV_REFERENCED);
            }
        }
    }

    // Nothing written after this point should inherit a stale profile name.
    scanner.current = String::new();

    // --- roll each (browser, kind) up into a check the verdict can read ---
    let kinds = std::mem::take(&mut scanner.kinds);
    for ((label, kind), state) in &kinds {
        let check_name = format!("{}:{}", label, kind);
        if state.ok {
            scanner.r.ran(&check_name);
            // A profile that could not be read is still a gap when a DIFFERENT
            // profile of the same browser read fine: the unread profile was
            // never searched, so nothing has been cleared for it.
            for (profile_name, reason) in &state.failures {
                scanner.r.could_not_run(
                    &format!("{} [{}]", check_name, if profile_name.is_empty() { "profile" } else { profile_name }),
                    reason,
                );
            }
        } else {
            // Nothing anywhere read this kind: the kind itself is the gap.
            scanner.r.could_not_run(
                &check_name,
                &if state.reason.is_empty() {
                    "could not be read".to_string()
                } else {
                    state.reason.clone()
                },
            );
        }
    }

    // Report the measured window. Without this, "browser: CLEAN" invites the
    // reader to assume it means "clean for as long as I have owned this
    // computer", which is never true.
    if !scanner.seen_mtimes.is_empty() {
        let earliest = *scanner.seen_mtimes.iter().min().unwrap();
        let mut by_year: HashMap<i64, i64> = HashMap::new();
        for m in &scanner.seen_mtimes {
            *by_year.entry(datetime::civil_from_unix_secs(*m).date.year).or_insert(0) += 1;
        }
        let mut by_year_sorted: Vec<(i64, i64)> = by_year.into_iter().collect();
        by_year_sorted.sort();
        let now = datetime::now_unix();
        let days = ((now - earliest) / 86_400).max(0);
        let mut by_year_map = serde_json::Map::new();
        for (y, c) in by_year_sorted {
            by_year_map.insert(y.to_string(), serde_json::json!(c));
        }
        let mut cache_reach = serde_json::json!({
            "earliest": datetime::iso_from_unix(earliest),
            "days": days,
            "basis": format!(
                "oldest of {} cache/LevelDB/Service-Worker files searched",
                fmt_count(scanner.seen_mtimes.len() as u64)
            ),
            "note": "The HTTP cache is recycled within weeks, but Local Storage, \
                     LevelDB and Service Worker files can persist for years - which \
                     is why this date is often much older than the cache alone. It \
                     is the oldest SURVIVOR, not proof of a continuous record since \
                     then.",
        });
        cache_reach["by_year"] = serde_json::Value::Object(by_year_map);
        scanner.r.reach_set("cache", cache_reach);
    }
    if !scanner.cookie_times.is_empty() {
        let oldest = *scanner.cookie_times.iter().min().unwrap();
        let now = datetime::now_unix();
        let days = ((now - oldest) / 86_400).max(0);
        scanner.r.reach_set(
            "cookies",
            serde_json::json!({
                "earliest": datetime::iso_from_unix(oldest),
                "days": days,
                "basis": format!(
                    "oldest surviving cookie across {} cookie store(s)",
                    scanner.cookie_stores
                ),
                "note": "Cookies are the strongest evidence the browser keeps: one exists \
                         only if the browser actually got a response from that site. But \
                         this is the oldest SURVIVOR, not a full record back to that date. \
                         Cookies expire (Chrome caps them at 400 days) or get cleared, so \
                         most cookies from that time are gone.",
            }),
        );
    }
    if scanner.history_rows {
        scanner.r.reach_set(
            "history",
            serde_json::json!({
                "earliest": serde_json::Value::Null,
                "days": serde_json::Value::Null,
                "basis": "browser history was searched, but records only top-level \
                          navigations",
                "note": "History reaches back further than the cache but CANNOT record an \
                         ad: ads load as a sub-resource inside a page, and only the page \
                         itself is recorded. The long record cannot see ads; the record \
                         that sees ads is not long.",
            }),
        );
    }
    finish(scanner)
}

fn finish(scanner: BrowserScanner<'_, '_>) -> ModuleResult {
    scanner.r
}
