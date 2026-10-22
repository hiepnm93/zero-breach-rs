//! Shared fixtures for the ported test-suite: synthetic indicator sets, quiet
//! scan contexts and browser-tree builders. Every path a test touches is
//! inside a temp dir; the indicator is a reserved-TLD name (`.invalid`,
//! RFC 2606) that can never resolve, so even a bug that tried to contact it
//! could not reach anyone.

#![allow(dead_code)]

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use zero_breach_rs::context::ScanContext;
use zero_breach_rs::iocs::{self, IocSet};

pub const TEST_DOMAIN: &str = "synthetic-test-indicator.invalid";
pub const PAYLOAD_BYTES: &[u8] = b"MZ\x90\x00 synthetic adint-scan test payload, not malware\n";

pub fn payload_sha256() -> String {
    zero_breach_rs::text::sha256_hex(PAYLOAD_BYTES)
}

pub fn temp_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "zb_rs_test_{}_{}_{}_{}",
        tag,
        std::process::id(),
        n,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write an indicator file and load it.
pub fn ioc_set_from_lines(dir: &Path, lines: &[&str]) -> IocSet {
    let path = dir.join("iocs.txt");
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
    iocs::load(&path).expect("fixture indicator set must load")
}

/// The standard synthetic set: one reserved-TLD domain, one file hash.
pub fn synthetic_ioc_set(dir: &Path) -> IocSet {
    ioc_set_from_lines(
        dir,
        &[
            "# synthetic test indicator set",
            &format!("{}\tdelivery\tprimary", TEST_DOMAIN),
            &format!("{}\tsample\tprimary", payload_sha256()),
        ],
    )
}

/// A scan context whose progress output goes nowhere (or is collected).
pub fn quiet_ctx(iocs: &IocSet) -> ScanContext<'_> {
    ScanContext::new(iocs).with_emit(Box::new(|_m| {}))
}

/// A scan context that records its progress lines.
pub fn recording_ctx(iocs: &IocSet, sink: Rc<RefCell<Vec<String>>>) -> ScanContext<'_> {
    ScanContext::new(iocs).with_emit(Box::new(move |m| sink.borrow_mut().push(m.to_string())))
}

/// A Chromium `urls` table with one row.
pub fn chromium_history_db(path: &Path, url: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let con = rusqlite::Connection::open(path).unwrap();
    con.execute_batch("CREATE TABLE urls (url TEXT, title TEXT);")
        .unwrap();
    con.execute("INSERT INTO urls VALUES (?, 'a page')", [url])
        .unwrap();
}

/// A minimal but real Chromium-shaped Cookies database.
pub fn chromium_cookie_db(path: &Path, host: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let con = rusqlite::Connection::open(path).unwrap();
    con.execute_batch("CREATE TABLE cookies (host_key TEXT, name TEXT, creation_utc INTEGER);")
        .unwrap();
    con.execute(
        "INSERT INTO cookies VALUES (?, 'sid', 13300000000000000)",
        [host],
    )
    .unwrap();
}

/// A minimal Firefox favicons database.
pub fn firefox_favicons_db(path: &Path, icon_url: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let con = rusqlite::Connection::open(path).unwrap();
    con.execute_batch("CREATE TABLE moz_icons (id INTEGER, icon_url TEXT);")
        .unwrap();
    con.execute("INSERT INTO moz_icons VALUES (1, ?1)", [icon_url])
        .unwrap();
    con.execute(
        "INSERT INTO moz_icons VALUES (2, 'https://unrelated.example/f.ico')",
        [],
    )
    .unwrap();
}

/// Chromium profile display names in "Local State".
pub fn write_local_state(user_data: &Path, extra: &str) {
    std::fs::create_dir_all(user_data).unwrap();
    std::fs::write(
        user_data.join("Local State"),
        format!(
            r#"{{"profile": {{"info_cache": {{"Default": {{"name": "Bubbles"{}}}}}}}}}"#,
            extra
        ),
    )
    .unwrap();
}
