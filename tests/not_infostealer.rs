//! This tool must stay distinguishable from the malware it resembles.
//!
//! The scanner opens browser cookie databases, fingerprints files and
//! enumerates the registry — an infostealer does all three. The difference is
//! one specific thing: an infostealer DECRYPTS cookie values, because the
//! values are the credentials it is stealing. This tool only ever reads cookie
//! HOST NAMES and metadata.
//! Ported from zero-breach scan/tests/test_not_infostealer.py (Apache-2.0).

mod common;

use std::path::{Path, PathBuf};

use zero_breach_rs::context::ScanContext;
use zero_breach_rs::modules::browser::{self, BrowserConfig};

use common::{temp_dir, TEST_DOMAIN};

fn source_files() -> Vec<(String, String)> {
    let pkg = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    fn walk(dir: &Path, pkg: &Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, pkg, out);
            } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
                let rel = path
                    .strip_prefix(pkg)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.push((rel, std::fs::read_to_string(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(&pkg, &pkg, &mut out);
    out
}

#[test]
fn no_module_reads_encrypted_cookie_values() {
    let mut offenders = Vec::new();
    for (name, text) in source_files() {
        let low = text.to_lowercase();
        for needle in ["encrypted_value", "encrypted_key", "value_encrypted"] {
            if low.contains(needle) {
                offenders.push(format!("{}: {}", name, needle));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "reading encrypted cookie/credential values is what an infostealer does; \
         indicator matching only needs the host name: {:?}",
        offenders
    );
}

#[test]
fn no_module_calls_a_decryption_api() {
    // DPAPI and the AES-GCM unwrap of Chromium's local state key are the
    // specific mechanisms credential stealers use on Windows. Reading "Local
    // State" for profile DISPLAY NAMES is allowed; the master key is not.
    let forbidden = [
        "cryptunprotectdata",
        "dpapi",
        "win32crypt",
        "protect_data",
        "aesgcm",
        "aes_gcm",
        "unprotect",
        "os_crypt",
        "encrypted_key",
    ];
    let mut offenders = Vec::new();
    for (name, text) in source_files() {
        let low = text.to_lowercase();
        for needle in forbidden {
            if low.contains(needle) {
                offenders.push(format!("{}: {}", name, needle));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "no module may touch a credential-decryption path: {:?}",
        offenders
    );
}

#[test]
fn no_decryption_crate_is_imported() {
    // The scanner has no legitimate need to decrypt anything. sha2 is used for
    // the HSTS fingerprint and file hashing (as hashlib was upstream).
    let banned = [
        "use aes",
        "use gcm",
        "use cbc",
        "use chacha",
        "use rsa::",
        "use p256",
        "use crypto",
        "::cipher",
        "cryptographic",
    ];
    let mut offenders = Vec::new();
    for (name, text) in source_files() {
        let low = text.to_lowercase();
        for needle in banned {
            if low.contains(needle) {
                offenders.push(format!("{}: {}", name, needle));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "decryption crate use: {:?}",
        offenders
    );
}

#[test]
fn scan_modules_only_open_files_for_reading() {
    // Modules may only read. The one legitimate write — a temp copy of a
    // locked database — goes through a copy routine that writes to ITS OWN
    // temp dir, never to a profile. Grep the module sources for the classic
    // write-mode mistakes.
    let mut offenders = Vec::new();
    for (name, text) in source_files() {
        if !name.starts_with("modules") {
            continue;
        }
        for needle in [
            "OpenOptions::new().write(true)",
            "fs::write(",
            "create(true)",
        ] {
            if text.contains(needle) {
                offenders.push(format!("{}: {}", name, needle));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "scan modules must not write files: {:?}",
        offenders
    );
}

#[test]
fn no_module_writes_to_the_registry() {
    let forbidden = [
        "setvalue",
        "createkey",
        "deletekey",
        "deletevalue",
        "savekey",
        "set-itemproperty",
        "new-itemproperty",
        "remove-item",
    ];
    let mut offenders = Vec::new();
    for (name, text) in source_files() {
        if !name.starts_with("modules") {
            continue;
        }
        let low = text.to_lowercase();
        for needle in forbidden {
            if low.contains(needle) {
                offenders.push(format!("{}: {}", name, needle));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "scan modules are read-only: {:?}",
        offenders
    );
}

fn browser_run(dir: &Path, user_data: &Path) -> zero_breach_rs::result::ModuleResult {
    let ioc_path = dir.join("iocs.txt");
    std::fs::write(
        &ioc_path,
        format!("{}\tdelivery\tprimary\tt\n", TEST_DOMAIN),
    )
    .unwrap();
    let iocs = zero_breach_rs::iocs::load(&ioc_path).unwrap();
    let mut ctx = ScanContext::new(&iocs).with_emit(Box::new(|_| {}));
    let cfg = BrowserConfig {
        chromium: vec![("test".to_string(), user_data.to_path_buf())],
        firefox: Some(vec![]),
        snapshot: None,
    };
    browser::run_with(&mut ctx, &cfg)
}

#[test]
fn an_encrypted_cookie_value_is_never_read() {
    // Behavioural proof, which is stronger than reading the source: give the
    // module a cookie database whose encrypted_value holds a sentinel, and the
    // sentinel must appear nowhere in anything the module produces.
    let sentinel = "SENTINEL-SECRET-VALUE-DO-NOT-READ";
    let dir = temp_dir("nostealer");
    let net = dir.join("User Data").join("Default").join("Network");
    std::fs::create_dir_all(&net).unwrap();
    let con = rusqlite::Connection::open(net.join("Cookies")).unwrap();
    con.execute_batch(&format!(
        "CREATE TABLE cookies (host_key TEXT, name TEXT, encrypted_value BLOB, value TEXT, creation_utc INTEGER);
         INSERT INTO cookies VALUES ('.{}', 'sid', x'{}', '{}', 13300000000000000);",
        TEST_DOMAIN,
        sentinel.bytes().map(|b| format!("{:02x}", b)).collect::<String>(),
        sentinel
    ))
    .unwrap();

    let result = browser_run(&dir, &dir.join("User Data"));

    // The indicator must still be found — we are not testing that it reads
    // nothing, only that it never reads the secret.
    assert!(
        !result.hits.is_empty(),
        "the cookie host should still match"
    );
    let blob = format!("{:#}", result.to_json());
    assert!(
        !blob.contains(sentinel),
        "the cookie's encrypted_value leaked into the result"
    );
    assert!(
        !blob.to_uppercase().contains("SENTINEL"),
        "no part of a cookie's value may reach the output"
    );
}

#[test]
fn local_state_master_key_is_never_read() {
    // Local State is read for profile display names. The same file holds the
    // encrypted master key for cookie values, so prove the key is never taken,
    // and that the signed-in email is not collected along with the name.
    let key_sentinel = "MASTER-KEY-SENTINEL-MUST-NOT-APPEAR";
    let dir = temp_dir("localstate");
    let ud = dir.join("User Data");
    let net = ud.join("Profile 1").join("Network");
    std::fs::create_dir_all(&net).unwrap();
    // The real file shape uses os_crypt.encrypted_key; the module must never
    // reach for it, so the sentinel sits under that very key here.
    let local_state = format!(
        r#"{{"os_crypt": {{"encrypted_key": "{}"}}, "profile": {{"info_cache": {{"Profile 1": {{"name": "Bubbles", "user_name": "someone@example.invalid", "gaia_name": "Someone Real"}}}}}}}}"#,
        key_sentinel
    );
    std::fs::write(ud.join("Local State"), local_state).unwrap();

    common::chromium_cookie_db(&net.join("Cookies"), &format!(".{}", TEST_DOMAIN));

    let result = browser_run(&dir, &ud);

    let blob = format!("{:#}", result.to_json());
    assert!(
        !blob.contains(key_sentinel),
        "the cookie-decryption master key leaked into the result"
    );
    // The display name is the thing we DO want, so prove it arrived.
    assert!(
        result.hits.iter().any(|h| h.profile.contains("Bubbles")),
        "the profile display name should be attached to the hit"
    );
    assert!(
        !blob.contains("someone@example.invalid"),
        "the signed-in email address must not be collected"
    );
    assert!(
        !blob.contains("Someone Real"),
        "only the profile display name is collected"
    );
    let _ = PathBuf::new();
}
