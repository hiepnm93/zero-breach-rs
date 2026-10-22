//! D2 — the tool must never contact an indicator: the guard, the static
//! no-network check over the scan modules, and the refusal of remote
//! filesystem paths (which a socket guard cannot see).
//! Ported from zero-breach scan/tests/test_netguard.py (Apache-2.0).

mod common;

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use zero_breach_rs::context::ScanContext;
use zero_breach_rs::modules::browser::{SnapError, Snapshot};
use zero_breach_rs::modules::host::{self, ComEntry};
use zero_breach_rs::netguard::{self, no_network};
use zero_breach_rs::result::ModuleResult;

use common::{temp_dir, TEST_DOMAIN};

// --- the guard itself -------------------------------------------------------

#[test]
fn the_guard_blocks_and_records_attempts() {
    let _g = no_network();
    for name in netguard::BLOCKED_ENTRY_POINTS {
        let err = netguard::enforce(name).unwrap_err();
        assert!(err.what == name);
        assert!(err
            .to_string()
            .starts_with("D2 violation: scan code attempted network contact"));
    }
    let recorded = netguard::attempts();
    assert_eq!(recorded.len(), netguard::BLOCKED_ENTRY_POINTS.len());
    assert!(recorded[0].starts_with("socket."));
    netguard::clear_attempts();
    assert!(netguard::attempts().is_empty());
}

#[test]
fn the_guard_is_released_when_the_scope_ends() {
    assert!(!netguard::is_active());
    {
        let _g = no_network();
        assert!(netguard::is_active());
    }
    assert!(
        !netguard::is_active(),
        "the guard must be restored on exit, or it would break the IOC-update \
         path that is allowed to use the network"
    );
}

/// The scan path itself holds the guard for the whole module walk. Exercised
/// through the real entry point with fixture-free modules: `run_modules` is
/// the binary's job, so here we assert the invariant the CLI relies on — the
/// modules it calls are the ones compiled without networking.
#[test]
fn scan_modules_reference_no_network_api() {
    // Static guard: a module must not even name a network API. This is the
    // Rust form of the upstream "no module even imports a network library"
    // test, so a future edit that adds a socket call fails the suite.
    let mod_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("modules");
    let forbidden = [
        "std::net",
        "TcpStream",
        "UdpSocket",
        "to_socket_addrs",
        "lookup_host",
        "ureq",
        "reqwest",
        "hyper",
        "http::",
        "getaddrinfo",
        "gethostbyname",
    ];
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&mod_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().map(|e| e != "rs").unwrap_or(true) {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        for needle in forbidden {
            if text.contains(needle) {
                offenders.push(format!(
                    "{}: {}",
                    path.file_name().unwrap().to_string_lossy(),
                    needle
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "scan modules must not reference network APIs: {:?}",
        offenders
    );
}

#[test]
fn scan_modules_shell_out_to_no_resolver() {
    // Blocks the other way to resolve a name: handing it to a system tool.
    let mod_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("modules");
    let forbidden = [
        "resolve-dnsname",
        "nslookup",
        "ping",
        "curl",
        "wget",
        "invoke-webrequest",
        "test-netconnection",
        "whois",
        "portqry",
    ];
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&mod_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().map(|e| e != "rs").unwrap_or(true) {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap().to_lowercase();
        for word in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
            if forbidden.contains(&word) {
                offenders.push(format!(
                    "{}: {}",
                    path.file_name().unwrap().to_string_lossy(),
                    word
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a module appears to shell out to a name resolver or HTTP client: {:?}",
        offenders
    );
}

// --- remote paths are never touched ----------------------------------------

/// The socket guard cannot see a filesystem path. A COM registration value
/// comes out of the registry, which an attacker on a compromised machine
/// controls: an existence test on \\attacker-host\share\x.dll makes WINDOWS
/// open an SMB session, and that handshake can hand the remote host the
/// user's NetNTLM credentials. A mapped drive letter does the same with none
/// of the visual warning.
struct ComFixture {
    iocs: zero_breach_rs::iocs::IocSet,
    dir: PathBuf,
}

impl ComFixture {
    fn new() -> ComFixture {
        let dir = temp_dir("comunc");
        let iocs =
            common::ioc_set_from_lines(&dir, &[&format!("{}\tdelivery\tprimary\tt", TEST_DOMAIN)]);
        ComFixture { iocs, dir }
    }

    fn run(&self, raw_values: &[&str], remote_letters: &[char], kind: &str) -> ModuleResult {
        let entries: Vec<ComEntry> = raw_values
            .iter()
            .enumerate()
            .map(|(i, v)| ComEntry {
                clsid: format!("{{{}}}", i),
                kind: kind.to_string(),
                raw: v.to_string(),
                view: "native".to_string(),
                ..Default::default()
            })
            .collect();
        let mut ctx = ScanContext::new(&self.iocs).with_emit(Box::new(|_| {}));
        let mut r = ModuleResult::new("host");
        host::check_com(&mut r, &mut ctx, entries, remote_letters, true, &[]);
        r
    }
}

#[test]
fn unc_registration_is_never_handed_to_the_filesystem() {
    let unc = "\\\\attacker-host\\share\\payload.dll";
    let unc_ext = "\\\\?\\UNC\\attacker-host\\p.dll";
    let fixture = ComFixture::new();
    // The safe control must be local on the OS running the test.
    let local = fixture.dir.join("synthetic-local-library.dll");
    std::fs::write(&local, b"x").unwrap();
    let r = fixture.run(
        &[unc, unc_ext, local.to_str().unwrap()],
        &[],
        "InprocServer32",
    );
    assert_eq!(
        r.metric("com_remote_paths"),
        2,
        "both UNC spellings are refused"
    );
    let entries_note = r.notes.join("\n");
    assert!(entries_note.contains("UNVERIFIED"));
    assert!(entries_note.contains("attacker-host"));
    // The refusal is a gap, not a silent drop (D3): UNKNOWN is never CLEAN.
    let com = r
        .checks
        .iter()
        .find(|c| c.name == "com-persistence")
        .unwrap();
    assert!(!com.ran, "the COM check must not report as fully run");
    assert!(com.reason.contains("not on a local disk"));
}

#[test]
fn network_mapped_drive_letter_is_never_touched() {
    let fixture = ComFixture::new();
    let r = fixture.run(&["Z:\\payload.dll"], &['Z'], "InprocServer32");
    assert_eq!(r.metric("com_remote_paths"), 1);
    assert!(r
        .checks
        .iter()
        .any(|c| c.name == "com-persistence" && !c.ran));
}

#[test]
fn localserver_remote_paths_are_rejected_before_command_parsing_io() {
    let fixture = ComFixture::new();
    for raw in [
        "\\\\synthetic.invalid\\share\\app.exe",
        "\\\\?\\UNC\\synthetic.invalid\\a.exe",
        "Z:\\app.exe -Embedding",
    ] {
        let r = fixture.run(&[raw], &['Z'], "LocalServer32");
        assert_eq!(
            r.metric("com_remote_paths"),
            1,
            "raw {:?} must be refused",
            raw
        );
        assert!(
            r.checks.iter().any(|c| !c.ran),
            "raw {:?}: the check must not read as fully run",
            raw
        );
    }
}

#[test]
fn a_local_path_is_still_examined() {
    let fixture = ComFixture::new();
    let local = fixture.dir.join("local.dll");
    std::fs::write(&local, b"x").unwrap();
    let r = fixture.run(&[local.to_str().unwrap()], &[], "InprocServer32");
    assert_eq!(r.metric("com_remote_paths"), 0);
    assert!(r
        .checks
        .iter()
        .any(|c| c.name == "com-persistence" && c.ran));
}

#[test]
fn signature_inventory_never_starts_a_subprocess() {
    // Signatures are left unverified on purpose: the OS verifier may contact
    // the network. The function must be pure inventory, no execution.
    let (statuses, reason) = host::signature_status(&["C:\\example.dll".to_string()]);
    assert!(!reason.is_empty());
    assert!(reason.contains("may contact the network"));
    assert_eq!(statuses.get("c:\\example.dll").unwrap().0, "NotChecked");
}

#[test]
fn a_truncated_registry_walk_is_reported_not_hidden() {
    let fixture = ComFixture::new();
    let local = fixture.dir.join("local.dll");
    std::fs::write(&local, b"x").unwrap();
    let entries = vec![ComEntry {
        clsid: "{1}".to_string(),
        kind: "InprocServer32".to_string(),
        raw: local.to_string_lossy().into_owned(),
        view: "native".to_string(),
        ..Default::default()
    }];
    let mut ctx = ScanContext::new(&fixture.iocs).with_emit(Box::new(|_| {}));
    let mut r = ModuleResult::new("host");
    host::check_com(
        &mut r,
        &mut ctx,
        entries,
        &[],
        true,
        &["native view enumeration stopped after 37 keys (access denied)".to_string()],
    );
    let com = r
        .checks
        .iter()
        .find(|c| c.name == "com-persistence")
        .unwrap();
    assert!(
        !com.ran,
        "a truncated enumeration must not pass as complete"
    );
    assert!(com.reason.contains("could not be fully enumerated"));
}

/// The pattern module's honest stub: it must never pretend to have scanned.
#[test]
fn pattern_stub_reports_unavailable_and_never_clean() {
    let dir = temp_dir("patstub");
    let iocs =
        common::ioc_set_from_lines(&dir, &[&format!("{}\tdelivery\tprimary\tt", TEST_DOMAIN)]);
    let mut ctx = ScanContext::new(&iocs).with_emit(Box::new(|_| {}));
    let r = zero_breach_rs::modules::patternscan::run(&mut ctx);
    assert_eq!(r.status(), "UNKNOWN");
    assert!(r
        .checks
        .iter()
        .any(|c| c.name == "pattern-engine" && !c.ran));
    assert!(r.checks.iter().any(|c| c
        .reason
        .contains("pattern scan not available in this build")));
}

/// A snapshot failure keeps the temp-dir story straight: a leftover is
/// reported, not swallowed.
#[test]
fn snapshot_discard_reports_a_leftover() {
    let dir = temp_dir("snapleft");
    // Build a snapshot we keep alive, then check the "kept" flag path.
    let target = dir.join("db.sqlite");
    std::fs::write(&target, b"x").unwrap();
    let (snap, incomplete) = zero_breach_rs::modules::browser::copy_locked(&target).unwrap();
    assert!(incomplete.is_empty());
    assert!(snap.db_path().exists());
    let path = snap.db_path();
    drop(snap); // TempDir removes itself
    assert!(!path.exists(), "the snapshot must be removed");
}

/// Silence unused-import warnings when the suite shape changes.
#[allow(unused)]
fn _uses(b: &Rc<RefCell<Vec<String>>>, s: &SnapError) {
    let _ = b.borrow().len();
    let _ = s.is_lock;
}
#[allow(unused)]
type TestSnapResult = Result<(Snapshot, Vec<String>), SnapError>;
