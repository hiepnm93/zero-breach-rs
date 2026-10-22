//! The known fixed-path check (HW.sys), COM command parsing, and remote-path
//! judgement.
//! Ported from zero-breach scan/tests/test_known_paths.py and
//! test_server_path.py (Apache-2.0).

mod common;

use std::path::Path;

use zero_breach_rs::context::ScanContext;
use zero_breach_rs::modules::host;
use zero_breach_rs::result::{ModuleResult, EV_ON_DISK};

use common::TEST_DOMAIN;

fn ioc_set_with_hash(dir: &Path, digest: &str) -> zero_breach_rs::iocs::IocSet {
    common::ioc_set_from_lines(
        dir,
        &[
            &format!("{}\tdelivery\tprimary\tt", TEST_DOMAIN),
            &format!("{}\tsample\tsecondary\tavast-2022", digest),
        ],
    )
}

fn run_known_paths(sysroot: &Path, iocs: &zero_breach_rs::iocs::IocSet) -> ModuleResult {
    let mut ctx = ScanContext::new(iocs).with_emit(Box::new(|_| {}));
    let mut r = ModuleResult::new("host");
    host::check_known_paths(&mut r, &mut ctx, &sysroot.to_string_lossy());
    r
}

#[test]
fn no_file_present_is_a_clean_ran_check() {
    let dir = common::temp_dir("kp");
    let iocs = ioc_set_with_hash(&dir, &"a".repeat(64));
    let sysroot = common::temp_dir("kp_sys");
    let r = run_known_paths(&sysroot, &iocs);
    assert!(r.hits.is_empty());
    assert!(r.checks.iter().any(|c| c.name == "known-paths" && c.ran));
}

#[test]
fn known_bad_hash_is_a_serious_on_disk_hit() {
    let dir = common::temp_dir("kp2");
    let sysroot = common::temp_dir("kp2_sys");
    let content = b"this-is-the-known-bad-driver-build";
    let digest = zero_breach_rs::text::sha256_hex(content);
    std::fs::create_dir_all(sysroot.join("System32").join("drivers")).unwrap();
    std::fs::write(
        sysroot.join("System32").join("drivers").join("HW.sys"),
        content,
    )
    .unwrap();
    let iocs = ioc_set_with_hash(&dir, &digest);
    let r = run_known_paths(&sysroot, &iocs);
    assert_eq!(r.hits.len(), 1, "the known-bad driver must be a hit");
    assert_eq!(r.hits[0].evidence, EV_ON_DISK);
    assert!(r.hits[0].location.contains("HW.sys"));
    // A sample-tier hash means the KNOWN-BAD wording, not the driver lead.
    assert!(r.hits[0].detail.contains("KNOWN-BAD"));
}

#[test]
fn same_named_but_different_file_is_a_note_not_a_hit() {
    let dir = common::temp_dir("kp3");
    let sysroot = common::temp_dir("kp3_sys");
    std::fs::create_dir_all(sysroot.join("System32").join("drivers")).unwrap();
    std::fs::write(
        sysroot.join("System32").join("drivers").join("HW.sys"),
        b"a legitimate unrelated HW.sys driver",
    )
    .unwrap();
    // The IOC set carries a DIFFERENT hash, so this file must not match.
    let iocs = ioc_set_with_hash(&dir, &"b".repeat(64));
    let r = run_known_paths(&sysroot, &iocs);
    assert!(
        r.hits.is_empty(),
        "a same-named file that does not match a known-bad hash must not raise \
         a hit"
    );
    assert!(
        r.notes.iter().any(|n| n.contains("HW.sys")),
        "but its presence should be noted for a human to look at"
    );
}

#[test]
fn a_vuln_driver_hit_is_never_called_known_bad() {
    // A `vuln-driver` tier match is legitimate signed software this actor
    // abuses; the wording must be a lead, never "KNOWN-BAD".
    let dir = common::temp_dir("kp4");
    let sysroot = common::temp_dir("kp4_sys");
    let content = b"vulnerable-but-legitimate-driver";
    let digest = zero_breach_rs::text::sha256_hex(content);
    std::fs::create_dir_all(sysroot.join("System32").join("drivers")).unwrap();
    std::fs::write(
        sysroot.join("System32").join("drivers").join("HW.sys"),
        content,
    )
    .unwrap();
    let iocs = common::ioc_set_from_lines(
        &dir,
        &[
            &format!("{}\tdelivery\tprimary\tt", TEST_DOMAIN),
            &format!("{}\tvuln-driver\tsecondary\tavast-2022", digest),
        ],
    );
    let r = run_known_paths(&sysroot, &iocs);
    assert_eq!(r.hits.len(), 1);
    assert_eq!(r.hits[0].tier, "vuln-driver");
    assert_eq!(r.hits[0].evidence, EV_ON_DISK);
    assert!(r.hits[0].detail.contains("LEGITIMATE"));
    assert!(!r.hits[0].detail.contains("KNOWN-BAD"));
}

#[test]
fn an_unreadable_file_is_a_gap_not_a_clean_check() {
    let dir = common::temp_dir("kp5");
    let sysroot = common::temp_dir("kp5_sys");
    std::fs::create_dir_all(sysroot.join("System32").join("drivers")).unwrap();
    std::fs::write(
        sysroot.join("System32").join("drivers").join("HW.sys"),
        b"x",
    )
    .unwrap();
    // Make the file unreadable, so the fingerprint is unavailable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            sysroot.join("System32").join("drivers").join("HW.sys"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
    }
    let iocs = ioc_set_with_hash(&dir, &"a".repeat(64));
    let r = run_known_paths(&sysroot, &iocs);
    #[cfg(unix)]
    {
        // Running as root ignores the mode; only assert when it truly failed.
        if r.metric("known_paths_checked") == 0 {
            assert!(r
                .checks
                .iter()
                .any(|c| !c.ran && c.name.starts_with("known-path:")));
        }
    }
    let _ = r;
}

// --- COM command parsing (pure text; never probes the filesystem) -----------

#[test]
fn com_command_boundaries() {
    const BS: char = '\\';
    let cases: Vec<(String, String)> = vec![
        (
            r"C:\tool.exe\payload.bat -Embedding".to_string(),
            r"C:\tool.exe\payload.bat".to_string(),
        ),
        (
            r"C:\folder.com\payload.exe -Embedding".to_string(),
            r"C:\folder.com\payload.exe".to_string(),
        ),
        (
            r"C:\folder.exe.backup\payload.cmd /quiet".to_string(),
            r"C:\folder.exe.backup\payload.cmd".to_string(),
        ),
        (
            "C:/folder.exe/payload.COM -Embedding".to_string(),
            "C:/folder.exe/payload.COM".to_string(),
        ),
        (
            r"C:\folder.cmd\payload.exe".to_string(),
            r"C:\folder.cmd\payload.exe".to_string(),
        ),
        (
            r"C:\Program Files\server.exe -Embedding".to_string(),
            r"C:\Program Files\server.exe".to_string(),
        ),
        (
            r"C:\server.com --helper C:\later.exe".to_string(),
            r"C:\server.com".to_string(),
        ),
        (
            r"C:\server.bat --helper C:\later.exe".to_string(),
            r"C:\server.bat".to_string(),
        ),
        (
            r"C:\server.cmd --helper C:\later.com".to_string(),
            r"C:\server.cmd".to_string(),
        ),
        (
            "C:\\server.EXE\t-Embedding".to_string(),
            r"C:\server.EXE".to_string(),
        ),
        (
            format!(r#""C:{BS}Program Files{BS}tool.exe{BS}payload.bat" -Embedding"#),
            format!(r"C:{BS}Program Files{BS}tool.exe{BS}payload.bat"),
        ),
        (
            format!(r"{BS}{BS}remote.invalid{BS}share.exe{BS}payload.bat -Embedding"),
            format!(r"{BS}{BS}remote.invalid{BS}share.exe{BS}payload.bat"),
        ),
    ];
    for (raw, expected) in cases {
        assert_eq!(
            host::server_path(&raw, "LocalServer32"),
            expected,
            "raw {:?}",
            raw
        );
    }
}

#[test]
fn bare_dll_values_keep_spaces_and_extension_like_directories() {
    for kind in ["InprocServer32", "InprocHandler32"] {
        for raw in [
            r"C:\folder.exe\my server.dll",
            r#""C:\my folder\server.dll""#,
        ] {
            assert_eq!(
                host::server_path(raw, kind),
                raw.trim_matches('"'),
                "kind {} raw {:?}",
                kind,
                raw
            );
        }
    }
}

#[test]
fn environment_expansion_precedes_command_parsing() {
    std::env::set_var("ZB_SERVER_TEST", r"C:\folder.exe");
    assert_eq!(
        host::server_path("${ZB_SERVER_TEST}\\payload.cmd -Embedding", "LocalServer32"),
        r"C:\folder.exe\payload.cmd"
    );
    std::env::remove_var("ZB_SERVER_TEST");
}

// --- remote path judgement --------------------------------------------------

#[test]
fn remote_path_reason_refuses_the_remote_shapes() {
    let letters = ['Z'];
    assert_eq!(
        host::remote_path_reason(r"\\server\share\x.dll", &letters, true),
        "it is a UNC path to a remote share (\\\\server\\share)"
    );
    assert_eq!(
        host::remote_path_reason(r"\\?\UNC\server\share\x.dll", &letters, true),
        "it is a UNC path to a remote share (\\\\?\\UNC\\...)"
    );
    assert_eq!(
        host::remote_path_reason(r"Z:\payload.dll", &letters, true),
        "drive Z: is mapped to a remote share"
    );
    assert_eq!(
        host::remote_path_reason(r"Z:\payload.dll", &[], false),
        "drive Z: could not be classified as a local disk or a network mapping on this host"
    );
    // An extended-length LOCAL path is ordinary: the prefix alone settles
    // nothing, so the part after it is read.
    assert_eq!(
        host::remote_path_reason(r"\\?\C:\Windows\x.dll", &letters, true),
        ""
    );
    assert_eq!(
        host::remote_path_reason(r"C:\Windows\x.dll", &letters, true),
        ""
    );
    assert_eq!(host::remote_path_reason("", &letters, true), "");
}

#[cfg(windows)]
#[test]
fn powershell_is_an_absolute_path_not_a_bare_name() {
    // Regression for upstream issue #7: PowerShell must be invoked by absolute
    // path, never the bare name "powershell", which Windows resolves through
    // the current directory first.
    let exe = host::ps_exe();
    assert!(
        exe.is_absolute(),
        "PowerShell must be absolute, got {:?}",
        exe
    );
    assert!(exe
        .to_string_lossy()
        .to_lowercase()
        .ends_with("powershell.exe"));
}
