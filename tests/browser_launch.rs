//! A locked browser database is a GAP, not a clean result — plus the Firefox
//! artifacts, Vivaldi discovery, and temp-snapshot cleanup.
//! Ported from zero-breach scan/tests/test_browser_launch.py and
//! test_vivaldi.py (Apache-2.0).

mod common;

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use zero_breach_rs::modules::browser::{
    self, BrowserConfig, SnapError, Snapshot, CHROMIUM_COOKIE_COLUMNS, FIREFOX_COOKIE_COLUMNS,
};
use zero_breach_rs::result::{ModuleResult, CLEAN, HITS, PARTIAL, UNKNOWN};
use zero_breach_rs::{datetime, report};

use common::{temp_dir, TEST_DOMAIN};

/// Signature of the real snapshot routine, aliased for readability.
type SnapFn = fn(&Path) -> Result<(Snapshot, Vec<String>), SnapError>;
type LockPredicate = Rc<dyn Fn(&Path) -> bool>;

/// Names of bscan_* snapshot dirs in the system temp directory. Other tests
/// in this binary run in parallel and also snapshot, so a leak check has to
/// quiesce before concluding.
fn bscan_dir_names() -> std::collections::HashSet<String> {
    std::fs::read_dir(std::env::temp_dir())
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with("bscan_"))
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Fails if a bscan_* directory created after `before` is still present after
/// a grace period (parallel tests' own snapshots are transient and vanish
/// within it; a leak does not).
fn assert_no_new_bscan_dirs(before: &std::collections::HashSet<String>) {
    for _ in 0..60 {
        let new: Vec<String> = bscan_dir_names().difference(before).cloned().collect();
        if new.is_empty() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let new: Vec<String> = bscan_dir_names().difference(before).cloned().collect();
    assert!(new.is_empty(), "snapshot temp dirs leaked: {:?}", new);
}

struct Fixture {
    dir: PathBuf,
    iocs: zero_breach_rs::iocs::IocSet,
    lock_all: bool,
    lock_predicate: Option<LockPredicate>,
}

impl Fixture {
    fn new(tag: &str) -> Fixture {
        let dir = temp_dir(tag);
        let iocs = common::ioc_set_from_lines(
            &dir,
            &[&format!("{}\tdelivery\tprimary\ttest-source", TEST_DOMAIN)],
        );
        Fixture {
            dir,
            iocs,
            lock_all: false,
            lock_predicate: None,
        }
    }

    /// Simulate a locked database exactly as the real lock path fails: the
    /// snapshot routine raises a permission-style refusal for matching paths
    /// and copies normally for the rest.
    fn lock<F: Fn(&Path) -> bool + 'static>(&mut self, predicate: F) {
        self.lock_predicate = Some(Rc::new(predicate));
    }

    fn config(
        &self,
        chromium: Vec<(String, PathBuf)>,
        firefox: Option<Vec<(PathBuf, PathBuf)>>,
    ) -> BrowserConfig {
        let lock_all = self.lock_all;
        let predicate: Option<LockPredicate> = self.lock_predicate.clone();
        let real: SnapFn = browser::copy_locked;
        BrowserConfig {
            chromium,
            firefox,
            snapshot: Some(Rc::new(RefCell::new(Box::new(move |path: &Path| {
                let locked = lock_all || predicate.as_ref().map(|p| p(path)).unwrap_or(false);
                if locked {
                    return Err(SnapError::locked("database is locked"));
                }
                real(path)
            })))),
        }
    }

    fn run(
        &self,
        chromium: Vec<(String, PathBuf)>,
        firefox: Option<Vec<(PathBuf, PathBuf)>>,
    ) -> ModuleResult {
        let cfg = self.config(chromium, firefox);
        let mut ctx = common::quiet_ctx(&self.iocs);
        browser::run_with(&mut ctx, &cfg)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn chromium_config(root: &Path) -> Vec<(String, PathBuf)> {
    vec![("test".to_string(), root.to_path_buf())]
}

fn vivaldi_config(root: &Path) -> Vec<(String, PathBuf)> {
    vec![("vivaldi".to_string(), root.to_path_buf())]
}

#[test]
fn every_database_locked_rolls_up_to_unknown_with_gaps() {
    let mut f = Fixture::new("alllocked");
    let prof = f.dir.join("User Data").join("Default");
    common::chromium_history_db(&prof.join("History"), "https://example.org/ordinary-page");
    common::chromium_cookie_db(&prof.join("Network").join("Cookies"), ".example.net");
    f.lock(|_p| true); // nothing can be snapshotted

    let r = f.run(chromium_config(&f.dir.join("User Data")), Some(vec![]));

    assert!(
        r.hits.is_empty(),
        "a locked db must not somehow produce a hit"
    );
    assert_eq!(
        r.status(),
        UNKNOWN,
        "a browser whose every database was locked observed nothing; that is \
         UNKNOWN, never CLEAN"
    );
    assert!(
        r.checks.iter().any(|c| !c.ran),
        "the locked databases must be recorded as checks that could NOT run"
    );
    // And the gap must reach the verdict, which is what the user reads.
    let doc = report::build_document(&f.iocs, &[r], datetime::now_unix());
    let gaps = doc["verdict"]["gaps"].as_array().unwrap().clone();
    assert!(
        !gaps.is_empty(),
        "the locked-database gap must surface in the verdict - this is the bug: \
         it used to roll up to a clean result"
    );
}

#[test]
fn readable_history_and_locked_cookies_is_partial() {
    let mut f = Fixture::new("partial");
    let prof = f.dir.join("User Data").join("Default");
    common::chromium_history_db(&prof.join("History"), "https://example.org/ordinary-page");
    common::chromium_cookie_db(&prof.join("Network").join("Cookies"), ".example.net");
    f.lock(|p| p.to_string_lossy().contains("Cookies"));

    let r = f.run(chromium_config(&f.dir.join("User Data")), Some(vec![]));

    assert!(r.hits.is_empty());
    assert_eq!(r.status(), PARTIAL, "one kind ran clean, one could not run");
    let ran: Vec<&str> = r
        .checks
        .iter()
        .filter(|c| c.ran)
        .map(|c| c.name.as_str())
        .collect();
    let gaps: Vec<&str> = r
        .checks
        .iter()
        .filter(|c| !c.ran)
        .map(|c| c.name.as_str())
        .collect();
    assert!(ran.contains(&"test:history"));
    assert!(
        gaps.iter().any(|g| g.starts_with("test:cookies")),
        "the locked cookie store is the gap"
    );
    assert!(
        r.checks
            .iter()
            .any(|c| !c.ran && c.reason.to_lowercase().contains("locked")),
        "the gap must carry a reason the user can act on"
    );
}

#[test]
fn a_browser_with_only_a_readable_history_has_no_gaps() {
    let f = Fixture::new("absent");
    let prof = f.dir.join("User Data").join("Default");
    common::chromium_history_db(&prof.join("History"), "https://example.org/ordinary-page");

    let r = f.run(chromium_config(&f.dir.join("User Data")), Some(vec![]));

    assert!(r.hits.is_empty());
    assert_eq!(
        r.status(),
        CLEAN,
        "nothing was locked and the one present artifact was read; an absent \
         cookie store is not a gap"
    );
    assert!(r.checks.iter().all(|c| c.ran));
    assert!(r.checks.iter().any(|c| c.name == "test:history"));
    assert!(
        !r.checks.iter().any(|c| c.name == "test:cookies"),
        "a cookie store the browser never created must not be reported as a \
         check at all"
    );
}

#[test]
fn a_locked_profile_is_a_gap_even_when_another_profile_reads() {
    let mut f = Fixture::new("oneprofile");
    let ud = f.dir.join("User Data");
    common::chromium_cookie_db(
        &ud.join("Default").join("Network").join("Cookies"),
        &format!(".{}", TEST_DOMAIN),
    );
    common::chromium_cookie_db(
        &ud.join("Profile 1").join("Network").join("Cookies"),
        ".example.net",
    );
    // The second profile's cookie store is locked; the first reads fine.
    f.lock(|p| p.to_string_lossy().contains("Profile 1"));

    let r = f.run(chromium_config(&ud), Some(vec![]));

    // The profile that WAS read is a check that ran.
    assert!(r.checks.iter().any(|c| c.name == "test:cookies" && c.ran));
    // The profile that was NOT read is a gap, named with its account.
    let gaps: Vec<&zero_breach_rs::result::Check> = r
        .checks
        .iter()
        .filter(|c| !c.ran && c.name.starts_with("test:cookies"))
        .collect();
    assert!(
        !gaps.is_empty(),
        "the locked profile must surface as its own gap"
    );
    assert!(
        gaps.iter().any(|c| c.name.contains("Profile 1")),
        "the gap must name the profile that was not covered"
    );
    assert!(r.skipped >= 1);
    assert!(r.notes.iter().any(|n| n.to_lowercase().contains("locked")));
    // The readable profile's indicator cookie is still found.
    assert_eq!(r.status(), HITS);
    assert!(r
        .hits
        .iter()
        .any(|h| h.indicator == TEST_DOMAIN && h.evidence == "contacted"));
}

#[test]
fn copy_locked_cleans_its_temp_dir_when_the_copy_fails() {
    let f = Fixture::new("tmpclean");
    let not_a_file = f.dir.join("a-directory");
    std::fs::create_dir_all(&not_a_file).unwrap();
    let before = bscan_dir_names();
    assert!(browser::copy_locked(&not_a_file).is_err());
    assert_no_new_bscan_dirs(&before);
}

#[test]
fn run_leaves_no_temp_dir_behind_when_a_db_cannot_be_copied() {
    let mut f = Fixture::new("tmpclean2");
    let prof = f.dir.join("User Data").join("Default");
    common::chromium_cookie_db(&prof.join("Network").join("Cookies"), ".example.net");
    f.lock(|p| p.to_string_lossy().contains("Cookies"));
    let before = bscan_dir_names();
    let _ = f.run(chromium_config(&f.dir.join("User Data")), Some(vec![]));
    assert_no_new_bscan_dirs(&before);
}

#[test]
fn a_successful_scan_leaves_no_snapshot_behind() {
    let f = Fixture::new("tmpclean3");
    let prof = f.dir.join("User Data").join("Default");
    common::chromium_history_db(&prof.join("History"), "https://example.org/ordinary-page");
    let before = bscan_dir_names();
    let _ = f.run(chromium_config(&f.dir.join("User Data")), Some(vec![]));
    assert_no_new_bscan_dirs(&before);
}

// --- Firefox artifacts ------------------------------------------------------

struct FirefoxFixture {
    f: Fixture,
    profiles_dir: PathBuf,
    cache_dir: PathBuf,
}

impl FirefoxFixture {
    fn new(tag: &str) -> FirefoxFixture {
        let f = Fixture::new(tag);
        let profiles_dir = f
            .dir
            .join("Roaming")
            .join("Mozilla")
            .join("Firefox")
            .join("Profiles");
        let prof = profiles_dir.join("abc123.default-release");
        std::fs::create_dir_all(&prof).unwrap();
        let cache_dir = f.dir.join("Local");
        std::fs::create_dir_all(&cache_dir).unwrap();
        FirefoxFixture {
            f,
            profiles_dir,
            cache_dir,
        }
    }

    fn run(&self) -> ModuleResult {
        self.f.run(
            vec![],
            Some(vec![(self.profiles_dir.clone(), self.cache_dir.clone())]),
        )
    }
}

#[test]
fn firefox_favicon_for_an_indicator_is_contacted() {
    let fx = FirefoxFixture::new("fffav");
    let prof = fx.profiles_dir.join("abc123.default-release");
    common::firefox_favicons_db(
        &prof.join("favicons.sqlite"),
        &format!("https://{}/favicon.ico", TEST_DOMAIN),
    );

    let r = fx.run();

    let fav: Vec<&zero_breach_rs::result::Hit> = r
        .hits
        .iter()
        .filter(|h| h.detail.starts_with("favicon"))
        .collect();
    assert_eq!(fav.len(), 1, "the indicator favicon must be found once");
    assert_eq!(fav[0].indicator, TEST_DOMAIN);
    assert_eq!(
        fav[0].evidence, "contacted",
        "a stored favicon means the browser fetched it from that host"
    );
    assert!(r.checks.iter().any(|c| c.name == "firefox:favicons"));
}

#[test]
fn firefox_hsts_entry_for_an_indicator_is_contacted() {
    let fx = FirefoxFixture::new("ffhsts");
    let prof = fx.profiles_dir.join("abc123.default-release");
    // SiteSecurityServiceState.txt keeps hostnames in plaintext, one entry per
    // line, keyed "<host>:HSTS".
    std::fs::write(
        prof.join("SiteSecurityServiceState.txt"),
        format!(
            "unrelated.example:HSTS\t0\t17\t18000,1,0\n{}:HSTS\t0\t17\t18000,1,0\n",
            TEST_DOMAIN
        ),
    )
    .unwrap();

    let r = fx.run();

    let hits: Vec<&zero_breach_rs::result::Hit> = r
        .hits
        .iter()
        .filter(|h| h.evidence == "contacted")
        .collect();
    assert_eq!(hits.len(), 1, "the HSTS entry should be one contacted hit");
    assert_eq!(hits[0].indicator, TEST_DOMAIN);
    assert!(r.checks.iter().any(|c| c.name == "firefox:hsts"));
    // No other hostname from the file may reach the output.
    let blob = format!("{:#}", r.to_json());
    assert!(!blob.contains("unrelated.example"));
}

#[test]
fn firefox_hsts_file_with_no_indicator_is_clean_not_a_hit() {
    let fx = FirefoxFixture::new("ffhsts2");
    let prof = fx.profiles_dir.join("abc123.default-release");
    std::fs::write(
        prof.join("SiteSecurityServiceState.txt"),
        "unrelated.example:HSTS\t0\t17\t18000,1,0\n",
    )
    .unwrap();
    let r = fx.run();
    assert!(r.hits.is_empty());
    assert!(r.checks.iter().any(|c| c.name == "firefox:hsts" && c.ran));
    assert_eq!(r.status(), CLEAN);
}

// --- Vivaldi (Chromium-based) discovery -------------------------------------

#[test]
fn vivaldi_roots_per_platform() {
    use zero_breach_rs::modules::browser::chromium_roots_for;
    let home = Path::new("/home/u");

    let win = chromium_roots_for("win32", home, Path::new(r"C:\L"));
    let win_vivaldi = win.iter().find(|(n, _)| n == "vivaldi").unwrap();
    assert_eq!(
        win_vivaldi.1,
        PathBuf::from(r"C:\L").join("Vivaldi").join("User Data")
    );

    let mac = chromium_roots_for("darwin", home, Path::new(""));
    assert_eq!(
        mac.iter().find(|(n, _)| n == "vivaldi").unwrap().1,
        home.join("Library")
            .join("Application Support")
            .join("Vivaldi")
    );

    let linux = chromium_roots_for("linux", home, Path::new(""));
    assert_eq!(
        linux.iter().find(|(n, _)| n == "vivaldi").unwrap().1,
        home.join(".config").join("vivaldi")
    );
    assert_eq!(
        linux
            .iter()
            .find(|(n, _)| n == "vivaldi-snapshot")
            .unwrap()
            .1,
        home.join(".config").join("vivaldi-snapshot")
    );
    assert_eq!(
        linux
            .iter()
            .find(|(n, _)| n == "vivaldi-flatpak")
            .unwrap()
            .1,
        home.join(".var")
            .join("app")
            .join("com.vivaldi.Vivaldi")
            .join("config")
            .join("vivaldi")
    );
}

#[test]
fn discovered_vivaldi_roots_scan_profiles_without_changing_source_files() {
    for platform in ["win32", "darwin", "linux"] {
        let f = Fixture::new("vivdisco");
        let home = f.dir.join(platform);
        std::fs::create_dir_all(&home).unwrap();
        let roots = browser::chromium_roots_for(platform, &home, &home);
        let vivaldi: Vec<&(String, PathBuf)> = roots
            .iter()
            .filter(|(n, _)| n.starts_with("vivaldi"))
            .collect();
        assert!(
            !vivaldi.is_empty(),
            "{} should discover vivaldi roots",
            platform
        );
        for (name, root) in &vivaldi {
            common::chromium_history_db(
                &root.join("Default").join("History"),
                &format!("https://{}/x", TEST_DOMAIN),
            );
            common::chromium_cookie_db(
                &root.join("Profile 1").join("Network").join("Cookies"),
                &format!(".{}", TEST_DOMAIN),
            );
            let _ = name;
        }
        let before = tree_snapshot(&home);
        let chromium: Vec<(String, PathBuf)> = roots.clone();
        let r = f.run(chromium, Some(vec![]));
        assert_eq!(
            r.hits.len(),
            vivaldi.len() * 2,
            "{}: one history and one cookie hit per vivaldi root",
            platform
        );
        assert!(r.hits.iter().all(|h| h.evidence == "contacted"));
        let profiles: std::collections::HashSet<String> =
            r.hits.iter().map(|h| h.profile.clone()).collect();
        assert_eq!(
            profiles,
            ["Default".to_string(), "Profile 1".to_string()]
                .into_iter()
                .collect(),
            "profiles are named; actually got {:?}",
            profiles
        );
        assert_eq!(
            before,
            tree_snapshot(&home),
            "scanning must not modify any source file"
        );
    }
}

fn tree_snapshot(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.is_file() {
                out.push((
                    p.to_string_lossy().into_owned(),
                    std::fs::read(&p).unwrap_or_default(),
                ));
            }
        }
    }
    walk(root, &mut out);
    out.sort();
    out
}

#[test]
fn locked_vivaldi_is_unknown_not_clean() {
    let mut f = Fixture::new("vivlock");
    let root = f.dir.join("Vivaldi").join("User Data");
    common::chromium_history_db(
        &root.join("Default").join("History"),
        "https://example.org/x",
    );
    f.lock(|_p| true);
    let r = f.run(vivaldi_config(&root), Some(vec![]));
    assert_eq!(r.status(), UNKNOWN);
    assert!(r
        .checks
        .iter()
        .any(|c| !c.ran && c.name.contains("vivaldi")));
}

#[test]
fn one_locked_vivaldi_profile_preserves_gap() {
    let mut f = Fixture::new("vivlock2");
    let root = f.dir.join("Vivaldi").join("User Data");
    for profile in ["Default", "Profile 1"] {
        common::chromium_history_db(&root.join(profile).join("History"), "https://example.org/x");
    }
    f.lock(|p| p.to_string_lossy().contains("Profile 1"));
    assert_eq!(f.run(vivaldi_config(&root), Some(vec![])).status(), PARTIAL);
}

#[test]
fn vivaldi_research_reference_is_not_contact() {
    let f = Fixture::new("vivref");
    let root = f.dir.join("Vivaldi").join("User Data");
    common::chromium_history_db(
        &root.join("Default").join("History"),
        &format!("https://research.invalid/?indicator={}", TEST_DOMAIN),
    );
    let r = f.run(vivaldi_config(&root), Some(vec![]));
    assert_eq!(r.hits.len(), 1);
    assert_eq!(r.hits[0].evidence, "referenced");
}

#[test]
fn absent_vivaldi_is_not_reported_clean() {
    let f = Fixture::new("vivabsent");
    let root = f.dir.join("Vivaldi").join("User Data");
    std::fs::create_dir_all(&root).unwrap();
    let r = f.run(vivaldi_config(&root), Some(vec![]));
    assert!(r.hits.is_empty());
    assert_eq!(r.status(), UNKNOWN);
}

#[test]
fn corrupt_vivaldi_history_is_a_gap() {
    let f = Fixture::new("vivcorrupt");
    let root = f.dir.join("Vivaldi").join("User Data");
    let history = root.join("Default").join("History");
    std::fs::create_dir_all(history.parent().unwrap()).unwrap();
    std::fs::write(&history, b"not a SQLite database").unwrap();
    let r = f.run(vivaldi_config(&root), Some(vec![]));
    assert!(r.hits.is_empty());
    assert_eq!(r.status(), UNKNOWN);
}

#[test]
fn history_hit_in_vivaldi_profile() {
    let f = Fixture::new("vivhit");
    let ud = f.dir.join("Vivaldi").join("User Data");
    common::chromium_history_db(
        &ud.join("Default").join("History"),
        &format!("https://{}/x", TEST_DOMAIN),
    );
    let r = f.run(vivaldi_config(&ud), Some(vec![]));
    assert!(
        !r.hits.is_empty(),
        "an indicator in Vivaldi history must be found"
    );
}

#[test]
fn locked_note_names_vivaldi() {
    for path in [
        r"C:\Users\u\AppData\Local\Vivaldi\User Data\Default\History",
        "/home/u/.config/vivaldi/Default/History",
    ] {
        let note = browser::locked_note(Path::new(path), &SnapError::locked("database is locked"));
        assert!(note.contains("Vivaldi"), "{:?} -> {:?}", path, note);
        assert!(note.contains("Close Vivaldi and run again"));
    }
}

#[test]
fn cookie_columns_stay_on_the_narrow_allowlist() {
    // The columns the module is willing to ask for are built from these
    // literal lists, so those lists are the thing to pin. Widening them has to
    // be a deliberate act that fails this test first. Cookie VALUES are not on
    // the list and never will be.
    const ALLOWED: [&str; 9] = [
        "host_key",
        "name",
        "host",
        "creation_utc",
        "creationtime",
        "top_frame_site_key",
        "last_access_utc",
        "lastaccessed",
        "expires_utc",
    ];
    let allowed_lower: Vec<String> = ALLOWED.iter().map(|c| c.to_lowercase()).collect();
    for col in CHROMIUM_COOKIE_COLUMNS {
        assert!(
            allowed_lower.contains(&col.to_lowercase()),
            "cookie column {:?} is not on the allow-list - reading more of a \
             cookie store than host/name/timestamps needs a deliberate decision",
            col
        );
    }
    for col in FIREFOX_COOKIE_COLUMNS {
        assert!(
            allowed_lower.contains(&col.to_lowercase()),
            "cookie column {:?} is not on the allow-list",
            col
        );
    }
}
