//! Hunt known sample hashes across the user-writable parts of this machine.
//! Ported from zero-breach scan/adint_scan/modules/hashscan.py (Apache-2.0).
//!
//! Citizen Lab (and others) publish SHA-256 hashes for the Windows payloads
//! this infrastructure delivers. Hashing every file on C: would take hours, so
//! this scans the locations an implant DLL actually lands in, plus anything
//! the user downloaded, and compares each file's digest against the sample
//! hashes carried in the IOC set.
//!
//! A clean result means "none of these exact files are in these locations" —
//! nothing more. Each sample is one build; another victim's payload would hash
//! differently, which is why a clean hash scan is never a clean bill of health
//! (D1/D3).
//!
//! Read-only, no network (D2): hashing a local file resolves nothing.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::context::ScanContext;
use crate::iocs::Indicator;
use crate::localpaths::{normcase, normpath, path_problem, walk_local, WalkHandler, WalkProblem};
use crate::result::{Hit, ModuleResult, EV_ON_DISK};
use crate::text::fmt_count;


pub const NAME: &str = "hash";

/// Only file types a payload plausibly ships as. Keeps the walk cheap and
/// avoids hashing the user's documents and media for no reason.
pub const EXTS: [&str; 10] = [
    ".dll", ".exe", ".sys", ".ocx", ".cpl", ".scr", ".tmp", ".dat", ".bin", ".ax",
];

/// Files larger than this are almost certainly not the implant; skipping them
/// (counted as skipped, never as clean) keeps the scan from stalling on big
/// blobs.
pub const MAX_BYTES: u64 = 120 * 1024 * 1024;

/// Directory names pruned from the walk: browser/code caches, dependency
/// trees and the Windows component store — huge, noisy, and not where an
/// implant DLL lands.
pub const PRUNE_DIRS: [&str; 7] = [
    "cache",
    "cache_data",
    "gpucache",
    "code cache",
    "node_modules",
    ".git",
    "servicepackfiles",
];

/// The user-writable locations an implant actually drops into, filtered to
/// those that exist on this host. Matches the proof-of-concept exactly.
///
/// Parameterised so tests can point it at a fixture tree; `roots()` calls it
/// with the real environment.
pub fn roots_from(
    appdata: Option<String>,
    localappdata: Option<String>,
    programdata: Option<String>,
    temp: Option<String>,
    systemroot: Option<String>,
    home: &Path,
) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut push = |raw: Option<String>| {
        if let Some(v) = raw {
            if !v.is_empty() {
                roots.push(PathBuf::from(v));
            }
        }
    };
    push(appdata);
    push(localappdata);
    push(programdata);
    push(temp);
    let sysroot = match systemroot {
        Some(s) if !s.is_empty() => s,
        _ => "C:\\Windows".to_string(),
    };
    roots.push(Path::new(&sysroot).join("Temp"));
    roots.push(home.join("Downloads"));
    roots.push(home.join("Desktop"));
    roots.push(home.join("Documents"));
    roots.push(PathBuf::from("C:\\Users\\Public"));

    // De-duplicate by resolved, case-normalised path, then drop any root that
    // is nested inside another. %TEMP% is %LOCALAPPDATA%\Temp on a default
    // install, so without this every file under Temp is hashed twice.
    let mut resolved: Vec<PathBuf> = Vec::new();
    for raw in roots {
        let norm = normcase(&normpath(&raw));
        if !resolved.contains(&norm) {
            resolved.push(norm);
        }
    }
    let mut kept = Vec::new();
    for r1 in &resolved {
        let nested = resolved.iter().any(|r2| {
            r1 != r2 && r1.to_string_lossy().starts_with(&format!(
                "{}{}",
                r2.to_string_lossy(),
                std::path::MAIN_SEPARATOR
            ))
        });
        if !nested {
            kept.push(r1.clone());
        }
    }
    kept
}

/// The real roots for this host.
pub fn roots() -> Vec<PathBuf> {
    let env = |k: &str| std::env::var(k).ok();
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    roots_from(
        env("APPDATA"),
        env("LOCALAPPDATA"),
        env("PROGRAMDATA"),
        env("TEMP"),
        env("SystemRoot"),
        &home,
    )
}

/// SHA-256 of a file, read in 1 MiB chunks so a large file never loads whole
/// into memory. Returns (hex_digest, size); Err carries why the file was not
/// fingerprinted (unreadable, or over the size cap — which is skipped, never
/// counted as clean).
fn fingerprint(full: &Path) -> Result<(String, u64), String> {
    use std::io::Read;
    if let Some(problem) = path_problem(full) {
        return Err(problem);
    }
    let size = std::fs::metadata(full).map_err(|e| e.to_string())?.len();
    if size > MAX_BYTES {
        return Err(format!("larger than the {}-byte cap", fmt_count(MAX_BYTES)));
    }
    let mut h = Sha256::new();
    let mut fh = std::fs::File::open(full).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = fh.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok((format!("{:x}", h.finalize()), size))
}

/// Run against the real roots.
pub fn run(ctx: &mut ScanContext) -> ModuleResult {
    run_with(ctx, roots())
}

/// Run against an explicit root list (tests point this at a fixture tree; the
/// real machine is never read by the suite).
pub fn run_with(ctx: &mut ScanContext, scan_roots: Vec<PathBuf>) -> ModuleResult {
    let mut r = ModuleResult::new(NAME);
    // Publish the result straight away so that if anything below fails, the
    // CLI can still recover whatever was found before the failure instead of
    // discarding it (see ScanContext::partial).
    ctx.publish_partial(&r);

    // The hashes come from the IOC set, never hardcoded.
    let targets: HashMap<String, Indicator> = ctx
        .iocs
        .hashes()
        .into_iter()
        .map(|i| (i.value.clone(), i.clone()))
        .collect();

    // D3: with nothing to compare against we cannot claim CLEAN. State the
    // gap and stop — an empty target set is UNKNOWN for this check, not clean.
    if targets.is_empty() {
        r.could_not_run("hash-compare", "no sample hashes in the indicator set");
        return r;
    }

    ctx.emit(&format!(
        "[hash] looking for {} known sample hash(es)",
        targets.len()
    ));

    for root in scan_roots {
        let root_text = root.to_string_lossy().into_owned();
        if let Some(problem) = path_problem(&root) {
            r.could_not_run(&format!("root:{}", root_text), &problem);
            continue;
        }
        if !root.is_dir() {
            continue;
        }
        // The full path, not the basename: %TEMP% and %SystemRoot%\Temp both
        // end in "Temp". The verdict for this root is decided AFTER the walk,
        // not before it: a root where every candidate file failed to open must
        // not count as a clean, completed check (D3).
        ctx.emit(&format!("[hash] scanning {} ...", root_text));
        let mut hashed = 0i64;
        let mut candidates = 0i64;
        let mut unreadable = 0i64;
        let mut files: Vec<PathBuf> = Vec::new();
        {
            struct Collect<'a> {
                files: &'a mut Vec<PathBuf>,
                skipped: &'a mut i64,
                unreadable: &'a mut i64,
            }
            impl WalkHandler for Collect<'_> {
                fn onerror(&mut self, _p: WalkProblem) {
                    // An unreadable subtree would otherwise vanish silently.
                    *self.skipped += 1;
                    *self.unreadable += 1;
                }
                fn files(&mut self, _dir: &Path, fs: &[PathBuf]) {
                    self.files.extend(fs.iter().cloned());
                }
            }
            let mut h = Collect {
                files: &mut files,
                skipped: &mut r.skipped,
                unreadable: &mut unreadable,
            };
            let prune = |name: &str| PRUNE_DIRS.contains(&name);
            walk_local(&root, &prune, &mut h);
        }
        for full in files {
            let name = full
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if !EXTS.iter().any(|e| name.ends_with(e)) {
                continue;
            }
            candidates += 1;
            let (digest, size) = match fingerprint(&full) {
                Ok(v) => v,
                Err(_) => {
                    // Locked / permission-denied / unreadable / over the size
                    // cap: skipped, never counted as clean.
                    r.skipped += 1;
                    unreadable += 1;
                    continue;
                }
            };

            hashed += 1;
            r.checked += 1;
            r.bump_metric("files_hashed", 1);
            r.bump_metric("bytes_hashed", size as i64);

            if let Some(ind) = targets.get(&digest) {
                // EV_ON_DISK is the whole point: a file whose fingerprint
                // matches a published sample is conclusive.
                r.add_hit(Hit {
                    indicator: digest.clone(),
                    location: full.to_string_lossy().into_owned(),
                    detail: format!(
                        "this file's SHA-256 matches a published sample: {}",
                        ind.value
                    ),
                    tier: ind.tier.clone(),
                    confidence: ind.confidence.clone(),
                    source: ind.source.clone(),
                    evidence: EV_ON_DISK.to_string(),
                    observed: String::new(),
                    profile: String::new(),
                });
                ctx.emit(&format!(
                    "[hash] !! MATCH {} ({})",
                    full.display(),
                    ind.value
                ));
            }
        }

        // Now say honestly what this root amounted to.
        let name = format!("root:{}", root_text);
        if hashed > 0 {
            r.ran(&name);
            if unreadable > 0 {
                r.could_not_run(
                    &format!("{} (partial)", name),
                    &format!(
                        "{} of {} candidate file(s) under this root could not be read or \
                         were too large to fingerprint, so they were not compared against \
                         the known hashes",
                        unreadable, candidates
                    ),
                );
            }
        } else if candidates > 0 || unreadable > 0 {
            // Candidates existed but not one could be fingerprinted: this root
            // was not searched at all, however many files it holds.
            r.could_not_run(
                &name,
                &format!(
                    "no file under this root could be fingerprinted ({} candidate \
                     file(s) unreadable)",
                    unreadable
                ),
            );
        } else {
            // Walked cleanly, held nothing to fingerprint. Genuinely covered.
            r.ran(&name);
        }
    }
    r
}
