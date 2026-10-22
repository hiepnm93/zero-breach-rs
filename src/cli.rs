//! Command-line entry point and orchestration.
//! Ported from zero-breach scan/adint_scan/cli.py (Apache-2.0).
//!
//!   zero-breach scan [--quick] [--deep] [--json <path>] [--iocs <path>]
//!   zero-breach update-iocs [--apply] [--url <base>] [--local <path>]
//!
//! Default scan behaviour (no flags): read-only tier-1 IOC match across the
//! browser, hash and host modules, under the no-network guard. Requires no
//! administrator.
//!
//! There is no system-writing mode. The upstream tool removed its earlier
//! --arm/--undo feature because a review found its undo path could delete
//! every scheduled task on the machine from a journal file any program can
//! write; this port never had it, so a reviewer finds no write path at all.
//!
//! Exit codes: 0 = no indicators found (CLEAN or with gaps); 2 = indicators
//! matched; 1 = the scan could not be set up (bad IOC file, etc.).

use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::{Parser, Subcommand};

use crate::context::{ScanContext, default_emit};
use crate::iocs::{self, IocError, IocSet};
use crate::localpaths::path_problem;
use crate::modules::{browser, hashscan, host, patternscan};
use crate::netguard;
use crate::report::{build_document, render_human, write_json, V_HITS};
use crate::result::ModuleResult;
use crate::update_iocs::{self, UpdateArgs};

/// The bundled indicator set and its published digest, compiled in so the
/// binary runs standalone (the Python release embedded the same file).
pub const EMBEDDED_IOCS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/iocs/adfection_iocs.txt"
));
pub const EMBEDDED_IOCS_SHA256: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/iocs/adfection_iocs.txt.sha256"
));

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "zero-breach",
    version = VERSION,
    about = "Local, read-only check for AdFection / Candiru indicators. \
             A clean result is NOT a clean bill of health."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read-only tier-1 IOC match across the browser, hash and host modules
    Scan {
        /// skip fingerprinting every file (roughly halves the runtime). The
        /// skipped check is reported as a gap, not as clean.
        #[arg(long)]
        quick: bool,
        /// tier 2: full persistence sweep (noisy; most hits are legitimate)
        #[arg(long)]
        deep: bool,
        /// experimental local Candiru file-pattern check (not available in
        /// this build; reported as a gap, never as clean)
        #[arg(long)]
        patterns: bool,
        /// file or folder for --patterns (repeatable). Requires --patterns.
        #[arg(long = "pattern-path", value_name = "PATH")]
        pattern_path: Vec<String>,
        /// also write the machine-readable report to PATH
        #[arg(long, value_name = "PATH")]
        json: Option<String>,
        /// indicator file (default: the bundled adfection_iocs.txt)
        #[arg(long, value_name = "PATH")]
        iocs: Option<String>,
    },
    /// Refresh the indicator list from the upstream repository (the one
    /// network-capable subcommand; HTTPS only, hash-verified, dry run by
    /// default)
    #[command(name = "update-iocs")]
    UpdateIocs(UpdateArgs),
}

/// The indicator set the tool ships with, parsed once.
pub fn embedded_ioc_set() -> Result<IocSet, IocError> {
    let mut set = iocs::parse(EMBEDDED_IOCS, "<embedded adfection_iocs.txt>", None)?;
    set.asof = parse_embedded_asof();
    Ok(set)
}

fn parse_embedded_asof() -> Option<String> {
    for line in EMBEDDED_IOCS.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('#') {
            continue;
        }
        if let Some(date) = trimmed
            .strip_prefix('#')
            .map(str::trim_start)
            .and_then(|r| r.strip_prefix("as-of:"))
            .map(str::trim)
            .filter(|d| crate::datetime::parse_date(d).is_some())
        {
            return Some(date.to_string());
        }
    }
    None
}

/// Refuse a user-typed path that is not on a local disk.
///
/// --iocs and --json are paths people type, often copied from an instruction
/// somebody else wrote. Opening or creating a UNC path or a mapped network
/// drive makes Windows itself open an SMB session to that host — sending this
/// account's network credentials and, for --json, the complete report. The
/// socket guard cannot see that. abspath first: path_problem refuses relative
/// paths outright, and "--json report.json" is the documented usage.
fn refuse_remote(label: &str, value: &str) -> bool {
    let abs = std::env::current_dir()
        .map(|d| d.join(value))
        .unwrap_or_else(|_| PathBuf::from(value));
    if let Some(problem) = path_problem(&abs) {
        eprintln!(
            "error: {} {}: {} - use a path on a local disk",
            label,
            value,
            problem
        );
        return true;
    }
    false
}

fn load_iocs(path: Option<&str>) -> Result<IocSet, i32> {
    match path {
        None => embedded_ioc_set().map_err(|e| {
            eprintln!("error: {}", e);
            1
        }),
        Some(p) => iocs::load(Path::new(p)).map_err(|e| {
            eprintln!("error: {}", e);
            1
        }),
    }
}

/// Run every module under the no-network guard, isolating each one so a
/// failure costs the module, never the whole tool.
fn run_modules(ctx: &mut ScanContext) -> Vec<ModuleResult> {
    // A module that panics must not spray a Rust panic trace over a report
    // meant to be forwarded; the recovery below records it as a gap instead.
    std::panic::set_hook(Box::new(|_info| {}));

    let mut results: Vec<ModuleResult> = Vec::new();
    // The entire scan runs inside the no-network guard (D2).
    let _guard = netguard::no_network();

    struct Module {
        name: &'static str,
        run: fn(&mut ScanContext) -> ModuleResult,
    }
    let mut modules: Vec<Module> = vec![
        Module { name: browser::NAME, run: browser::run },
        Module { name: hashscan::NAME, run: hashscan::run },
        Module { name: host::NAME, run: host::run },
    ];
    if ctx.patterns {
        modules.push(Module { name: patternscan::NAME, run: patternscan::run });
    }

    for module in modules {
        // --quick drops the file-fingerprint check. It costs ~45% of the whole
        // scan to look for ONE published file hash, and Candiru compiles a
        // fresh build per target, so another victim's file would not match it
        // anyway. Skipping is reported as a GAP, never as clean (D3) - a
        // check that did not run has not cleared anything.
        if module.name == hashscan::NAME && ctx.quick {
            let mut r = ModuleResult::new(hashscan::NAME);
            r.could_not_run(
                "file-fingerprints",
                "skipped by --quick. No file on this machine was fingerprinted, so a \
                 known sample sitting on disk would not have been found. Re-run without \
                 --quick to include it",
            );
            results.push(r);
            ctx.emit("[*] skipping file fingerprints (--quick)");
            continue;
        }
        ctx.emit(&format!("[*] running check: {}", module.name));
        let started = Instant::now();
        ctx.partial = None;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (module.run)(ctx)
        }));
        let mut result = match outcome {
            Ok(r) => r,
            // Keep what the module had already found. Replacing it with a
            // fresh empty result discarded real hits: one malformed artifact
            // late in the browser walk wiped out a matching cookie that had
            // already been read, and the scan reported only a gap.
            Err(_) => {
                let partial = ctx.partial.take();
                match partial {
                    Some(p) if p.name == module.name => p,
                    _ => ModuleResult::new(module.name),
                }
            }
        };
        ctx.partial = None;
        result.duration_s = started.elapsed().as_secs_f64();
        ctx.emit(&format!(
            "[*]   {} finished in {:.0}s",
            module.name, result.duration_s
        ));
        results.push(result);
    }

    if ctx.deep {
        // Tier 2 is not written yet. An advertised flag must not crash, and it
        // must not quietly report a clean sweep it never performed: the honest
        // result is UNKNOWN.
        let mut r = ModuleResult::new("deep");
        r.could_not_run(
            "persistence-sweep",
            "tier 2 (--deep) is not implemented yet — no full persistence sweep was \
             performed. A full persistence review requires a separate forensic \
             examination",
        );
        results.push(r);
    }
    results
}

/// Run the `scan` subcommand. Returns the process exit code.
pub fn scan(args: ScanArgs) -> i32 {
    // Checked before anything is opened, and before a 15-minute scan rather
    // than after it. The bundled default is never attacker-chosen, so only a
    // path the user supplied is checked.
    if let Some(iocs_path) = &args.iocs {
        if refuse_remote("--iocs", iocs_path) {
            return 1;
        }
    }
    if let Some(json_path) = &args.json {
        if refuse_remote("--json", json_path) {
            return 1;
        }
    }

    let ioc_set = match load_iocs(args.iocs.as_deref()) {
        Ok(s) => s,
        Err(code) => return code,
    };

    if args.deep {
        eprint!(
            "WARNING (--deep): a full persistence sweep lists many legitimate\n\
             entries. Most findings are NOT malicious. Read each one; do not\n\
             panic at an unsigned binary in a user-writable path.\n\n"
        );
    }

    let started_unix = crate::datetime::now_unix();
    let results = {
        let mut ctx = ScanContext::new(&ioc_set);
        ctx.deep = args.deep;
        ctx.quick = args.quick;
        ctx.patterns = args.patterns;
        ctx.pattern_paths = args.pattern_path.iter().map(PathBuf::from).collect();
        ctx.emit = Box::new(default_emit);
        run_modules(&mut ctx)
    };

    let document = build_document(&ioc_set, &results, started_unix);
    println!("{}", render_human(&document));

    if let Some(json_path) = &args.json {
        match write_json(&document, json_path) {
            Ok(()) => eprintln!("\n[wrote JSON report to {}]", json_path),
            // The human report already printed; a failed JSON write must not
            // bury it under a traceback. Report the failure and keep the
            // verdict code.
            Err(e) => eprintln!(
                "\n[could not write JSON report to {}: {}]",
                json_path, e
            ),
        }
    }

    if document["verdict"]["status"].as_str() == Some(V_HITS) {
        2
    } else {
        0
    }
}

#[derive(Clone, Debug)]
pub struct ScanArgs {
    pub quick: bool,
    pub deep: bool,
    pub patterns: bool,
    pub pattern_path: Vec<String>,
    pub json: Option<String>,
    pub iocs: Option<String>,
}

/// Process entry point. `argv` includes the program name at index 0, exactly
/// as `std::env::args()` presents it. Returns the exit code.
pub fn main(argv: Vec<String>) -> i32 {
    let cli = match Cli::try_parse_from(argv) {
        Ok(c) => c,
        Err(e) => {
            // Usage errors exit 2, exactly as argparse did upstream. (That is
            // a different "2" from the indicators-found code, which is only
            // ever returned by a completed scan.)
            let _ = e.print();
            return 2;
        }
    };
    match cli.command {
        Command::Scan {
            quick,
            deep,
            patterns,
            pattern_path,
            json,
            iocs,
        } => {
            if !pattern_path.is_empty() && !patterns {
                eprintln!("error: --pattern-path requires --patterns");
                return 2;
            }
            scan(ScanArgs {
                quick,
                deep,
                patterns,
                pattern_path,
                json,
                iocs,
            })
        }
        Command::UpdateIocs(args) => update_iocs::main(args),
    }
}
