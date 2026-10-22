//! Refresh the indicator list from the project repository.
//! Ported from zero-breach scan/update-iocs.py (Apache-2.0).
//!
//! WHY THIS IS A SEPARATE SUBCOMMAND, not part of the scanner. The scanner's
//! strongest guarantee is that it NEVER touches the network: it cannot be made
//! to resolve or contact an indicator. Putting an update feature inside the
//! scan path would weaken that guarantee and the claim built on it. So
//! updating is a deliberate, separate act you run yourself, on a subcommand
//! that plainly does reach the network and does nothing else.
//!
//! WHAT IT DOES: downloads the current indicator file from the upstream repo
//! over HTTPS, checks it against the published SHA-256 served beside it,
//! confirms it actually parses as a valid, non-empty indicator set, shows you
//! exactly what changed, and — only with `--apply` — replaces your local copy.
//! A dry run by default.
//!
//! THE TRUST MODEL, STATED HONESTLY. HTTPS with certificate verification
//! proves the bytes came from the upstream host over an encrypted,
//! authenticated channel. The published SHA-256 catches a corrupted or
//! truncated download; it does NOT, on its own, prove authenticity, because it
//! is served from the same place as the file. Tagged releases carry detached
//! GPG signatures upstream; this updater does not verify signatures.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use clap::Args;

use crate::iocs::{self, IocError};

pub const DEFAULT_BASE: &str = "https://raw.githubusercontent.com/interplains/zero-breach/main/iocs/";
const IOC_NAME: &str = "adfection_iocs.txt";

#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// replace the local indicator file if the new one is valid
    #[arg(long)]
    pub apply: bool,
    /// base URL to fetch from (must end in /; HTTPS only)
    #[arg(long, default_value = DEFAULT_BASE)]
    pub url: String,
    /// path to the local indicator file to compare/replace
    #[arg(long, default_value = "iocs/adfection_iocs.txt")]
    pub local: String,
}

/// Fetch a URL over HTTPS with certificate verification on. Returns bytes.
fn fetch(url: &str) -> Result<Vec<u8>, String> {
    if !url.to_lowercase().starts_with("https://") {
        return Err(format!("refusing to fetch over a non-HTTPS URL: {}", url));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .user_agent("adint-scan-update")
        .build();
    let mut reader = agent.get(url).call().map_err(|e| e.to_string())?.into_reader();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

type Meta = BTreeMap<String, (String, String, String)>;

/// (value -> (tier, confidence, source), curated date, count) for one file.
///
/// The metadata travels alongside the values because an upstream correction
/// that retiers an indicator, downgrades its confidence or fixes its citation
/// changes what the scanner tells you about a hit, even though no indicator
/// value moved.
fn index(path: &Path) -> Result<(Meta, Option<String>, usize), IocError> {
    let s = iocs::load(path)?;
    let meta: Meta = s
        .indicators
        .iter()
        .map(|i| {
            (
                i.value.clone(),
                (i.tier.clone(), i.confidence.clone(), i.source.clone()),
            )
        })
        .collect();
    Ok((meta, s.asof.clone(), s.len()))
}

/// "tier=a -> b, source=c -> d" for only the fields that actually moved.
fn describe_change(old: &(String, String, String), new: &(String, String, String)) -> String {
    let fields = [
        ("tier", &old.0, &new.0),
        ("confidence", &old.1, &new.1),
        ("source", &old.2, &new.2),
    ];
    let mut parts = Vec::new();
    for (name, was, now) in fields {
        if was != now {
            let was = if was.is_empty() { "(none)" } else { was.as_str() };
            let now = if now.is_empty() { "(none)" } else { now.as_str() };
            parts.push(format!("{}={} -> {}", name, was, now));
        }
    }
    parts.join(", ")
}

/// Run the `update-iocs` subcommand. Returns the process exit code.
pub fn main(args: UpdateArgs) -> i32 {
    let mut base = args.url.clone();
    if !base.ends_with('/') {
        base.push('/');
    }

    // 1. Download the indicator file and its published hash.
    println!("fetching {}{} ...", base, IOC_NAME);
    let data = match fetch(&format!("{}{}", base, IOC_NAME)) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: download failed: {}", e);
            return 1;
        }
    };
    println!("fetching published SHA-256 ...");
    let published = match fetch(&format!("{}{}.sha256", base, IOC_NAME)) {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            text.split_whitespace()
                .next()
                .unwrap_or("")
                .trim()
                .to_lowercase()
        }
        Err(e) => {
            eprintln!("error: download failed: {}", e);
            return 1;
        }
    };

    // 2. Integrity: the bytes must match the published hash.
    let got = crate::text::sha256_hex(&data);
    if got != published {
        eprintln!(
            "error: downloaded file does not match the published SHA-256.\n  \
             published: {}\n  got:       {}\nNot touching your local file.",
            published, got
        );
        return 1;
    }
    println!("SHA-256 verified: {}", got);

    // 3. Validity: it must parse as a non-empty indicator set BEFORE it can
    //    replace anything. A truncated or malformed download is refused here.
    let tmp = match tempfile::Builder::new()
        .prefix("adint_update_")
        .tempdir()
    {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: could not create a temporary directory: {}", e);
            return 1;
        }
    };
    let newfile = tmp.path().join(IOC_NAME);
    if let Err(e) = std::fs::write(&newfile, &data) {
        eprintln!("error: could not write the download to a temporary file: {}", e);
        return 1;
    }
    let (new_meta, new_asof, new_count) = match index(&newfile) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "error: the downloaded file is not a valid indicator set ({}). Not \
                 touching your local file.",
                e
            );
            return 1;
        }
    };
    println!("downloaded list is valid: {} indicators", new_count);

    // 4. Diff against the local copy so the change is never silent.
    let local = Path::new(&args.local);
    let (old_meta, old_asof, old_count) = if local.exists() {
        match index(local) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: the local indicator file is not valid: {}", e);
                return 1;
            }
        }
    } else {
        println!("(no local indicator file at {} yet)", args.local);
        (BTreeMap::new(), None, 0usize)
    };

    let added: Vec<&String> = new_meta
        .keys()
        .filter(|v| !old_meta.contains_key(*v))
        .collect();
    let removed: Vec<&String> = old_meta
        .keys()
        .filter(|v| !new_meta.contains_key(*v))
        .collect();
    let changed: Vec<&String> = new_meta
        .keys()
        .filter(|v| {
            old_meta.contains_key(*v) && new_meta.get(*v) != old_meta.get(*v)
        })
        .collect();
    let asof_changed = old_count > 0 && new_asof != old_asof;
    println!(
        "\nchange since your copy: +{} new, -{} removed, ~{} changed (you have {}, \
         repo has {})",
        added.len(),
        removed.len(),
        changed.len(),
        old_count,
        new_count
    );
    if asof_changed {
        println!(
            "  curation date: {} -> {}",
            old_asof.as_deref().unwrap_or("(none)"),
            new_asof.as_deref().unwrap_or("(none)")
        );
    }
    for v in added.iter().take(40) {
        println!("  + {}", v);
    }
    if added.len() > 40 {
        println!("  + ... and {} more", added.len() - 40);
    }
    for v in removed.iter().take(40) {
        println!("  - {}", v);
    }
    if removed.len() > 40 {
        println!("  - ... and {} more", removed.len() - 40);
    }
    for v in changed.iter().take(40) {
        println!(
            "  ~ {}: {}",
            v,
            describe_change(&old_meta[*v], &new_meta[*v])
        );
    }
    if changed.len() > 40 {
        println!("  ~ ... and {} more", changed.len() - 40);
    }

    if added.is_empty() && removed.is_empty() && changed.is_empty() && !asof_changed {
        println!("\nYour indicator list is already up to date.");
        return 0;
    }

    // 5. Apply only on explicit request.
    if !args.apply {
        println!(
            "\nThis was a dry run. Re-run with --apply to replace:\n  {}",
            args.local
        );
        return 0;
    }

    // Write beside the destination and rename over it. Opening the
    // destination directly truncates it first, so an interruption or a failed
    // write at that moment leaves a targeted person with no usable indicator
    // list at all — and the scanner refuses to run without one. The temp file
    // is in the same directory so the rename cannot cross a filesystem
    // boundary.
    let dest = match std::fs::canonicalize(local.parent().unwrap_or(Path::new("."))) {
        Ok(p) => p.join(local.file_name().unwrap_or_default()),
        Err(_) => local.to_path_buf(),
    };
    let tmp_path = match tempfile::Builder::new()
        .prefix(".adint_iocs_")
        .tempfile_in(dest.parent().unwrap_or(Path::new(".")))
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: could not write {}: {}", args.local, e);
            return 1;
        }
    };
    let tmp_path = match tmp_path.keep() {
        Ok((_file, path)) => path,
        Err(e) => {
            eprintln!("error: could not write {}: {}", args.local, e);
            return 1;
        }
    };
    if let Err(e) = std::fs::write(&tmp_path, &data) {
        let _ = std::fs::remove_file(&tmp_path);
        eprintln!("error: could not write {}: {}", args.local, e);
        return 1;
    }
    if let Err(e) = std::fs::rename(&tmp_path, &dest) {
        let _ = std::fs::remove_file(&tmp_path);
        eprintln!("error: could not write {}: {}", args.local, e);
        return 1;
    }
    println!(
        "\nupdated {} ({} indicators).",
        args.local, new_count
    );
    0
}
