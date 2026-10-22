//! Optional, bounded matching of pinned public Candiru research rules.
//! Ported from zero-breach scan/adint_scan/modules/patternscan.py
//! (Apache-2.0) as an honest stub.
//!
//! The Python module drives the pinned YARA-X engine over a carefully bounded
//! walk (1 MiB per file, file/directory/entry/depth/byte caps, TOCTOU-checked
//! reads, cloud-recall refusal). Porting that faithfully means also embedding
//! the two third-party YARA rules (MSTIC, DRL 1.1; yara-signator, CC BY-SA
//! 4.0) and binding `yara-x` — a real engine version-pinning obligation the
//! upstream tool enforces (`CANDIRU_ENGINE_VERSION`). That is not a small
//! optional feature, so this build ships the honest stub instead: the module
//! runs, reports that it could not, and never pretends to have scanned
//! anything. See README ("What is not ported").
//!
//! Matches, when a future build implements this, require investigation; they
//! are neither exact sample identifications nor confirmation of infection. No
//! rule or sample is ever fetched at scan time.

use crate::context::ScanContext;
use crate::result::ModuleResult;

pub const NAME: &str = "patterns";

pub fn run(ctx: &mut ScanContext) -> ModuleResult {
    let mut r = ModuleResult::new(NAME);
    ctx.publish_partial(&r);
    r.note(
        "Optional public Candiru file patterns; matches would require investigation, \
         not an exact sample identification or confirmed infection.",
    );
    r.could_not_run(
        "pattern-engine",
        "pattern scan not available in this build - the pinned YARA-X Candiru rule \
         engine is not compiled into this Rust port, so no file was checked against \
         Candiru patterns. A no-match here does not exclude encrypted, packed, \
         memory-only, or other builds.",
    );
    r
}
