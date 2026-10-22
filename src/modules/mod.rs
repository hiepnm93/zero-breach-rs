//! Scan modules. Each module exposes a `NAME` and a `run(ctx) -> ModuleResult`
//! and records every sub-check with `ModuleResult::ran` /
//! `could_not_run`, so that CLEAN is never reported for something that did not
//! actually execute (D3). Ported from zero-breach scan/adint_scan/modules/
//! (Apache-2.0).

pub mod browser;
pub mod hashscan;
pub mod host;
pub mod patternscan;
