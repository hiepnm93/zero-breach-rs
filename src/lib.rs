//! zero-breach-rs — local, read-only detector for AdFection / Candiru
//! indicators. Unofficial Rust port of zero-breach
//! (https://github.com/interplains/zero-breach, Apache-2.0): the module layout
//! mirrors the Python package `scan/adint_scan` one-for-one.
//!
//! Ported from zero-breach (https://github.com/interplains/zero-breach,
//! commit 1c7e9b6, Apache-2.0); see NOTICE.
//!
//! A clean result from this tool means "no known indicators were found in the
//! places that can be checked." It does NOT mean the device is clean.

// The port keeps the upstream module surface public on purpose — parts of it
// exist as the exercise surface for the test suite rather than for the binary.
#![allow(dead_code)]

pub mod cli;
pub mod context;
pub mod datetime;
pub mod iocs;
pub mod localpaths;
pub mod modules;
pub mod netguard;
pub mod report;
pub mod result;
pub mod text;
pub mod update_iocs;

/// The ported upstream version this port tracks.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
