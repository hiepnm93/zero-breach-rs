//! ScanContext — what every module receives. Keeps modules decoupled from the
//! CLI. Ported from zero-breach scan/adint_scan/context.py (Apache-2.0).

use std::path::PathBuf;

use crate::iocs::IocSet;
use crate::result::ModuleResult;

pub type EmitFn<'a> = Box<dyn Fn(&str) + 'a>;

/// The default progress sink: stderr, so stdout stays the clean human report.
pub fn default_emit(msg: &str) {
    eprintln!("{}", msg);
}

pub struct ScanContext<'a> {
    pub iocs: &'a IocSet,
    pub deep: bool,
    /// Skip the file-fingerprinting check, which is the slowest part of the
    /// scan by far and the weakest signal in it.
    pub quick: bool,
    pub verbose: bool,
    pub emit: EmitFn<'a>,
    /// The result the running module is filling in, published here as soon as
    /// it exists. A module that dies half way through has usually already
    /// found something — a matching cookie read before a later, malformed
    /// artifact raised — and that evidence must survive the crash. Modules set
    /// it; nothing else should read it except the CLI's recovery path.
    pub partial: Option<ModuleResult>,
    /// Optional research feature. Never installs a dependency or fetches rules.
    pub patterns: bool,
    pub pattern_paths: Vec<PathBuf>,
    /// Local, per-user COM server files discovered by the host check. Only the
    /// optional pattern module consumes these; explicit --pattern-path wins.
    pub pattern_candidate_paths: Vec<PathBuf>,
    pub pattern_candidate_omitted: i64,
}

impl<'a> ScanContext<'a> {
    pub fn new(iocs: &'a IocSet) -> ScanContext<'a> {
        ScanContext {
            iocs,
            deep: false,
            quick: false,
            verbose: true,
            emit: Box::new(default_emit),
            partial: None,
            patterns: false,
            pattern_paths: Vec::new(),
            pattern_candidate_paths: Vec::new(),
            pattern_candidate_omitted: 0,
        }
    }

    pub fn with_emit(mut self, emit: EmitFn<'a>) -> Self {
        self.emit = emit;
        self
    }

    pub fn emit(&self, msg: &str) {
        (self.emit)(msg);
    }

    /// Publish the in-progress result so a crash cannot cost the hits already
    /// collected (see `ScanContext::partial`).
    pub fn publish_partial(&mut self, r: &ModuleResult) {
        self.partial = Some(r.clone());
    }

    pub fn take_partial(&mut self) -> Option<ModuleResult> {
        self.partial.take()
    }
}
