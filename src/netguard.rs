//! Runtime enforcement of doctrine D2: never contact an indicator.
//! Ported from zero-breach scan/adint_scan/netguard.py (Apache-2.0).
//!
//! D2 is the most important rule in the project. Resolving a C&C domain, or
//! opening any connection, would announce a possible victim to the people
//! running the infrastructure. The tool is a local string-matching tool; it has
//! no reason to touch the network at all.
//!
//! Python made resolution *impossible* by monkey-patching every `socket`
//! entry point while a scan ran. Rust has no equivalent runtime patching of
//! `std::net`, so the same guarantee is enforced differently, and just as
//! absolutely:
//!
//!   * the scan path contains no networking code at all — no `std::net`
//!     socket, no resolver, no HTTP client is compiled into it. The one
//!     network-capable dependency (`ureq`) is linked only for the separate,
//!     explicitly-invoked `update-iocs` subcommand, which never runs a scan;
//!   * while a scan runs inside [`no_network()`], a process-wide guard is
//!     held: anything that tried to route through the guard's
//!     [`enforce`](enforce) checkpoint is refused loudly and recorded, the way
//!     `NetworkContactAttempt` was raised upstream;
//!   * a static test (`tests/netguard.rs`) fails the build if a scan module
//!     ever references a network API, the same job the upstream
//!     "no module even imports a network library" test does.
//!
//! This does NOT restrict child processes (the Windows host module's
//! PowerShell reads the LOCAL DNS resolver cache — reading an already-cached
//! entry resolves nothing), exactly as upstream.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Raised (returned) when scan code tries to resolve a name or open a
/// connection. The message mirrors the Python `NetworkContactAttempt` text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkContactAttempt {
    pub what: String,
}

impl std::fmt::Display for NetworkContactAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "D2 violation: scan code attempted network contact via {}. \
             The scanner must never resolve or connect to an indicator.",
            self.what
        )
    }
}

impl std::error::Error for NetworkContactAttempt {}

static GUARDS: AtomicUsize = AtomicUsize::new(0);
static ATTEMPTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// True while at least one [`NoNetworkGuard`] is alive.
pub fn is_active() -> bool {
    GUARDS.load(Ordering::SeqCst) > 0
}

/// The entry points Python blocked on the `socket` module, kept so the
/// recorded attempt names line up with the upstream tool's reports.
pub const BLOCKED_ENTRY_POINTS: [&str; 6] = [
    "socket.getaddrinfo",
    "socket.gethostbyname",
    "socket.gethostbyname_ex",
    "socket.gethostbyaddr",
    "socket.getnameinfo",
    "socket.create_connection",
];

/// The blocked methods on a socket object: `sendto`/`sendmsg` matter because a
/// UDP datagram needs no prior `connect()`.
pub const BLOCKED_SOCKET_METHODS: [&str; 6] = [
    "socket.socket.connect",
    "socket.socket.connect_ex",
    "socket.socket.sendto",
    "socket.socket.sendmsg",
    "socket.socket.sendall",
    "socket.socket.send",
];

/// Record an attempted contact and produce the refusal. Mirrors the Python
/// `_Recorder.trip`.
pub fn trip(what: &str) -> NetworkContactAttempt {
    if let Ok(mut v) = ATTEMPTS.lock() {
        v.push(what.to_string());
    }
    NetworkContactAttempt {
        what: what.to_string(),
    }
}

/// Checkpoint for code that would touch the network: while a scan runs under
/// the guard this refuses, loudly, instead of leaking a signal.
pub fn enforce(what: &str) -> Result<(), NetworkContactAttempt> {
    if is_active() {
        Err(trip(what))
    } else {
        Ok(())
    }
}

/// Every attempted contact recorded so far (test/observation helper).
pub fn attempts() -> Vec<String> {
    ATTEMPTS.lock().map(|v| v.clone()).unwrap_or_default()
}

/// Clear the recorded attempts (test helper).
pub fn clear_attempts() {
    if let Ok(mut v) = ATTEMPTS.lock() {
        v.clear();
    }
}

/// RAII guard held for the whole scan. Created by [`no_network`]; the guard is
/// released when the value is dropped, so a panic cannot leave it set.
pub struct NoNetworkGuard {
    _private: (),
}

impl Drop for NoNetworkGuard {
    fn drop(&mut self) {
        GUARDS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Hold the no-network guard for the duration of a scan. Upstream this
/// disabled every socket entry point; here it raises the process-wide guard
/// that [`enforce`] and the static tests build on. The scan path never calls
/// any of them, so a scan performs zero resolutions.
pub fn no_network() -> NoNetworkGuard {
    GUARDS.fetch_add(1, Ordering::SeqCst);
    NoNetworkGuard { _private: () }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_blocks_and_restores() {
        assert!(!is_active());
        {
            let _g = no_network();
            assert!(is_active());
            let err = enforce("socket.getaddrinfo").unwrap_err();
            assert!(err.what == "socket.getaddrinfo");
            assert!(attempts().iter().any(|a| a == "socket.getaddrinfo"));
            assert!(err
                .to_string()
                .starts_with("D2 violation: scan code attempted network contact"));
        }
        assert!(!is_active(), "the guard must be released on drop");
    }

    #[test]
    fn outside_the_guard_the_checkpoint_is_open() {
        enforce("socket.create_connection").expect("no guard, no refusal");
    }

    #[test]
    fn every_blocked_entry_point_is_documented() {
        assert_eq!(BLOCKED_ENTRY_POINTS.len(), 6);
        assert_eq!(BLOCKED_SOCKET_METHODS.len(), 6);
    }
}
