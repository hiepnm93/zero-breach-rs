# Zero Breach (Rust port)

## Source / Attribution

This is an **unofficial Rust port** of
[zero-breach](https://github.com/interplains/zero-breach) — *adint-scan*, a
local, read-only detector for AdFection / Candiru indicators — **Copyright 2026
archivegenocide.com**, licensed under the **Apache-2.0** (`LICENSE`). The port
tracks upstream **commit `1c7e9b6`** (release v0.1.8) and ports its scanner
(`scan/adint_scan`) file-for-file.

The **indicator data** (`iocs/adfection_iocs.txt`) is CC0 / public domain,
from the same repository (`iocs/LICENSE.md`). It is compiled into the binary
and kept beside it in `iocs/`.

Background research this tool draws on, by the people who documented the
campaign:

- The Citizen Lab, *Exposing AdFection: How Discover-Tech Turned Targeted Ads
  Into a Pipeline for Zero-Click Mercenary Spyware* (2026-10-15) —
  <https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/>
- Recorded Future / Insikt Group, *Tracking Candiru's DevilsTongue Spyware*
  (CTA-2025-0805, 2025-08-05) —
  <https://www.recordedfuture.com/research/tracking-candirus-devilstongue-spyware>
- Further Candiru research: The Citizen Lab (2021, 2022), Confiant (2026),
  Microsoft (2021), ESET (2021), Avast / Gen (2022), Google Threat Analysis
  Group (2021), Amnesty International Security Lab (2024).

This project is **not affiliated with, and not endorsed by**, upstream
zero-breach / archivegenocide.com, The Citizen Lab, Recorded Future, Amnesty
International, Access Now or any other organisation named here. Their names
appear only to cite the source of an indicator or to point at expert help.
Any error in this port is its own; see `NOTICE`.

> **A clean result is not a clean bill of health.** Spyware of this grade is
> built to defeat exactly this kind of check, most of the evidence it leaves
> expires within weeks, and Windows does not record DNS history unless someone
> turned it on. If you have real reason to believe you are a target, the right
> step is expert help — the
> [Access Now Digital Security Helpline](https://www.accessnow.org/help/) or
> the [Amnesty International Security Lab](https://securitylab.amnesty.org/) —
> not a self-service tool.

## What it does

`zero-breach scan` checks a computer for traces of the **AdFection / Candiru**
spyware campaign — the operation in which an ad-tech company used real-time ad
bidding to deliver zero-click spyware. It searches the machine's own leftover
records — browser history, cookies (host names and timestamps only), caches and
connection records, file fingerprints, auto-start registrations, known malware
file-paths and the DNS resolver cache — for published indicators, and reports
what it found, how strong the evidence is, and, just as importantly, **what it
could not check**.

Every match is **evidence-graded** (`on-disk`, `persistence`, `contacted`,
`dns-record`, `attempted`, `configured`, `referenced`), because the artifact
decides the meaning: a domain inside a cached news article about the campaign
is not a connection to it. A DNS cache entry pointing at a sink address is
protective configuration, not contact. Indicators are printed defanged
(`example[.]com`) so forwarding a report cannot cause a mail gateway to fetch
them.

Read-only throughout: browser databases are **copied to a temporary directory**
before being opened (never written to), the scan never touches the registry,
the hosts file or DNS settings, and it never resolves or contacts an indicator
— the scan path contains no networking code at all.

## Build and run

```
cargo build --release
cargo run --release -- scan                # full scan
cargo run --release -- scan --quick        # skip file fingerprinting (a reported gap)
cargo run --release -- scan --json out.json
cargo run --release -- scan --iocs /path/to/iocs.txt
```

No administrator rights are needed. Exit codes: `0` nothing found, `2` an
indicator matched, `1` the scan could not be set up (e.g. a bad indicator
file), `2` also for a command-line usage error (as `argparse` did upstream).

`--json` writes the machine-readable report with the same fields as the
upstream tool (`tool`, `timestamp`, `platform`, `ioc_set`, `modules`,
`verdict`, `doctrine_line`); the human text report goes to stdout.

`--iocs` / `--json` refuse paths that are not on a local disk, exactly as
upstream v0.1.8: a UNC path or a mapped network drive would make Windows open
an SMB session — leaking credentials and, for `--json`, the whole report.

### update-iocs (the only network-capable subcommand)

```
cargo run --release -- update-iocs                  # dry run: fetch, verify, diff
cargo run --release -- update-iocs --apply          # also replace ./iocs/adfection_iocs.txt
cargo run --release -- update-iocs --local /path/to/iocs.txt
```

It fetches `adfection_iocs.txt` and its `.sha256` from the upstream raw URL
over HTTPS (certificate verification on), refuses anything else, checks the
downloaded bytes against the published digest, validates that the download
still parses as a non-empty indicator set, prints the diff, and — only with
`--apply` — replaces the local file via a same-directory temp file and an
atomic rename. The scan subcommand never touches the network.

The published SHA-256 catches a corrupted or truncated download; it does not,
on its own, prove authenticity, because it is served from the same place as
the file. See the trust-model notes in `src/update_iocs.rs`.

## What is ported

| upstream (`scan/adint_scan/`) | here | notes |
|---|---|---|
| `cli.py` | `src/cli.rs` | `scan` and `update-iocs` subcommands, same flags, same exit codes, module-loop panic recovery (keeps partial hits) |
| `iocs.py` | `src/iocs.rs` | loader, validation, type inference, boundary matching (text + bytes + UTF-16LE), parent/child pruning, freshness; IDN → punycode via a small embedded RFC 3492 encoder |
| `localpaths.py` | `src/localpaths.rs` | `path_problem`, `local_temp_dir`, `walk_local` (never follows links or reparse points; Windows drive typing via `GetDriveTypeW`) |
| `netguard.py` | `src/netguard.rs` | Python patched `socket` at runtime, which Rust cannot do; the same guarantee is enforced structurally (no network code in the scan path) plus a guard object, an attempt recorder and static tests over `src/modules/` |
| `context.py` | `src/context.rs` | |
| `result.py` | `src/result.rs` | Hit / Check / ModuleResult, evidence grades, CLEAN ≠ UNKNOWN rollup |
| `report.py` | `src/report.rs` | human text + JSON with the same fields, defanging, field scrubbing, D1 line, reach/campaign-window section |
| `modules/browser.py` | `src/modules/browser.rs` | Chromium (Chrome/Edge/Brave/Vivaldi/Chromium, incl. snap/flatpak) and Firefox: history, cookies (host + timestamps only), favicons, cache/LevelDB blobs, HSTS and connection records; per-(browser, kind) gap rollup |
| `modules/hashscan.py` | `src/modules/hashscan.rs` | |
| `modules/host.py` | `src/modules/host.rs` | Windows checks behind `#[cfg(windows)]`; every other platform reports "not supported on \<os\>" — never a fake CLEAN |
| `modules/patternscan.py` | `src/modules/patternscan.rs` | **stub** (below) |
| `scan/update-iocs.py` | `src/update_iocs.rs` | |
| `scan/tests/` | `tests/` | the meaningful cases, ported |

**Not ported:** `build/` (the STIX / MISP / denylist emitters) and `tools/`
(release checks) — they are packaging and release tooling for the Python
distribution, not scanner behaviour. The third-party YARA rules
(`third_party/candiru/`) are therefore not embedded either; see below.

### The optional pattern check is a stub

Upstream `--patterns` drives the **pinned YARA-X engine** (version-pinned
1.21.0) over two third-party Candiru rules (MSTIC, Detection Rule License 1.1;
yara-signator, CC BY-SA 4.0) with a carefully bounded walk. Porting that
faithfully means embedding those rules and binding and version-pinning
`yara-x` in Rust — not a small optional feature, so this build ships the honest
stub instead: `--patterns` runs a module that reports
"pattern scan not available in this build" as a gap, never as a clean result.
No file is checked against Candiru patterns by this build.

## Behaviour differences from the Python tool

- Timestamps are rendered in **UTC** (Python used the machine's local zone);
  dates may differ by a timezone offset, never in logic.
- `platform` in the JSON reports the Rust toolchain version in the slot the
  Python report used for the interpreter version; the other platform fields
  keep their names.
- Profile folder roots are labelled with the OS path spelling of the host
  (the Python `normpath` kept `C:\...` verbatim on POSIX); both are refused as
  non-local on the same platforms.
- Invalid UTF-8 in an `--iocs` file is a clean `error:` exit 1 instead of a
  Python traceback; every other loader refusal keeps the upstream wording.
- The netguard cannot monkey-patch `std::net` (see `src/netguard.rs` for how
  the same guarantee is enforced instead).

## Tests

```
cargo test                 # 166 tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The suite covers the boundary matching (a longer name or number that merely
contains an indicator must not match), the loader's failure modes, evidence
grading, locked-browser gaps, the no-network guard (including static checks
that scan modules reference no network API and shell out to no resolver),
synthetic positives (a planted hash, a test domain in cache/history — both
detected), the not-infostealer guarantees (an `encrypted_value` sentinel and a
`Local State` master-key sentinel never reach the output; cookie columns are
pinned to a narrow allow-list), report safety (human text is defanged and
line-forging-proof; JSON stays raw) and the CLI contract (exit codes, path
refusal). Everything runs hermetically inside tempdirs with reserved-TLD
indicators; browser locks are simulated through an injectable snapshot hook.

Windows code is checked with:

```
rustup target add x86_64-pc-windows-gnu
cargo check --target x86_64-pc-windows-gnu   # also builds (mingw-w64)
```

CI (`.github/workflows/ci.yml`) runs tests and clippy on Ubuntu, Windows and
macOS, and builds release binaries on `v*` tags.

## Licence

The software is licensed under the **Apache License 2.0** (`LICENSE`). The
indicator data in `iocs/` is released into the public domain under **CC0 1.0**
(`iocs/LICENSE.md`). Upstream's `NOTICE` is kept verbatim, with a port
attribution line appended. This project is not affiliated with or endorsed by
upstream or by any research organisation cited above.
