Unofficial Rust port of [interplains/zero-breach](https://github.com/interplains/zero-breach) (Apache-2.0, Copyright 2026 archivegenocide.com). Not affiliated with or endorsed by upstream. See NOTICE.

**A clean result is not a clean bill of health.** Read the README before relying on it.

## Files

| File | What it is |
|---|---|
| `zero-breach-windows-x86_64.exe` | Windows scanner (host checks are Windows-only) |
| `zero-breach-macos-aarch64`, `zero-breach-macos-x86_64` | macOS scanner (Apple Silicon / Intel) |
| `zero-breach-linux-x86_64` | Linux scanner |
| `adfection_iocs.txt` (+ `.sha256`) | Indicator list, also embedded in the binaries (CC0) |
| `adfection.hosts.txt`, `.dnsmasq.conf`, `.adblock.txt`, `.domains.txt` | Blocklist exports (CC0) |
| `adfection.stix.json`, `.withdrawals.stix.json`, `.misp.json` | STIX 2.1 / MISP exports (CC0) |
| `NOTICE`, `LICENSE`, `LICENSE-DATA-CC0.md` | Attribution and licences |
| `SHA256SUMS.txt` | SHA-256 of every file above |

The blocklist, STIX and MISP files are **upstream's own v0.1.8 release files, byte for byte**. The release job downloads them, checks upstream's GPG signature (key `C24E C92B 12D6 670A 2516 065F 9B4D 5754 99AF A53C`, from upstream SIGNING.md), and requires that they were built from the same `adfection_iocs.txt` these binaries embed. You can check them yourself against upstream's signed `SHA256SUMS.txt`.

The binaries are not GPG-signed; verify them with `SHA256SUMS.txt`. YARA pattern scanning is not in this build, so the Candiru rule files from upstream are not included.

Update the indicator list later with `zero-breach update-iocs --apply`.

---
Bản Rust không chính thức của zero-breach. Tải file theo hệ điều hành, chạy `zero-breach scan`. Các file blocklist giống y bản gốc v0.1.8, đã kiểm chữ ký.
