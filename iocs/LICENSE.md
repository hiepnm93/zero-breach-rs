# Indicator data — CC0 1.0 Universal (public domain dedication)

The files in this directory — `adfection_iocs.txt` and the generated exports in
`../dist/` — are dedicated to the public domain under
**[CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/legalcode)**.

To the extent possible under law, archivegenocide.com has waived all copyright
and related or neighbouring rights to this indicator set. You may copy, modify,
distribute and use it, including commercially, without asking and without
attribution.

**The software in the rest of this repository is licensed separately**, under the
Apache License 2.0. See `../LICENSE`.

## Why CC0 and not Apache for the data

An indicator is a fact. Facts are not copyrightable, so a restrictive licence
here would be both unenforceable and obstructive. What *is* arguably protectable
is the curation — the tiering, the confidence grading, the per-indicator source
attribution — and CC0 waives that too, deliberately. The entire point of this
file is that other people put it in their own tools: DNS blocklists, MISP
instances, STIX bundles, SIEM rules, Amnesty's MVT. Any friction in that is
friction against the people the data exists to protect.

## Attribution is not required, but is appreciated and is good practice

Not for us — for the researchers. The indicators were published by:

- **The Citizen Lab** (University of Toronto), *"Exposing AdFection: How
  Discover-Tech Turned Targeted Ads Into a Pipeline for Zero-Click Mercenary
  Spyware"*, 2026-10-15.
- **Recorded Future / Insikt Group**, *Devil's Tongue* infrastructure reporting,
  [CTA-2025-0805](https://www.recordedfuture.com/research/tracking-candirus-devilstongue-spyware), 2025-08-05.
- **The Citizen Lab**, [*Hooking Candiru*](https://citizenlab.ca/research/hooking-candiru-another-mercenary-spyware-vendor-comes-into-focus/), 2021-07-15;
  [*CatalanGate*](https://citizenlab.ca/research/catalangate-extensive-mercenary-spyware-operation-against-catalans-using-pegasus-candiru/), 2022-04-18 (Candiru indicators only).
- **Confiant**, [*ADINT: Weaponized Ad Tech for Zero-Click Spyware and Mass Identity Vacuuming*](https://blog.confiant.com/p/adint-weaponized-ad-tech-for-zero-click-spyware-and-mass-identity-vacuuming), 2026-10-15.
- **Microsoft**, [*Protecting customers from a private-sector offensive actor using 0-day exploits and DevilsTongue malware*](https://www.microsoft.com/en-us/security/blog/2021/07/15/protecting-customers-from-a-private-sector-offensive-actor-using-0-day-exploits-and-devilstongue-malware/), 2021-07-15.
- **ESET**, [*Strategic web compromises in the Middle East with a pinch of Candiru*](https://www.welivesecurity.com/2021/11/16/strategic-web-compromises-middle-east-pinch-candiru/), 2021-11-16.
- **Avast / Gen**, [*The Return of Candiru: Zero-days in the Middle East*](https://www.gendigital.com/blog/insights/research/the-return-of-candiru-zero-days-in-the-middle-east), 2022-07-21, and its [official indicator repository](https://github.com/gendigitalinc/ioc/tree/master/Candiru).
- **Google Threat Analysis Group**, [*How we protect users from 0-day attacks*](https://blog.google/threat-analysis-group/how-we-protect-users-0-day-attacks/), 2021-07-14 (Candiru-related Chrome/IE sections only).
- **Amnesty International Security Lab**, [*A Web of Surveillance*](https://securitylab.amnesty.org/latest/2024/05/a-web-of-surveillance/), 2024-05-01 (Candiru Table 6 only).

Every line in `adfection_iocs.txt` carries its source in the fourth column, and
every object in the STIX and MISP exports carries it too, so this attribution
survives being copied into another tool. Please keep that column intact when you
redistribute.

The current source dataset contains 405 indicators (292 domains, 111 IPs and
two SHA-256 values). The live blocklists contain 291 reviewed domain/hostname
rules: bare `adtimizer.co` is retained as scanner evidence but omitted from
blocking, while its named operational subdomains remain. Historical domains
may have expired or changed ownership; inclusion is not a claim of current
malicious activity. Shared hosting parents and IPs are not block rules.

## Please read the header of the indicator file before using it

`adfection_iocs.txt` documents what was **deliberately not imported** and why —
including the 305 validator domains Citizen Lab counted but did not publish, and
corporate domains that are attribution rather than indicators. It also explains
why the `candiru-ip` tier is weaker than the others: those are cloud-hosted
addresses from 2025 that are very likely reassigned to unrelated tenants by now,
and are only meaningful when a hit is dated within the reporting period.

Blocking them wholesale, or feeding them to a tool that alerts on any match, will
generate false positives against innocent people. The tiers exist precisely so
you do not have to do that. See also `VALIDATOR-GAP.md`.
