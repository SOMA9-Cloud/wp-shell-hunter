# wp-shell-hunter

[![CI](https://github.com/SOMA9-Cloud/wp-shell-hunter/actions/workflows/test.yml/badge.svg)](https://github.com/SOMA9-Cloud/wp-shell-hunter/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org)
[![No deps](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen.svg)](#requirements)

Detect PHP webshells **disguised as media files** in WordPress and cPanel
hosting environments. Catches the patterns that surface-level malware scanners
routinely miss.

## Why this exists

Most WordPress malware tooling looks for `.php` files in standard paths.
Modern webshell families bypass that by:

- Embedding PHP code in files with media extensions (`.tiff`, `.gif`, `.png`,
  `.mp4`, `.flv`, `.3gp`, `.webp`, `.zip`).
- Hiding inside attacker-created **doubled directories**
  (`wp-admin/maint/maint/`, `cgi-bin/cgi-bin/cgi-bin/`,
  `images/images/images/images/`).
- Obfuscating the dropper with `goto`-statement spaghetti, quadruple-nested
  `md5()` password gates, and `eval()` chained with `curl_exec()`.

When an admin only finds and removes the obvious `.php` files, the
non-`.php` droppers stay behind and the site re-infects within hours.

`wp-shell-hunter` was built specifically to catch the non-obvious tier.

## Quick start

```bash
# One-shot install (no pip, no virtualenv)
curl -fsSL https://raw.githubusercontent.com/SOMA9-Cloud/wp-shell-hunter/main/install.sh | sudo bash

# Scan a webroot
wp-shell-hunter /var/www/html

# Multiple WordPress installations under /home
wp-shell-hunter /home --workers 8

# JSON output for SIEM/CI ingestion
wp-shell-hunter /var/www/html --json > findings.json

# Skip the (very noisy) WordPress uploads directory by default;
# enable explicitly if you want to scan it too:
wp-shell-hunter /var/www/html --scan-uploads
```

Exit codes:

| Code | Meaning                                              |
|------|------------------------------------------------------|
| `0`  | Nothing suspicious found                             |
| `1`  | At least one suspicious finding (manual review)      |
| `2`  | At least one finding rated `malicious` (urgent)      |

These codes are stable across versions and safe to use in CI gates.

## Detectors

### 1. `disguised_php`

Reads the first 16 bytes of every file with a media or asset extension and
reports a finding if the content begins with `<?php` (or `<?` short tag with no
XML follow-on). PHP code stored in `.tiff`, `.gif`, `.png`, `.mp4`, etc. has no
legitimate use case.

**Confidence:** high. **Severity:** malicious.

### 2. `doubled_directory`

Walks paths looking for adjacent identical directory components (`/foo/foo/`),
then deeper repetition (`/foo/foo/foo/`). A whitelist excludes legitimate PHP
class organisation patterns from popular libraries (PSR-4 namespacing such as
`SimplePie/SimplePie/`, `Requests/Requests/`).

**Confidence:** medium for two-deep doubling, high for three-or-more.
**Severity:** suspicious.

### 3. `obfuscation`

Reads up to 256 KB of content and scores against patterns observed across
multiple webshell families:

| Pattern                           | Weight |
|-----------------------------------|-------:|
| `goto`-spaghetti (≥ 5 statements) |     +3 |
| Quadruple-nested `md5(md5(...))`  |     +4 |
| Triple-nested `md5(...)`          |     +3 |
| `eval($var[N])` style execution   |     +3 |
| `${$var[N]}` indirect variable    |     +1 |
| Hex-escape alphabet build         |     +2 |
| `eval()` with `curl_exec()`       |     +4 |

Total ≥ 7 → malicious + high confidence.
Total ≥ 4 → suspicious + medium confidence.
Total ≥ 3 → suspicious + low confidence.
Below 3 → silently skipped.

The thresholds are tuned to avoid flagging routinely obfuscated but legitimate
code (minified libraries, packed assets) while still catching aggressive
multi-layer obfuscation.

## What it does NOT do

- Does not delete files. Findings are reported only. Use your existing tools
  for remediation, or use the planned `--quarantine` mode in a future release.
- Does not run code. Files are inspected as bytes; nothing is executed.
- Does not phone home. There is no telemetry, no remote update check.
- Does not require root unless you are scanning paths only root can read.
- Does not replace a full malware scanner. Use it alongside ImunifyAV,
  Sucuri SiteCheck, Wordfence, etc.

## Requirements

- Python **3.8+** (already present on every modern Linux distribution).
- No third-party Python packages. Standard library only.
- Read access to the paths being scanned.

## Installation

### Option A — install.sh (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/SOMA9-Cloud/wp-shell-hunter/main/install.sh | sudo bash
```

This drops the package under `/opt/wp-shell-hunter` and symlinks the launcher
into `/usr/local/bin`.

### Option B — clone and run from source

```bash
git clone https://github.com/SOMA9-Cloud/wp-shell-hunter.git
cd wp-shell-hunter
./bin/wp-shell-hunter --help
```

### Option C — module mode

```bash
git clone https://github.com/SOMA9-Cloud/wp-shell-hunter.git
cd wp-shell-hunter
PYTHONPATH=src python3 -m wp_shell_hunter /path/to/scan
```

## CI integration

```yaml
# Example GitHub Actions step
- name: Scan deployment for disguised PHP
  run: |
    curl -fsSL https://raw.githubusercontent.com/SOMA9-Cloud/wp-shell-hunter/main/install.sh | sudo bash
    wp-shell-hunter ./public --json > shell-hunter.json
```

The non-zero exit code (`2`) on `malicious` findings will fail the job by
default, surfacing the issue early.

## Performance

Indicative numbers from a representative scan over a multi-site cPanel/WP host:

| Files | Workers | Time |
|------:|--------:|-----:|
| 50,000 | 4       | ~12s |
| 250,000 | 8      | ~45s |
| 1,000,000 | 16   | ~3m  |

The walker prunes large irrelevant trees (`node_modules`, `vendor`,
`__pycache__`, `cache`, etc.) by default. Override via `--scan-uploads` and
`--follow-symlinks` if your environment requires it.

## Limitations

- A motivated attacker can avoid all three detectors. This tool catches the
  current, common patterns; it is not a guarantee of cleanliness.
- Static analysis only. No behavioural detection.
- The obfuscation detector is heuristic. False positives are possible on
  heavily-obfuscated but benign code (rare in WordPress contexts).

## Contributing

Issues and pull requests welcome. New detector modules go under
`src/wp_shell_hunter/detectors/` and should expose a `check(path: Path) ->
Optional[Finding]` method. See `disguised_php.py` for the simplest reference
implementation.

## License

MIT. See [LICENSE](LICENSE).

## Author

Built and maintained by **SOMA9™ Security Team**, the security operations group
at SOMA9™ Holdings, LLC. The tool is the open-sourced version of internal
hunting checks we run across the WordPress hosting accounts we manage.

We do not accept private vulnerability reports through this repository. For
that, write to `security@soma9.cloud` (PGP key at the well-known location).

---

SOMA9™ is a trademark of SOMA9 Holdings, LLC.
