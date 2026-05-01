# Changelog

All notable changes to this project are documented here.

Maintained by SOMA9™ Security Team.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-Q2

Initial release.

### Added
- `disguised_php` detector: PHP open tag in files with media or asset extensions
  (`.tiff`, `.gif`, `.png`, `.mp4`, `.flv`, `.3gp`, `.jpg`, `.webp`, `.zip`, etc.)
- `doubled_directory` detector: attacker-created `foo/foo/` and deeper nesting
  patterns (`maint/maint/maint/`, `cgi-bin/cgi-bin/cgi-bin/`), with whitelist for
  legitimate PSR-4 PHP namespacing.
- `obfuscation` detector: `goto`-statement spaghetti density, quadruple-nested
  `md5()` password gating, indirect `$VAR[$idx]` execution, hex-escape alphabet
  build patterns.
- Multi-threaded filesystem walker (configurable workers).
- JSON and human-readable text output.
- Standard exit codes (`0` clean, `1` suspicious, `2` malicious) for CI/CD.
- Bundled launcher script with no install required (curl-pipe-bash deployable).
- `--no-hash` mode for high-throughput scanning.
- Configurable skip-list for known noisy directories (uploads, vendor, node_modules).
