"""CLI entrypoint: `python -m wp_shell_hunter` or via the bin/ shebang script."""
import argparse
import sys
from pathlib import Path

from . import __version__
from .scanner import Scanner
from .reporter import write_text, write_json, write_summary


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wp-shell-hunter",
        description="Detect PHP webshells disguised as media files in WordPress installations.",
        epilog=(
            "License: MIT. "
            "https://github.com/SOMA9-Cloud/wp-shell-hunter\n"
            "© SOMA9™ Holdings, LLC"
        ),
    )
    p.add_argument("path", nargs="?", default=".", help="path to scan (default: cwd)")
    p.add_argument("-j", "--json", action="store_true", help="emit JSON instead of text")
    p.add_argument("-w", "--workers", type=int, default=4, help="parallel workers (default 4)")
    p.add_argument("--scan-uploads", action="store_true", help="also scan wp-content/uploads (slow, noisy)")
    p.add_argument("--follow-symlinks", action="store_true", help="follow symlinks during walk")
    p.add_argument("--no-hash", action="store_true", help="skip sha256 computation (faster)")
    p.add_argument("--no-colour", action="store_true", help="disable ANSI colours")
    p.add_argument("--quiet", "-q", action="store_true", help="suppress summary line")
    p.add_argument("--version", "-V", action="version", version=f"wp-shell-hunter {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    scanner = Scanner(
        workers=args.workers,
        follow_symlinks=args.follow_symlinks,
        scan_uploads=args.scan_uploads,
        compute_hash=not args.no_hash,
    )

    findings = list(scanner.scan(Path(args.path)))

    use_colour = sys.stdout.isatty() and not args.no_colour

    if args.json:
        write_json(findings, sys.stdout)
    else:
        write_text(findings, sys.stdout, use_colour=use_colour)
        if not args.quiet:
            write_summary(findings, scanner.files_scanned, scanner.errors, sys.stdout, use_colour=use_colour)

    # Exit code: 0 = clean, 1 = suspicious, 2 = malicious found
    if any(f.severity.value == "malicious" for f in findings):
        return 2
    if findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
