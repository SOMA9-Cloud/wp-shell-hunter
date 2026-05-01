"""Report formatting: text and JSON output."""
import json
import sys
from typing import List, TextIO

from .finding import Finding, Severity


# ANSI colours, only used if stdout is a TTY
class C:
    RED = "\033[31m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def _colorize(text: str, colour: str, use_colour: bool) -> str:
    if not use_colour:
        return text
    return f"{colour}{text}{C.RESET}"


def write_text(findings: List[Finding], stream: TextIO, use_colour: bool = None) -> None:
    if use_colour is None:
        use_colour = stream.isatty()

    sev_colour = {
        Severity.MALICIOUS: C.RED,
        Severity.SUSPICIOUS: C.YELLOW,
        Severity.INFO: C.CYAN,
    }

    if not findings:
        stream.write(_colorize("[ok] No findings.\n", C.CYAN, use_colour))
        return

    by_severity = {Severity.MALICIOUS: [], Severity.SUSPICIOUS: [], Severity.INFO: []}
    for f in findings:
        by_severity[f.severity].append(f)

    for sev in (Severity.MALICIOUS, Severity.SUSPICIOUS, Severity.INFO):
        items = by_severity[sev]
        if not items:
            continue
        header = f"\n[{sev.value.upper()}] {len(items)} finding(s):\n"
        stream.write(_colorize(header, sev_colour[sev], use_colour))
        for f in items:
            mark = _colorize("✗", sev_colour[sev], use_colour) if sev == Severity.MALICIOUS else _colorize("!", sev_colour[sev], use_colour)
            stream.write(f"  {mark} {f.path}\n")
            stream.write(_colorize(
                f"      detector: {f.detector}  confidence: {f.confidence.value}\n",
                C.DIM, use_colour
            ))
            if f.indicators:
                stream.write(_colorize(
                    f"      indicators: {', '.join(f.indicators)}\n",
                    C.DIM, use_colour
                ))
            if f.sha256:
                stream.write(_colorize(
                    f"      sha256: {f.sha256[:16]}...\n",
                    C.DIM, use_colour
                ))


def write_json(findings: List[Finding], stream: TextIO) -> None:
    out = {"findings": [f.to_dict() for f in findings]}
    json.dump(out, stream, indent=2)
    stream.write("\n")


def write_summary(findings: List[Finding], scanned: int, errors: int, stream: TextIO, use_colour: bool = None) -> None:
    if use_colour is None:
        use_colour = stream.isatty()

    mal = sum(1 for f in findings if f.severity == Severity.MALICIOUS)
    sus = sum(1 for f in findings if f.severity == Severity.SUSPICIOUS)

    stream.write("\n" + "─" * 60 + "\n")
    stream.write(f"  Scanned: {scanned} files\n")
    stream.write(f"  Errors:  {errors}\n")
    stream.write(f"  Findings: {len(findings)}\n")
    if mal:
        stream.write(_colorize(f"    Malicious:  {mal}\n", C.RED, use_colour))
    if sus:
        stream.write(_colorize(f"    Suspicious: {sus}\n", C.YELLOW, use_colour))
