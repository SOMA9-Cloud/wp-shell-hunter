"""Detect obfuscation techniques typical of webshell families.

Patterns observed:
- goto-statement spaghetti (heavy goto density)
- quadruple-nested md5() password gating
- range() to build alphabet, then index by integers
- variable variable indirection $VAR[$idx]
- eval() of curl_exec result
"""
import re
from pathlib import Path
from typing import Optional

from ..finding import Finding, Severity, Confidence


# Compiled patterns
GOTO_PATTERN = re.compile(rb"goto\s+[A-Za-z_][A-Za-z0-9_]{4,}\s*;")
QUAD_MD5 = re.compile(rb"md5\s*\(\s*md5\s*\(\s*md5\s*\(\s*md5\s*\(")
TRIPLE_MD5 = re.compile(rb"md5\s*\(\s*md5\s*\(\s*md5\s*\(")
EVAL_CHAIN = re.compile(
    rb"@?\s*eval\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\[\s*\d+\s*[+]?\s*\d*\s*\]"
)
RANGE_ALPHABET = re.compile(rb"\$[A-Za-z_]\w*\s*=\s*\"\\(?:x72|142|x6e)\".*\\(?:x67|151|145)")
HEX_STRING_BUILD = re.compile(rb"explode\s*\(\s*\"\\(?:x[0-9a-f]{2}|\d{1,3})\"")
CURL_EVAL = re.compile(rb"eval\s*\([^)]{0,200}curl_exec", re.DOTALL)
INDIRECT_VAR = re.compile(rb"\$\{?\$[A-Za-z_]\w*\s*\[\s*\d+\s*[+]?\s*\d*\s*\]")

MAX_READ = 256 * 1024  # 256KB cap; webshells are tiny


class ObfuscationDetector:
    name = "obfuscation"
    description = "PHP obfuscation patterns (goto-spaghetti, quad-md5, eval(curl_exec), etc.)"

    def check(self, path: Path) -> Optional[Finding]:
        # Only inspect files that actually look like text (skip binaries, large media)
        try:
            size = path.stat().st_size
        except OSError:
            return None
        if size == 0 or size > 5 * 1024 * 1024:  # skip empty or > 5MB
            return None

        try:
            with path.open("rb") as fh:
                data = fh.read(MAX_READ)
        except (OSError, PermissionError):
            return None

        # Quick reject: no PHP open tag → not interesting
        if b"<?php" not in data and b"<?=" not in data:
            return None

        indicators = []
        score = 0

        goto_count = len(GOTO_PATTERN.findall(data))
        if goto_count >= 5:
            indicators.append(f"goto_spaghetti:{goto_count}")
            score += 3
        elif goto_count >= 2:
            indicators.append(f"goto_present:{goto_count}")
            score += 1

        if QUAD_MD5.search(data):
            indicators.append("quad_md5_gate")
            score += 4
        elif TRIPLE_MD5.search(data):
            indicators.append("triple_md5_gate")
            score += 3

        if EVAL_CHAIN.search(data):
            indicators.append("eval_indirect_var")
            score += 3

        if INDIRECT_VAR.search(data):
            indicators.append("variable_variable_indirection")
            score += 1

        if RANGE_ALPHABET.search(data) or HEX_STRING_BUILD.search(data):
            indicators.append("hex_alphabet_build")
            score += 2

        if CURL_EVAL.search(data):
            indicators.append("curl_exec_eval_chain")
            score += 4

        if score < 3:
            return None

        confidence = Confidence.LOW
        if score >= 7:
            confidence = Confidence.HIGH
        elif score >= 4:
            confidence = Confidence.MEDIUM

        return Finding(
            path=str(path),
            detector=self.name,
            severity=Severity.MALICIOUS if score >= 6 else Severity.SUSPICIOUS,
            confidence=confidence,
            indicators=indicators,
        )
