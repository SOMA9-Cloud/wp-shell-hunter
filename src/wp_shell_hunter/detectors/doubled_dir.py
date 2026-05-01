"""Detect attacker-created doubled directory pattern (foo/foo/, foo/foo/foo/)."""
import re
from pathlib import Path
from typing import Optional, Set

from ..finding import Finding, Severity, Confidence


# Legitimate doubled-directory patterns from popular PHP libraries.
# These are class organization patterns (e.g. PSR-4 autoloader paths).
# Whitelist them to avoid false positives.
LEGITIMATE_DOUBLED = re.compile(
    r"/(ID3|SimplePie|Requests|HTTP|Proxy|Cache|Cookie|Auth|Mock|Iri|Hooks|"
    r"Encoder|Polyfill|Mime|Curve|Field|Group|Modular|Extension|Util|Format|"
    r"TestCase|Parser|Sanitize|Strainer|Validator|Misc|Item|Source|Decoder|"
    r"phpseclib|Net|File|Math|Crypt|System|Exception|Stream)/\1(/|$)"
)

# Suspicious doubled patterns (attacker convention).
SUSPICIOUS_DOUBLED = re.compile(
    r"/(maint|images|cgi-bin|shop|css|widgets|user|network|includes|"
    r"term-template|categories|imgareaselect|wpview|finder|theme-compat|"
    r"html-api|colors|coffee|ectoplasm|midnight|js|admin|assets|core|"
    r"importer|importer|repositories|comments|taxonomy|style-engine|"
    r"php-compat|api|library|libs)/\1(/|$)"
)


class DoubledDirDetector:
    name = "doubled_directory"
    description = "Attacker-created doubled directory pattern (e.g. /maint/maint/)"

    def check(self, path: Path) -> Optional[Finding]:
        s = str(path)
        # Skip legitimate library doubled dirs (PSR-4 namespacing etc.)
        if LEGITIMATE_DOUBLED.search(s):
            return None
        if not SUSPICIOUS_DOUBLED.search(s):
            return None

        # Find the longest run of consecutive identical directory components.
        parts = path.parts
        max_run = 1
        current_run = 1
        run_name = ""
        for i in range(1, len(parts)):
            if parts[i] == parts[i - 1]:
                current_run += 1
                if current_run > max_run:
                    max_run = current_run
                    run_name = parts[i]
            else:
                current_run = 1

        if max_run < 2:
            # Regex matched but parts analysis disagrees — be conservative.
            match = SUSPICIOUS_DOUBLED.search(s)
            run_name = match.group(1)
            max_run = 2

        indicators = [f"doubled_dir:{run_name}:{max_run}x"]
        if max_run >= 3:
            indicators.append(f"deep_nesting:{max_run}")

        confidence = Confidence.MEDIUM
        if max_run >= 3:
            confidence = Confidence.HIGH

        return Finding(
            path=str(path),
            detector=self.name,
            severity=Severity.SUSPICIOUS,
            confidence=confidence,
            indicators=indicators,
        )
