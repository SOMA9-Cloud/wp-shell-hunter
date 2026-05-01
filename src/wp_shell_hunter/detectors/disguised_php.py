"""Detect PHP code inside files with media-style extensions."""
from pathlib import Path
from typing import Optional

from ..finding import Finding, Severity, Confidence


# Extensions that should never contain PHP. Order roughly by frequency observed.
MEDIA_EXTENSIONS = {
    ".tiff", ".tif",
    ".gif", ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".svg",
    ".mp4", ".m4v", ".mov", ".avi", ".flv", ".3gp", ".webm", ".mkv",
    ".mp3", ".wav", ".ogg", ".m4a",
    ".pdf",  # PDF technically can have JS but PHP magic byte at start is suspicious
    ".zip", ".tar", ".gz",  # archives shouldn't open as <?php
    ".html", ".htm",  # HTML files starting with <?php are suspicious in static contexts
    ".css", ".js",  # Asset files starting with <?php are suspicious
    ".woff", ".woff2", ".ttf", ".eot",
    ".ico",
}

# How many bytes to read at the start of file to check magic
HEADER_BYTES = 16


class DisguisedPhpDetector:
    name = "disguised_php"
    description = "PHP <?php tag in file with non-PHP media/asset extension"

    def check(self, path: Path) -> Optional[Finding]:
        ext = path.suffix.lower()
        if ext not in MEDIA_EXTENSIONS:
            return None

        try:
            with path.open("rb") as fh:
                head = fh.read(HEADER_BYTES)
        except (OSError, PermissionError):
            return None

        if not head:
            return None

        indicators = []

        # Direct PHP open tag
        if head.startswith(b"<?php"):
            indicators.append("starts_with_php_open_tag")

        # Short tag
        elif head.startswith(b"<?") and not head.startswith(b"<?xml"):
            indicators.append("starts_with_php_short_tag")

        # Whitespace then PHP
        elif head.lstrip().startswith(b"<?php"):
            indicators.append("php_tag_after_whitespace")

        if not indicators:
            return None

        # Bonus indicator: extension makes no sense
        if ext in (".tiff", ".3gp", ".flv", ".webp"):
            indicators.append("uncommon_disguise_extension")

        return Finding(
            path=str(path),
            detector=self.name,
            severity=Severity.MALICIOUS,
            confidence=Confidence.HIGH,
            indicators=indicators,
        )
