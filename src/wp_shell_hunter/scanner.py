"""Filesystem scanner: walks a tree, runs detectors on each file."""
import hashlib
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterator, List

from .detectors import ALL_DETECTORS
from .finding import Finding


# Skip these dirs entirely (huge or known-clean)
SKIP_DIRS = {
    "node_modules", ".git", ".svn", ".hg",
    "__pycache__", "vendor",
    "uploads",  # WP user uploads — too noisy. Configurable via flag.
    ".cache", "cache",
    "logs", "log",
    ".trash", ".Trash",
}

# Don't bother on files larger than this (webshells are tiny)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB


def _walk_files(root: Path, follow_symlinks: bool, scan_uploads: bool) -> Iterator[Path]:
    """Yield every file under root, skipping irrelevant directories."""
    skip = SKIP_DIRS.copy()
    if scan_uploads:
        skip.discard("uploads")

    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        # In-place prune
        dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".cagefs-")]
        for fn in filenames:
            p = Path(dirpath) / fn
            yield p


def _hash_file(path: Path) -> str:
    """Compute SHA256 of file. Returns empty string on error."""
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


def _scan_one(path: Path, compute_hash: bool) -> List[Finding]:
    """Run all detectors on a single file. Returns findings (possibly empty)."""
    try:
        size = path.stat().st_size
    except OSError:
        return []

    if size > MAX_FILE_SIZE:
        return []

    findings = []
    for det in ALL_DETECTORS:
        try:
            f = det.check(path)
        except Exception:  # noqa: BLE001 - one detector blowing up shouldn't kill scan
            continue
        if f is not None:
            f.size = size
            findings.append(f)

    # Hash only if we have at least one finding (saves IO)
    if findings and compute_hash:
        h = _hash_file(path)
        for f in findings:
            f.sha256 = h

    return findings


class Scanner:
    def __init__(
        self,
        workers: int = 4,
        follow_symlinks: bool = False,
        scan_uploads: bool = False,
        compute_hash: bool = True,
    ):
        self.workers = max(1, workers)
        self.follow_symlinks = follow_symlinks
        self.scan_uploads = scan_uploads
        self.compute_hash = compute_hash
        self.files_scanned = 0
        self.errors = 0

    def scan(self, root: Path) -> Iterator[Finding]:
        """Scan a directory tree. Yields findings as they're discovered."""
        root = Path(root).resolve()
        if not root.exists():
            print(f"[!] path does not exist: {root}", file=sys.stderr)
            return
        if root.is_file():
            for f in _scan_one(root, self.compute_hash):
                self.files_scanned += 1
                yield f
            return

        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            in_flight = {}
            for path in _walk_files(root, self.follow_symlinks, self.scan_uploads):
                fut = ex.submit(_scan_one, path, self.compute_hash)
                in_flight[fut] = path

                # Bound the queue so we don't load the whole tree into RAM
                if len(in_flight) >= self.workers * 8:
                    for done in as_completed(list(in_flight)):
                        self.files_scanned += 1
                        try:
                            for finding in done.result():
                                yield finding
                        except Exception:
                            self.errors += 1
                        del in_flight[done]
                        if len(in_flight) < self.workers * 4:
                            break

            # Drain
            for done in as_completed(in_flight):
                self.files_scanned += 1
                try:
                    for finding in done.result():
                        yield finding
                except Exception:
                    self.errors += 1
