"""Detection modules. Each detector returns a Finding (or None) per file."""
from .disguised_php import DisguisedPhpDetector
from .doubled_dir import DoubledDirDetector
from .obfuscation import ObfuscationDetector

ALL_DETECTORS = [
    DisguisedPhpDetector(),
    DoubledDirDetector(),
    ObfuscationDetector(),
]
