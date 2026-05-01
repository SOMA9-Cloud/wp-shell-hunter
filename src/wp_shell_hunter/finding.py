"""Finding dataclass: one suspicious file = one Finding."""
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import List


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Severity(str, Enum):
    INFO = "info"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass
class Finding:
    path: str
    detector: str
    severity: Severity
    confidence: Confidence
    indicators: List[str] = field(default_factory=list)
    sha256: str = ""
    size: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d
