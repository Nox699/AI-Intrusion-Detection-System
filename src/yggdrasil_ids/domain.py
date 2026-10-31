"""Small immutable domain objects shared by the collector and detectors."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class SSHEvent:
    event_id: str
    timestamp: float
    source_ip: str
    username: str
    outcome: str
    auth_method: str
    host: str = ""
    message: str = ""
    pid: str = ""
    cursor: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ParseResult:
    status: str
    event: SSHEvent | None = None
    reason: str = ""


@dataclass(frozen=True)
class Finding:
    detector_id: str
    title: str
    severity: str
    reason: str
    source_ip: str
    event_id: str
    timestamp: float
    details: dict[str, Any] = field(default_factory=dict)
    score: float | None = None
    model_version: str | None = None
