from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

SEVERITIES = ["low", "medium", "high", "critical"]


def severity_rank(name: str) -> int:
    return SEVERITIES.index(name)


@dataclass
class Event:
    ts: datetime
    ip: str
    kind: str
    raw: str
    user: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    agent: Optional[str] = None


@dataclass
class Finding:
    rule: str
    severity: str
    ip: str
    count: int
    first_seen: datetime
    last_seen: datetime
    summary: str
    mitre: str
    evidence: List[str] = field(default_factory=list)
