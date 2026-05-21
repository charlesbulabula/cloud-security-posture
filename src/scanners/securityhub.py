from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    SUCCEEDED = "succeeded"
    FAILED    = "failed"


@dataclass
class Job:
    id: str
    name: str
    status: Status = Status.PENDING
    retries: int = 0
    metadata: dict = field(default_factory=dict)

    def mark_running(self) -> None:
        self.status = Status.RUNNING

    def mark_done(self) -> None:
        self.status = Status.SUCCEEDED

    def mark_failed(self) -> None:
        self.status = Status.FAILED
        self.retries += 1

# rev 20260518164406-936783f3
