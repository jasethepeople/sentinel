from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from sentinel.models.tools import ToolRequest


@dataclass(frozen=True)
class TaskSpec:
    target: str
    principal_id: str = "cli-operator"


class WorkerAgent(ABC):
    @abstractmethod
    def plan(self, task: TaskSpec) -> list[ToolRequest]:
        """Return requests for the protected gateway; workers never execute tools."""
