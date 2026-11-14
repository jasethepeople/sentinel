from sentinel.agents.base import TaskSpec, WorkerAgent
from sentinel.models.tools import ToolRequest


class VerifyAgent(WorkerAgent):
    def plan(self, task: TaskSpec) -> list[ToolRequest]:
        return [ToolRequest(tool_name="simulate_verification", target=task.target, principal_id=task.principal_id)]
