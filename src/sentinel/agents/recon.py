from sentinel.agents.base import TaskSpec, WorkerAgent
from sentinel.models.tools import ToolRequest


class ReconAgent(WorkerAgent):
    def plan(self, task: TaskSpec) -> list[ToolRequest]:
        return [
            ToolRequest(tool_name=name, target=task.target, principal_id=task.principal_id)
            for name in ("simulate_asset_inventory", "simulate_service_inventory")
        ]
