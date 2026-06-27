"""Cliente MCP (ver mcp_contract.md). Fino: delega ao registry."""
from __future__ import annotations

from src.mcp.appsec_server import DEFAULT_REGISTRY, MCPRegistry


class MCPClient:
    def __init__(self, registry: MCPRegistry | None = None):
        self.registry = registry or DEFAULT_REGISTRY

    def schema(self) -> dict:
        return self.registry.schema()

    def invoke(self, tool: str, agent_id: str, **params) -> dict:
        return self.registry.invoke(tool, agent_id, **params)
