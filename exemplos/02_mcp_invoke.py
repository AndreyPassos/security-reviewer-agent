"""Exemplo — invocação MCP conforme mcp_contract.md.

Demonstra discovery + invocação de tool read-only com whitelist por agente.
A implementação de src/mcp/ é o próximo passo (ver README › Próximos passos).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.mcp.client import MCPClient  # noqa: E402 (implementar em src/mcp/)

client = MCPClient()
schema = client.schema()
print(f"Protocolo: {schema['protocol']}, domínio: {schema['domain']}, tools: {len(schema['tools'])}")

# Agente autorizado invoca scanner read-only:
resp = client.invoke(
    "secret_scan",
    "SecurityReviewerAgent",
    repo_path="./alvo",
    paths=["config/aws.go"],
    trace_id="trace-demo-001",
)
print("secret_scan ok:", resp["ok"], "— segredos:", len(resp["result"]))

# Agente fora da whitelist é recusado:
negado = client.invoke("secret_scan", "AgenteDesconhecido", repo_path="./alvo", trace_id="t2")
print("esperado TOOL_NAO_AUTORIZADA →", negado["error"])
