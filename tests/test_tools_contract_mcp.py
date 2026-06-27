"""Testes do contrato MCP (discovery + whitelist + erros).

Exercitam apenas a mecânica do registry/cliente: discovery, gate de whitelist e
tabela de erros. NÃO invocam os scanners (cujos corpos podem ainda lançar
NotImplementedError) — o gate de autorização e a checagem de existência da tool
ocorrem ANTES de qualquer handler ser chamado.
"""
from __future__ import annotations

from src.mcp.client import MCPClient
from src.mcp.errors import ERROR_CODES

EXPECTED_TOOLS = {"diff_collector", "code_search", "dependency_scan", "secret_scan"}
EXPECTED_ERROR_CODES = {
    "TOOL_NAO_ENCONTRADA",
    "TOOL_NAO_AUTORIZADA",
    "ENTRADA_INVALIDA",
    "INJECAO_DETECTADA",
    "PII_EXPOSTO",
    "HITL_OBRIGATORIO",
}


def test_schema_tem_4_tools_e_protocolo():
    schema = MCPClient().schema()
    assert schema["protocol"] == "mcp-mock/1.0"
    assert schema["domain"] == "appsec-review"
    assert len(schema["tools"]) == 4
    assert set(schema["tools"]) == EXPECTED_TOOLS


def test_invoke_agente_fora_whitelist_retorna_nao_autorizada():
    # Tool existe, mas o agente não está na whitelist → gate barra antes do handler.
    resp = MCPClient().invoke("code_search", "AgenteNaoAutorizado", padrao="x")
    assert resp["ok"] is False
    assert resp["result"] is None
    assert resp["error"] == "TOOL_NAO_AUTORIZADA"


def test_invoke_tool_inexistente_retorna_nao_encontrada():
    resp = MCPClient().invoke("tool_que_nao_existe", "SecurityReviewerAgent")
    assert resp["ok"] is False
    assert resp["result"] is None
    assert resp["error"] == "TOOL_NAO_ENCONTRADA"


def test_error_codes_tem_os_6_codigos():
    assert len(ERROR_CODES) == 6
    assert set(ERROR_CODES) == EXPECTED_ERROR_CODES
