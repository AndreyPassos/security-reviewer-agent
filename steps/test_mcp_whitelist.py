"""Steps — features/mcp_whitelist.feature (idioma pt).

Mecânica do registry MCP: discovery (4 tools + protocolo), gate de whitelist
(TOOL_NAO_AUTORIZADA) e tool inexistente (TOOL_NAO_ENCONTRADA). Usa a factory
real (build_default_registry → MCPClient → Orchestrator) via o client do pipeline.
"""
from __future__ import annotations

from pytest_bdd import given, parsers, scenario, then, when

from steps.conftest import montar_pipeline


@scenario("mcp_whitelist.feature", "Discovery expõe as 4 tools")
def test_discovery_expoe_4_tools():
    pass


@scenario("mcp_whitelist.feature", "Agente fora da whitelist é recusado")
def test_agente_fora_da_whitelist():
    pass


@scenario("mcp_whitelist.feature", "Tool inexistente é recusada")
def test_tool_inexistente():
    pass


def _client():
    # A factory monta InMemoryRepo → registry → MCPClient → Orchestrator;
    # aqui usamos o client já ligado ao registry.
    _repo, orchestrator = montar_pipeline()
    return orchestrator.client


# ───────────────── Cenário 1: discovery ─────────────────

@given(parsers.parse('o servidor MCP "{dominio}"'))
def servidor_mcp(context, dominio):
    context["client"] = _client()
    context["dominio"] = dominio


@when("consulto o discovery")
def consulto_discovery(context):
    context["schema"] = context["client"].schema()


@then("existem 4 tools registradas")
def existem_4_tools(context):
    assert len(context["schema"]["tools"]) == 4


@then(parsers.parse('o protocolo é "{protocolo}"'))
def protocolo_e(context, protocolo):
    assert context["schema"]["protocol"] == protocolo


# ───────────────── Cenários 2 e 3: whitelist / tool inexistente ─────────────────

@given(parsers.parse('um agente "{agente}" fora da whitelist'))
def agente_fora_da_whitelist(context, agente):
    context["client"] = _client()
    context["agente"] = agente


@given(parsers.parse('o agente "{agente}"'))
def agente_autorizado(context, agente):
    context["client"] = _client()
    context["agente"] = agente


@when(parsers.parse('ele invoca a tool "{tool}"'))
def invoca_tool(context, tool):
    context["resposta"] = context["client"].invoke(
        tool, context["agente"], trace_id="trace-wl-001"
    )


@then(parsers.parse('a resposta indica "{codigo}"'))
def resposta_indica(context, codigo):
    assert context["resposta"]["ok"] is False
    assert context["resposta"]["error"] == codigo
