"""Steps — features/schema_validation.feature (idioma pt).

Guardrail de saída GR-SEC02 (fail-closed): toda saída fora do contrato
AuditReport para o pipeline com GuardrailViolation(SCHEMA_INVALIDO).

Cenário 1: AuditReport sem o campo obrigatório "resumo".
Cenário 2: "resumo" incoerente com os findings. Como uma contagem por severidade
nunca pode ser negativa, um "resumo" com contagem negativa é, ao mesmo tempo,
incoerente com qualquer lista de findings E rejeitado pelo schema
(minimum: 0) — então validate_report_schema falha-fechado com SCHEMA_INVALIDO.
"""
from __future__ import annotations

import copy

from pytest_bdd import given, parsers, scenario, then, when

from src import guardrails
from src.guardrails import GuardrailViolation


@scenario("schema_validation.feature", "Saída fora do schema AuditReport")
def test_saida_fora_do_schema():
    pass


@scenario("schema_validation.feature", "score de severidade incoerente com findings")
def test_score_incoerente_com_findings():
    pass


def _report_valido() -> dict:
    """AuditReport mínimo e válido contra schemas.json (ponto de partida)."""
    return {
        "trace_id": "trace-schema-001",
        "escopo": "diff",
        "resumo": {"critico": 0, "alto": 0, "medio": 0, "baixo": 0},
        "nivel_seguranca": "alto",
        "findings": [],
        "top_riscos": [],
        "hitl_pendente": False,
    }


@given(parsers.parse('um AuditReport sem o campo obrigatório "{campo}"'))
def report_sem_campo(context, campo):
    report = _report_valido()
    report.pop(campo, None)
    context["report_dict"] = report


@given(parsers.parse('um AuditReport cujo "{campo}" não bate com a lista de findings'))
def report_com_resumo_incoerente(context, campo):
    report = _report_valido()
    # findings vazio, mas o resumo declara contagem negativa: impossível de bater
    # com qualquer lista de findings e rejeitado pelo schema (minimum: 0).
    report[campo] = {"critico": -1, "alto": 0, "medio": 0, "baixo": 0}
    context["report_dict"] = report


@when("os guardrails de saída são aplicados")
def aplica_guardrails_saida(context):
    context["violacao"] = None
    context["pipeline_parou"] = False
    try:
        guardrails.validate_report_schema(copy.deepcopy(context["report_dict"]))
    except GuardrailViolation as exc:
        context["violacao"] = exc.code
        context["pipeline_parou"] = True


@then(parsers.parse('a resposta indica "{codigo}"'))
def resposta_indica(context, codigo):
    assert context["violacao"] == codigo


@then("o pipeline para (fail-closed)")
def pipeline_para(context):
    assert context["pipeline_parou"] is True
