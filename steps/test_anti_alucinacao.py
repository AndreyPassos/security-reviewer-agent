"""Steps — features/anti_alucinacao.feature (idioma pt).

Cenário 1: Finding sem evidência é descartado por GR-SEC01 (CONFIANCA_BAIXA).
Cenário 2: repositório limpo → o agente não inventa findings (lista vazia) e
nivel_seguranca coerente com zero findings.
"""
from __future__ import annotations

from pytest_bdd import given, parsers, scenario, then, when

from src import guardrails
from steps.conftest import executar_auditoria


@scenario("anti_alucinacao.feature", "Finding sem evidência é descartado")
def test_finding_sem_evidencia_descartado():
    pass


@scenario("anti_alucinacao.feature", "Projeto limpo não gera achado inventado")
def test_projeto_limpo_nao_inventa():
    pass


# ───────────────── Cenário 1: anti-alucinação por evidência ─────────────────

@given(parsers.parse('um Finding candidato sem o campo "{campo}"'))
def finding_sem_campo(context, campo):
    # Finding válido em todos os campos EXCETO o ausente ("evidencia"), para
    # isolar a regra GR-SEC01 (descarte por falta de evidência).
    finding = {
        "id": "SEC-099",
        "titulo": "SQL injection suspeita",
        "categoria": "db",
        "severidade": "alto",
        "arquivo": "internal/db/user.go",
        "linha": 7,
        "evidencia": "SELECT * FROM users WHERE id = " + "'" + "?" + "'",
        "impacto": "Possível injeção.",
        "correcao": "Usar prepared statements.",
        "confianca": 0.9,
        "trace_id": "trace-halluc-001",
    }
    finding.pop(campo, None)
    context["finding"] = finding


@when("os guardrails de saída são aplicados")
def aplica_guardrails_saida(context):
    context["violacao"] = guardrails.avaliar_finding(context["finding"])


@then(parsers.parse('o Finding é descartado pela regra "{regra}"'))
def finding_descartado_pela_regra(context, regra):
    # GR-SEC01: avaliar_finding retorna um código (≠ None) quando o Finding é descartado.
    assert context["violacao"] is not None, f"Finding NÃO foi descartado pela regra {regra}"


@then(parsers.parse('a violação registrada é "{codigo}"'))
def violacao_registrada(context, codigo):
    assert context["violacao"] == codigo


# ───────────────── Cenário 2: projeto limpo, sem achados ─────────────────

@given("um repositório sem vulnerabilidades conhecidas")
def repositorio_limpo(context):
    context["files"] = {}
    context["changed"] = None
    context["paths"] = []
    context["stack"] = ["golang", "react"]
    context["trace_id"] = "trace-limpo-001"


@when(parsers.parse('audito o escopo "{escopo}"'))
def audito_escopo(context, escopo):
    executar_auditoria(context, escopo)


@then("a lista de findings está vazia")
def lista_findings_vazia(context):
    assert context["report"].findings == []


@then("o nivel_seguranca é coerente com zero findings")
def nivel_seguranca_coerente(context):
    report = context["report"]
    # Zero findings → nenhum risco → nivel_seguranca "alto".
    assert report.findings == []
    assert report.nivel_seguranca.value == "alto"
