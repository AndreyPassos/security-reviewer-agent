"""Steps — features/secret_hardcoded.feature (idioma pt).

Roda o Orchestrator real sobre um diff com chave AWS hardcoded e verifica:
Finding categoria=secrets, severidade >= alto, arquivo/linha preenchidos e que o
segredo só aparece mascarado (nunca em claro) no relatório.
"""
from __future__ import annotations

import json

from pytest_bdd import given, parsers, scenario, then, when

from steps.conftest import AWS_KEY, arquivo_com_chave_aws, executar_auditoria

# Ordenação de severidade para o critério "pelo menos".
_ORDEM_SEVERIDADE = {"baixo": 0, "medio": 1, "alto": 2, "critico": 3}


@scenario("secret_hardcoded.feature", "Chave AWS hardcoded no diff")
def test_chave_aws_hardcoded_no_diff():
    pass


@scenario("secret_hardcoded.feature", "Segredo nunca exposto em claro")
def test_segredo_nunca_exposto_em_claro():
    pass


@given(parsers.parse('um diff contendo uma chave AWS hardcoded em "{arquivo}" linha {linha:d}'))
def diff_com_chave_aws(context, arquivo, linha):
    files, changed = arquivo_com_chave_aws(path=arquivo, linha=linha)
    context["files"] = files
    context["changed"] = changed
    context["paths"] = [arquivo]
    context["stack"] = ["golang"]
    context["integracoes"] = ["aws"]
    context["trace_id"] = "trace-secret-001"


@when(parsers.parse('audito o escopo "{escopo}"'))
def audito_escopo(context, escopo):
    executar_auditoria(context, escopo)


def _finding_de_secrets(report):
    return next((f for f in report.findings if f.categoria.value == "secrets"), None)


@then(parsers.parse('existe um Finding de categoria "{categoria}"'))
def existe_finding_categoria(context, categoria):
    report = context["report"]
    assert any(f.categoria.value == categoria for f in report.findings), (
        f"nenhum Finding de categoria {categoria}: {[f.categoria.value for f in report.findings]}"
    )


@then(parsers.parse('a severidade é pelo menos "{severidade}"'))
def severidade_pelo_menos(context, severidade):
    finding = _finding_de_secrets(context["report"])
    assert finding is not None
    assert _ORDEM_SEVERIDADE[finding.severidade.value] >= _ORDEM_SEVERIDADE[severidade]


@then("o Finding tem arquivo e linha preenchidos")
def finding_arquivo_e_linha(context):
    finding = _finding_de_secrets(context["report"])
    assert finding is not None
    assert finding.arquivo and finding.arquivo.strip()
    assert finding.linha >= 1


@then("o segredo aparece apenas mascarado no relatório")
def segredo_apenas_mascarado(context):
    report_json = json.dumps(context["report"].model_dump(mode="json"), ensure_ascii=False)
    assert AWS_KEY not in report_json
    assert "AKIA****" in report_json


@then("o relatório não contém o valor do segredo em claro")
def relatorio_sem_segredo_em_claro(context):
    report_json = json.dumps(context["report"].model_dump(mode="json"), ensure_ascii=False)
    assert AWS_KEY not in report_json
