"""Testes dos contratos Pydantic (src/schemas.py) e do schema canônico JSON.

Não dependem dos scanners MCP — exercitam apenas a validação dos modelos e o
arquivo schemas/schemas.json.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.schemas import (
    AuditReport,
    Categoria,
    Escopo,
    Finding,
    NivelSeguranca,
    ResumoSeveridade,
    Severidade,
)

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "schemas.json"


def _finding_kwargs(**overrides) -> dict:
    """kwargs de um Finding válido; `overrides` permite invalidar um campo."""
    base = dict(
        id="SEC-001",
        titulo="SQL Injection no login",
        categoria=Categoria.DB,
        severidade=Severidade.CRITICO,
        arquivo="src/auth/login.py",
        linha=42,
        evidencia="query = 'SELECT * FROM users WHERE name=' + nome",
        impacto="Permite extração arbitrária da base de dados",
        correcao="Usar query parametrizada / prepared statements",
        owasp="A03:2021",
        confianca=0.95,
        trace_id="trace-abc-123",
    )
    base.update(overrides)
    return base


def _audit_report() -> AuditReport:
    return AuditReport(
        trace_id="trace-abc-123",
        escopo=Escopo.DIFF,
        resumo=ResumoSeveridade(critico=1, alto=0, medio=0, baixo=0),
        nivel_seguranca=NivelSeguranca.ALTO,
        findings=[Finding(**_finding_kwargs())],
        top_riscos=["SEC-001"],
        hitl_pendente=False,
        observacoes="auditoria de exemplo",
    )


def test_finding_round_trip_valido():
    f = Finding(**_finding_kwargs())
    # Round-trip via dict (modo Python).
    assert Finding(**f.model_dump()) == f
    # Round-trip via JSON (enums viram string e voltam).
    assert Finding.model_validate_json(f.model_dump_json()) == f


def test_audit_report_round_trip_valido():
    report = _audit_report()
    # Round-trip via dict, incluindo modelos aninhados (resumo, findings).
    assert AuditReport.model_validate(report.model_dump()) == report
    # Round-trip via JSON.
    assert AuditReport.model_validate_json(report.model_dump_json()) == report


def test_finding_evidencia_vazia_falha():
    with pytest.raises(ValidationError):
        Finding(**_finding_kwargs(evidencia=""))


def test_finding_linha_zero_falha():
    with pytest.raises(ValidationError):
        Finding(**_finding_kwargs(linha=0))


def test_schemas_json_e_json_valido_com_defs_audit_report():
    data = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert "$defs" in data
    assert "AuditReport" in data["$defs"]
