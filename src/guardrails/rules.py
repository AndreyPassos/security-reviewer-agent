"""Guardrails fail-closed Pre/Post (ver guardrails_contract.md).

Mecânica a implementar. Assinaturas e contrato de comportamento abaixo são
FIXOS — orquestrador e steps dependem deles. Não altere nomes nem assinaturas.
"""
from __future__ import annotations

import json
import os
import re
from typing import Optional

from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match

from src.guardrails.violations import (
    CONFIANCA_BAIXA,
    CONFIANCA_MINIMA,
    ENTRADA_INVALIDA,
    ESCOPO_PROIBIDO,
    GuardrailViolation,
    PII_EXPOSTO,
    SCHEMA_INVALIDO,
)
from src.schemas import AuditInput, AuditReport, Finding
from src.schemas import NivelSeguranca, ResumoSeveridade

_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "schemas", "schemas.json")


def pre(agent_id: str, audit_input: AuditInput) -> None:
    """Guardrails de entrada. Levanta GuardrailViolation em falha.

    - trace_id ausente/vazio → ENTRADA_INVALIDA
    - agent_id diferente de "SecurityReviewerAgent" → ESCOPO_PROIBIDO
    """
    if isinstance(audit_input, dict):
        trace_id = audit_input.get("trace_id")
    else:
        trace_id = getattr(audit_input, "trace_id", None)
    if trace_id is None or not str(trace_id).strip():
        raise GuardrailViolation(ENTRADA_INVALIDA, "trace_id ausente ou vazio")
    if agent_id != "SecurityReviewerAgent":
        raise GuardrailViolation(ESCOPO_PROIBIDO, f"agente nao autorizado: {agent_id}")


def assert_read_only(action: str) -> None:
    """GR-SEC04. Levanta ESCOPO_PROIBIDO se `action` for escrita/commit/exec.

    Bloquear ações que começam com: write:, edit:, commit, exec:, delete:, rm .
    Leitura (read:, search:, scan:) é permitida.
    """
    alvo = (action or "").strip().lower()
    bloqueadas = ("write:", "edit:", "commit", "exec:", "delete:", "rm ")
    if alvo.startswith(bloqueadas):
        raise GuardrailViolation(ESCOPO_PROIBIDO, f"acao de escrita bloqueada: {action}")


def avaliar_finding(finding) -> Optional[str]:
    """GR-SEC01. Retorna código de violação se o Finding deve ser descartado, senão None.

    Descartar (→ "CONFIANCA_BAIXA") quando faltar evidência: `evidencia` vazia,
    `arquivo` vazio, `linha` < 1, ou `confianca` < CONFIANCA_MINIMA.
    Aceita Finding (pydantic) ou dict.
    """
    if isinstance(finding, dict):
        evidencia = finding.get("evidencia", "")
        arquivo = finding.get("arquivo", "")
        linha = finding.get("linha", 0)
        confianca = finding.get("confianca", 0.0)
    else:
        evidencia = getattr(finding, "evidencia", "")
        arquivo = getattr(finding, "arquivo", "")
        linha = getattr(finding, "linha", 0)
        confianca = getattr(finding, "confianca", 0.0)

    if evidencia is None or not str(evidencia).strip():
        return CONFIANCA_BAIXA
    if arquivo is None or not str(arquivo).strip():
        return CONFIANCA_BAIXA
    try:
        if int(linha) < 1:
            return CONFIANCA_BAIXA
    except (TypeError, ValueError):
        return CONFIANCA_BAIXA
    try:
        if float(confianca) < CONFIANCA_MINIMA:
            return CONFIANCA_BAIXA
    except (TypeError, ValueError):
        return CONFIANCA_BAIXA
    return None


def filtrar_sem_evidencia(findings: list) -> tuple:
    """Retorna (mantidos, descartados) aplicando avaliar_finding a cada item."""
    mantidos = []
    descartados = []
    for finding in findings:
        if avaliar_finding(finding) is None:
            mantidos.append(finding)
        else:
            descartados.append(finding)
    return mantidos, descartados


def validate_report_schema(report_dict: dict) -> None:
    """GR-SEC02. Valida `report_dict` contra #/$defs/AuditReport de schemas.json.

    Inválido → GuardrailViolation(SCHEMA_INVALIDO). Usar jsonschema (Draft 2020-12).
    """
    with open(_SCHEMA_PATH, encoding="utf-8") as fh:
        doc = json.load(fh)
    # $ref resolvido contra o próprio documento (que carrega os $defs).
    schema = {"$ref": "#/$defs/AuditReport", **doc}
    validator = Draft202012Validator(schema)
    erro = best_match(validator.iter_errors(report_dict))
    if erro is not None:
        raise GuardrailViolation(SCHEMA_INVALIDO, f"AuditReport invalido: {erro.message}")


def post(agent_id: str, report: AuditReport) -> AuditReport:
    """Guardrails de saída (fail-closed). Retorna AuditReport saneado.

    Ordem:
    1. Descartar findings sem evidência (filtrar_sem_evidencia) — GR-SEC01.
    2. Recalcular `resumo` por severidade a partir dos findings mantidos.
    3. Checar PII em claro nas evidências (ex.: chave AWS não-mascarada
       `AKIA[0-9A-Z]{16}`) → GuardrailViolation(PII_EXPOSTO) — GR-SEC03.
    4. Se algum Finding crítico tiver confianca < CONFIANCA_MINIMA → hitl_pendente=True (GR-SEC05).
    5. Validar o dict final contra o schema (validate_report_schema) — GR-SEC02/07.
    Retorna o report saneado (pydantic AuditReport).
    """
    # Normalizar para AuditReport (aceita pydantic AuditReport OU dict).
    if isinstance(report, AuditReport):
        rpt = report.model_copy(deep=True)
    else:
        try:
            rpt = AuditReport.model_validate(report)
        except Exception as exc:  # dict malformado → fail-closed
            raise GuardrailViolation(SCHEMA_INVALIDO, f"AuditReport invalido: {exc}")

    findings_originais = list(rpt.findings)

    # 1. Descartar findings sem evidencia / confianca baixa (GR-SEC01).
    mantidos, _descartados = filtrar_sem_evidencia(findings_originais)
    rpt.findings = mantidos

    # 2. Recalcular resumo por severidade a partir dos findings mantidos (GR-SEC07).
    contagem = {"critico": 0, "alto": 0, "medio": 0, "baixo": 0}
    for finding in mantidos:
        chave = finding.severidade.value
        if chave in contagem:
            contagem[chave] += 1
    rpt.resumo = ResumoSeveridade(**contagem)

    # 2b. Coerência derivada dos findings, NÃO confiada ao agente/LLM (GR-SEC07).
    if contagem["critico"] > 0:
        rpt.nivel_seguranca = NivelSeguranca.BAIXO
    elif contagem["alto"] > 0:
        rpt.nivel_seguranca = NivelSeguranca.MEDIO
    else:
        rpt.nivel_seguranca = NivelSeguranca.ALTO
    rpt.top_riscos = [f.id for f in mantidos if f.severidade.value in ("critico", "alto")]

    # 3. PII em claro na evidencia: chave AWS nao-mascarada (GR-SEC03).
    aws_key = re.compile(r"AKIA[0-9A-Z]{16}")
    for finding in mantidos:
        if aws_key.search(finding.evidencia or ""):
            raise GuardrailViolation(
                PII_EXPOSTO,
                f"chave AWS em claro na evidencia do finding {finding.id}",
            )

    # 4. Finding critico com confianca baixa exige revisao humana (GR-SEC05).
    for finding in findings_originais:
        if finding.severidade.value == "critico" and float(finding.confianca) < CONFIANCA_MINIMA:
            rpt.hitl_pendente = True
            break

    # 5. Validar o dict final contra o schema (GR-SEC02/07).
    validate_report_schema(rpt.model_dump(mode="json", exclude_none=True))

    return rpt
