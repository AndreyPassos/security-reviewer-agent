"""Fixtures e helpers compartilhados dos steps pytest-bdd (5 features).

Tudo determinístico (sem rede, sem LLM, sem aleatoriedade). A factory liga a
implementação real: InMemoryRepo → build_default_registry(repo) → MCPClient(registry)
→ Orchestrator(client). Os steps de cada feature consomem essas peças via o
dicionário `context` (estado mutável por cenário).
"""
from __future__ import annotations

import pytest

from src.mcp.appsec_server import build_default_registry
from src.mcp.client import MCPClient
from src.mcp.repo import InMemoryRepo
from src.orquestracao.pipeline import Orchestrator
from src.schemas import AuditInput

# Chave AWS de exemplo (casa o regex AKIA[0-9A-Z]{16} do secret_scan).
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def montar_pipeline(files: dict | None = None, changed=None):
    """Factory determinística do pipeline real.

    InMemoryRepo(files, changed) → build_default_registry(repo) → MCPClient(registry)
    → Orchestrator(client). Retorna (repo, orchestrator) já ligados.
    """
    repo = InMemoryRepo(files=files or {}, changed=changed)
    registry = build_default_registry(repo)
    client = MCPClient(registry)
    orchestrator = Orchestrator(client)
    return repo, orchestrator


def arquivo_com_chave_aws(path: str = "config/aws.go", linha: int = 12):
    """Cria um arquivo onde a chave AWS cai EXATAMENTE em `linha` (1-based).

    secret_scan enumera as linhas com start=1, então preenchemos `linha-1` linhas
    antes e cravamos a chave na `linha`. Retorna (files, changed) prontos para a
    factory.
    """
    preenchimento = [f"// linha {i} de {path}" for i in range(1, linha)]
    codigo = f'const awsKey = "{AWS_KEY}" // credencial hardcoded'
    conteudo = "\n".join(preenchimento + [codigo])
    files = {path: conteudo}
    changed = {path: "modified"}
    return files, changed


def executar_auditoria(context: dict, escopo: str):
    """Monta o pipeline a partir do `context` e roda o Orchestrator real.

    Lê de context: files, changed, paths, stack, trace_id, repo_path (com defaults).
    Grava em context: repo, audit_input, report. Retorna o AuditReport.
    """
    files = context.get("files") or {}
    changed = context.get("changed")
    repo, orchestrator = montar_pipeline(files=files, changed=changed)
    audit_input = AuditInput(
        escopo=escopo,
        repo_path=context.get("repo_path", "./alvo"),
        paths=context.get("paths", []),
        stack=context.get("stack", ["golang"]),
        integracoes=context.get("integracoes", []),
        trace_id=context.get("trace_id", "trace-bdd-001"),
    )
    context["repo"] = repo
    context["audit_input"] = audit_input
    context["report"] = orchestrator.run(audit_input)
    return context["report"]


@pytest.fixture
def context() -> dict:
    """Estado mutável compartilhado entre os steps de um mesmo cenário."""
    return {}
