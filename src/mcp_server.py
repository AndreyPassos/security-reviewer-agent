"""Servidor MCP real (stdio) — expõe as tools do SecurityReviewerAgent ao Claude Code.

Aqui o CÉREBRO é o Claude (do Claude Code): este servidor só oferece TOOLS
determinísticas read-only + `validate_report` (guardrails fail-closed), reusando
exatamente o núcleo do projeto. Não precisa de DEEPSEEK_API_KEY neste modo.

Registrar (requer Python >= 3.10 + `pip install -r requirements-mcp.txt`):

    claude mcp add security-reviewer -- /caminho/.venv/bin/python -m src.mcp_server

Uso no Claude Code: "audite o repositório X em busca de segredos e padrões
inseguros" → o Claude chama scan_secrets/search_code/scan_deps/collect_diff,
raciocina, e chama validate_report para fechar com o contrato.
"""
from __future__ import annotations

import uuid
from typing import Optional

from mcp.server.fastmcp import FastMCP

from src import guardrails
from src.mcp import appsec_server as scanners
from src.mcp.errors import MCPError
from src.mcp.fs_repo import FileSystemRepo

mcp = FastMCP("security-reviewer")


def _tid(trace_id: Optional[str]) -> str:
    return trace_id or f"mcp-{uuid.uuid4().hex[:8]}"


def _run(handler, repo, params) -> list:
    """Executa um handler de scanner e serializa; erro de tool vira [{error}]."""
    try:
        result = handler(repo, params)
    except MCPError as e:
        return [{"error": e.code}]
    return [m.model_dump() if hasattr(m, "model_dump") else m for m in result]


@mcp.tool()
def scan_secrets(repo_path: str, paths: Optional[list] = None,
                 trace_id: Optional[str] = None) -> list:
    """Procura segredos hardcoded (chaves AWS, JWT, private keys) no repositório.

    Retorna [{arquivo, linha, tipo, valor_mascarado}]. Read-only; valores SEMPRE
    mascarados (nunca o segredo em claro)."""
    repo = FileSystemRepo(repo_path)
    return _run(scanners.secret_scan, repo, {"trace_id": _tid(trace_id), "paths": paths})


@mcp.tool()
def search_code(repo_path: str, pattern: str, paths: Optional[list] = None,
                trace_id: Optional[str] = None) -> list:
    """Procura um padrão (regex ou literal) no código.

    Retorna [{arquivo, linha, trecho, padrao}]. Use para padrões inseguros, ex.:
    'md5.', 'eval(', 'http.DefaultClient', 'yaml.load('."""
    repo = FileSystemRepo(repo_path)
    return _run(scanners.code_search, repo,
                {"trace_id": _tid(trace_id), "padrao": pattern, "paths": paths})


@mcp.tool()
def scan_deps(repo_path: str, trace_id: Optional[str] = None) -> list:
    """Cruza manifestos (go.mod/package.json/requirements.txt) com CVEs conhecidos.

    Retorna [{pacote, versao, cve, severidade, versao_corrigida}]."""
    repo = FileSystemRepo(repo_path)
    return _run(scanners.dependency_scan, repo, {"trace_id": _tid(trace_id)})


@mcp.tool()
def collect_diff(repo_path: str, base_ref: str = "HEAD~1",
                 trace_id: Optional[str] = None) -> list:
    """Lista arquivos alterados vs base_ref (git diff). Retorna [{path, status, linguagem}]."""
    repo = FileSystemRepo(repo_path, base_ref=base_ref)
    return _run(scanners.diff_collector, repo, {"trace_id": _tid(trace_id)})


@mcp.tool()
def validate_report(report: dict) -> dict:
    """Valida um AuditReport contra o contrato (fail-closed) e o devolve saneado.

    Descarta finding sem evidência, recalcula resumo/nível/top_riscos, bloqueia PII
    em claro e exige o schema. Retorna {ok: true, report} OU {ok: false, violation, msg}.
    CHAME esta tool antes de entregar o relatório final ao usuário."""
    try:
        saneado = guardrails.post("SecurityReviewerAgent", report)
        return {"ok": True, "report": saneado.model_dump(mode="json")}
    except guardrails.GuardrailViolation as e:
        return {"ok": False, "violation": e.code, "msg": str(e)}


if __name__ == "__main__":
    mcp.run()
