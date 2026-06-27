"""CLI — roda o SecurityReviewerAgent contra um repositório real.

Uso:
    python -m src.cli --repo /caminho/projeto                 # mock determinístico
    python -m src.cli --repo /caminho/projeto --llm           # raciocínio DeepSeek
    python -m src.cli --repo /caminho/projeto --escopo diff --base-ref HEAD~1

A chave do LLM vem de DEEPSEEK_API_KEY no ambiente (NUNCA hardcoded).
Exit code: 1 se houver finding crítico (amigável a CI), 2 em violação de guardrail.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid

from src import guardrails
from src.agents.security_reviewer import SecurityReviewerAgent
from src.mcp.appsec_server import build_default_registry
from src.mcp.client import MCPClient
from src.mcp.fs_repo import FileSystemRepo
from src.orquestracao.pipeline import Orchestrator
from src.schemas import AuditInput


def _load_dotenv(path: str = ".env") -> None:
    """Carrega KEY=VALUE de um .env local para o ambiente (sem dependência externa).

    Não sobrescreve variáveis já definidas no ambiente. O .env é gitignored —
    convém para dev/demo; em produção, use um secret manager.
    """
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            chave, valor = line.split("=", 1)
            os.environ.setdefault(chave.strip(), valor.strip().strip('"').strip("'"))


def detect_stack(repo: FileSystemRepo) -> list:
    stacks = set()
    for path, _ in repo.iter_files():
        if path.endswith(".go"):
            stacks.add("golang")
        elif path.endswith((".ts", ".tsx")):
            stacks.add("typescript")
        elif path.endswith((".js", ".jsx")):
            stacks.add("javascript")
        elif path.endswith(".py"):
            stacks.add("python")
    return sorted(stacks) or ["golang"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="SecurityReviewerAgent — auditoria AppSec por contrato")
    ap.add_argument("--repo", required=True, help="caminho do repositório alvo (read-only)")
    ap.add_argument("--escopo", default="full", choices=["diff", "modulo", "full"])
    ap.add_argument("--base-ref", default=None, help="ref git p/ diff (ex.: HEAD~1)")
    ap.add_argument("--stack", default=None, help="csv (ex.: golang,react); auto se omitido")
    ap.add_argument("--paths", default=None, help="csv de arquivos (escopo modulo)")
    ap.add_argument("--llm", action="store_true", help="usa DeepSeek (DEEPSEEK_API_KEY)")
    ap.add_argument("--trace", action="store_true", help="emite trace do agente (tool calls, passos) no stderr")
    ap.add_argument("--trace-id", default=None)
    a = ap.parse_args(argv)
    _load_dotenv()  # carrega .env local (DEEPSEEK_API_KEY) se existir

    repo = FileSystemRepo(a.repo, base_ref=a.base_ref)
    stack = a.stack.split(",") if a.stack else detect_stack(repo)
    paths = a.paths.split(",") if a.paths else []
    trace_id = a.trace_id or f"cli-{uuid.uuid4().hex[:8]}"

    if a.llm:
        from src.agents.llm_reviewer import LLMReviewerAgent
        agent = LLMReviewerAgent()
    else:
        agent = SecurityReviewerAgent()

    orch = Orchestrator(MCPClient(build_default_registry(repo)), agent, observe=a.trace)
    audit = AuditInput(escopo=a.escopo, repo_path=a.repo, stack=stack, paths=paths, trace_id=trace_id)

    try:
        report = orch.run(audit)
    except guardrails.GuardrailViolation as e:
        print(json.dumps({"erro": "GuardrailViolation", "code": e.code, "msg": str(e)},
                         ensure_ascii=False, indent=2))
        return 2

    print(report.model_dump_json(indent=2))
    return 1 if report.resumo.critico > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
