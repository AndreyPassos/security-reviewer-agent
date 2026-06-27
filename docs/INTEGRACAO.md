# INTEGRACAO.md — Os modos de uso (mesmo núcleo)

O agente tem **um núcleo** (tools + schemas + guardrails) consumido por **três portas**:
servidor **MCP** (cérebro = Claude do Claude Code), **CLI** (CI/terminal) e **lib** (Python).
Trocar o cérebro não mexe no núcleo — é o ponto da Clean Architecture.

## Núcleo compartilhado (não muda entre modos)

| Peça | Arquivo | Papel |
|---|---|---|
| Tools (scanners) | `src/mcp/appsec_server.py` | secret/code/dep/diff — determinísticas, sem IA, sem chave |
| Repo adapters | `src/mcp/repo.py` · `fs_repo.py` | leem memória/disco (read-only) |
| Guardrails | `src/guardrails/` | fail-closed: evidência, schema, PII |
| Schemas | `src/schemas.py` · `schemas/schemas.json` | contrato de I/O |
| Observabilidade | `src/observability.py` | trace_id |

## Matriz de modos

| Modo | Entrada | Cérebro | Chave? | Guardrails | Caso de uso |
|---|---|---|---|---|---|
| **A. MCP (Claude Code)** | `src/mcp_server.py` | Claude (Claude Code) | ❌ usa tua cota | `validate_report` (tool) | dev interativo, sem custo de chave |
| **B1. CLI mock** | `src/cli.py` | regras | ❌ | auto (`guardrails.post`) | CI barato, determinístico |
| **B2. CLI `--llm`** | `src/cli.py --llm` | DeepSeek | ✅ secret | auto (`guardrails.post`) | CI com raciocínio, sem Claude |
| **C. lib** | `Orchestrator` | qualquer agente | depende | auto | embutir em outro serviço |

## A — Servidor MCP (dentro do Claude Code)

Requer Python ≥ 3.10.

```bash
pip install -r requirements.txt -r requirements-mcp.txt
claude mcp add --transport stdio security-reviewer -- /caminho/.venv/bin/python -m src.mcp_server
# gerenciar: claude mcp list · claude mcp get security-reviewer · claude mcp remove security-reviewer
```

`--transport stdio` é obrigatório; tudo após `--` é o comando que sobe o servidor.
Escopo padrão é `local` (só este projeto); use `--scope user` p/ todos os projetos ou
`--scope project` p/ versionar em `.mcp.json`. Tools expostas: `scan_secrets`,
`search_code`, `scan_deps`, `collect_diff`, `validate_report`.
No Claude Code: "audite o repositório X" → o Claude chama as tools, raciocina e chama
`validate_report` para fechar com o contrato (fail-closed volta). **Sem DEEPSEEK_API_KEY.**

## B — CLI standalone (CI / terminal)

```bash
# determinístico (sem chave) — exit 1 se houver finding crítico
python -m src.cli --repo <caminho> --escopo full

# raciocínio DeepSeek (chave via ambiente/secret)
python -m src.cli --repo <caminho> --escopo full --llm
```

CI pronto em `.github/workflows/security-review.yml` (roda os testes + auditoria mock no PR).
Para FALHAR o build em finding crítico, remova `continue-on-error` do step de auditoria.

## C — Biblioteca (Python)

```python
from src.mcp.fs_repo import FileSystemRepo
from src.mcp.appsec_server import build_default_registry
from src.mcp.client import MCPClient
from src.orquestracao.pipeline import Orchestrator
from src.schemas import AuditInput

orch = Orchestrator(MCPClient(build_default_registry(FileSystemRepo("/proj"))))
report = orch.run(AuditInput(escopo="full", repo_path="/proj", stack=["golang"], trace_id="t1"))
```

## Garantia do contrato em cada modo

- **B/C:** `guardrails.post` embrulha a saída automaticamente.
- **A (MCP):** o Claude raciocina livre sobre as evidências das tools; chamar
  `validate_report` reaplica o mesmo `guardrails.post` → mantém o fail-closed.

## O que é novo vs reusado

| Novo | Reusado |
|---|---|
| `src/mcp_server.py` (porta MCP) | todos os handlers de scanner |
| `requirements-mcp.txt` | guardrails, schemas, observabilidade |
| `.github/workflows/security-review.yml` | CLI, testes, demo |
| este doc | — |
