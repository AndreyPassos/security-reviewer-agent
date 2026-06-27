# SecurityReviewerAgent — Auditor AppSec orientado por contratos

Agente de **revisão de segurança** orientado por contratos: `agent_spec`, schemas
(JSON Schema + Pydantic), tools MCP read-only, guardrails fail-closed e testes BDD.
Reutilizável em qualquer produto — a stack alvo é informada em `AuditInput.stack`.

> Modelo de convenções: repositório de referência da aula
> `naubergois/aero-passagens-platform`. Mesmo rigor de contratos, outro domínio.

## O que faz

Recebe um `AuditInput` (diff, módulo ou full scan) e devolve um `AuditReport`
estruturado: findings com evidência (`arquivo`+`linha`), severidade, OWASP,
resumo por severidade, top riscos e `hitl_pendente`.

## Pipeline

```
AuditInput → Orchestrator → diff_collector
                          → code_search ∥ dependency_scan ∥ secret_scan
                          → SecurityReviewerAgent
                          → guardrails.post → AuditReport
```

## Artefatos de contrato

| Arquivo | Conteúdo |
|---------|----------|
| `problema.md` | Dor de negócio e métricas |
| `agent_spec.md` | Contrato do agente + escopo + DoD |
| `tools_contract.md` | 4 tools read-only + whitelist + checks por linguagem |
| `mcp_contract.md` | Discovery, invocação, códigos de erro, auth |
| `guardrails_contract.md` | Fail-closed, pre/post, códigos de violação |
| `security_contract.md` | Threat model do próprio agente |
| `schemas/schemas.json` | Contratos canônicos (JSON Schema) |
| `src/schemas.py` | Espelho executável (Pydantic) |
| `docs/` | architecture, requirements, testing |

## Princípios

- **Evidence-required:** todo Finding tem `arquivo`+`linha`+`evidencia` (anti-alucinação).
- **Fail-closed:** saída fora do schema para o pipeline.
- **PII-safe:** segredos só mascarados no relatório.
- **Read-only:** o agente nunca edita nem commita.
- **trace_id** em toda entrada, handoff e saída.

## Testes BDD (5 features)

| Feature | Cenários |
|---------|----------|
| `secret_hardcoded.feature` | Detecção + mascaramento de segredo |
| `anti_alucinacao.feature` | Finding sem evidência descartado; projeto limpo |
| `schema_validation.feature` | Fail-closed `SCHEMA_INVALIDO` |
| `escopo_readonly.feature` | Bloqueio de escrita; injeção ignorada |
| `mcp_whitelist.feature` | Discovery, whitelist, tool inexistente |

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest tests/ steps/ -v        # 20/20
```

## Uso

Tour narrado (apresentação) — MCP discovery, tool calls, findings, guardrails, trace_id:

```bash
python demo.py
```

Auditar um repositório — **mock determinístico** (sem chave/LLM):

```bash
python -m src.cli --repo <caminho> --escopo full
```

Com **trace** do agente no stderr + relatório JSON limpo no stdout (pipeável p/ CI):

```bash
python -m src.cli --repo <caminho> --escopo full --trace
```

**LLM real (DeepSeek)** — map-reduce sobre todo o código:

```bash
cp .env.example .env          # edite e ponha sua DEEPSEEK_API_KEY (gitignored)
# ou: export DEEPSEEK_API_KEY=...
python -m src.cli --repo <caminho> --escopo full --llm --trace
```

**Escopo de PR** — audita só o diff (uso de CI):

```bash
python -m src.cli --repo <caminho> --escopo diff --base-ref HEAD~1 --llm
```

Flags: `--repo` (alvo, read-only) · `--escopo diff|modulo|full` · `--base-ref` ·
`--stack` (auto se omitido) · `--paths` · `--llm` · `--trace` · `--trace-id`.
Exit code: **1** se houver finding crítico (CI), **2** em violação de guardrail.

> Roteiro de apresentação: `docs/DEMO.md` · Referência completa num doc: `REFERENCIA.md`.

## Modos de uso (mesmo núcleo) — `docs/INTEGRACAO.md`

| Modo | Cérebro | Chave? | Como |
|------|---------|--------|------|
| **MCP (Claude Code)** | Claude | ❌ | `claude mcp add security-reviewer -- .venv/bin/python -m src.mcp_server` |
| **CLI mock** | regras | ❌ | `python -m src.cli --repo <p> --escopo full` |
| **CLI `--llm`** | DeepSeek | ✅ | `python -m src.cli --repo <p> --escopo full --llm` |
| **CI** | mock/DeepSeek | — | `.github/workflows/security-review.yml` |

No modo **MCP**, o Claude do Claude Code vira o cérebro (sem chave) e chama as tools
(`scan_secrets`, `search_code`, `scan_deps`, `collect_diff`, `validate_report`).
Requer Python ≥3.10 + `pip install -r requirements-mcp.txt`.

## Estado (implementado)

- [x] `execute()` em `src/agents/` — mock determinístico + `LLMReviewerAgent` (DeepSeek, map-reduce)
- [x] 4 scanners em `src/mcp/appsec_server.py` (diff_collector, code_search, dependency_scan, secret_scan)
- [x] Orquestração determinística em `src/orquestracao/pipeline.py` (fail-closed, com trace)
- [x] Guardrails pre/post, MCP discovery+whitelist, observabilidade (`src/observability.py`)
- [x] CLI (`src/cli.py`) + demo (`demo.py`) + testes (20/20)

## Próximos passos (opcionais)

1. Trocar scanners mock por reais (`gitleaks`/`govulncheck`/`trivy`) — mesma interface de handler
2. Verify-pass no LLM (refutar findings p/ reduzir falso-positivo)
3. Porta Go espelhando `schemas/schemas.json` para o projeto principal
