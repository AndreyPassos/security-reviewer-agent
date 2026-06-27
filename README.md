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
pytest steps/ tests/ -v
```

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
