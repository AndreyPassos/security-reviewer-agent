# DEMO.md — Roteiro de apresentação (SecurityReviewerAgent)

Agente auditor AppSec **orientado por contrato**, com tools determinísticas,
guardrails fail-closed, MCP, orquestração e raciocínio real via LLM (DeepSeek).

## Pré-requisitos

```bash
cd security-reviewer-agent
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Chave do LLM via ambiente — NUNCA em arquivo/commit:
export DEEPSEEK_API_KEY=sk-...        # rotacione após a demo
```

## Roteiro (≈5 min)

### 0. Tour completo (recomendado abrir com isto)
```bash
python demo.py
```
→ Mostra TUDO de uma vez, visível: MCP discovery, o agente **chamando cada tool**
(trace com tool/contagem/latência), os 7 findings, os 6 guardrails disparando e o
`trace_id` ponta a ponta. É o "ver o agente trabalhando".

### 1. Contrato primeiro (a tese da aula)
Mostrar que o agente nasce de contratos, não de prompt:
`agent_spec.md`, `guardrails_contract.md`, `mcp_contract.md`, `schemas/schemas.json`.

### 2. Tools determinísticas + trace do agente
```bash
python -m src.cli --repo demo-target --escopo full --trace
```
→ `--trace` (no stderr) mostra cada `tool_call`; o relatório JSON sai limpo no stdout
(pipeável p/ CI). Detecta: chave AWS (mascarada), CVE de dependência, md5/http/SQL.

### 3. Raciocínio real com LLM (DeepSeek)
```bash
python -m src.cli --repo demo-target --escopo full --llm
```
→ Mesmas evidências, porém findings redigidos pelo LLM (impacto, correção, OWASP).

### 4. Guardrails seguram o LLM (o ponto-chave)
A saída do LLM passa por `guardrails.post`:
- finding sem evidência → descartado (anti-alucinação, GR-SEC01)
- segredo em claro → bloqueado (PII_EXPOSTO, GR-SEC03)
- fora do schema → pipeline para (SCHEMA_INVALIDO, GR-SEC02)

### 5. Testes de contrato
```bash
pytest tests/ steps/ -q
```
→ Schema, contrato MCP e cenários BDD (Gherkin pt) verdes.

## O que destacar

| Conceito | Onde aparece |
|----------|--------------|
| Agent Contract (DoD) | `agent_spec.md` |
| Requisitos (RF/RNF) | `docs/requirements.md` |
| JSON Schema | `schemas/schemas.json` valida toda saída |
| Tool Calling | 4 scanners via MCP |
| MCP | discovery + whitelist por agente |
| Orquestração | `src/orquestracao/pipeline.py` (fail-closed) |
| Guardrails | `src/guardrails/` (pre/post) |
| Testes | `tests/` + `features/` + `steps/` |
| Observabilidade | `trace_id` ponta a ponta |
| Clean Architecture | troca `InMemoryRepo` ↔ `FileSystemRepo`, resto intacto |

## Tese de fechamento
Tools = exaustivas e determinísticas. LLM = raciocínio e redação (mas pode errar/omitir).
Guardrails + schema = garantem o contrato **independente** do LLM. Os três juntos = agente seguro.

## Segurança da própria demo
- A chave DeepSeek entra só por `DEEPSEEK_API_KEY` (ambiente). Nunca em arquivo.
- Só as evidências (segredos já mascarados) vão ao LLM — não o segredo em claro.
- Rotacione a chave após a apresentação.
