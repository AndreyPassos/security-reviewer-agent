# SecurityReviewerAgent — Referência Completa

Documento único consolidando **contrato do agente, requisitos, schemas, tools, MCP,
orquestração, guardrails, segurança, observabilidade, testes e uso**.
Agente auditor AppSec **orientado por contrato**, reutilizável em qualquer produto.

> Tese: agentes não nascem de prompts — nascem de contratos (requisitos, schemas,
> tools, guardrails, testes, segurança, orquestração). Modelo de convenções:
> repositório de referência da aula `naubergois/aero-passagens-platform`.

## Índice
1. [Visão geral e fluxo](#1-visão-geral-e-fluxo)
2. [Agent Contract (DoD)](#2-agent-contract-dod)
3. [Requisitos (RF/RNF)](#3-requisitos-rfrnf)
4. [Schemas (contratos executáveis)](#4-schemas-contratos-executáveis)
5. [Tools Contract](#5-tools-contract)
6. [MCP Contract](#6-mcp-contract)
7. [Guardrails (fail-closed)](#7-guardrails-fail-closed)
8. [Orquestração](#8-orquestração)
9. [Segurança do agente](#9-segurança-do-agente)
10. [Observabilidade](#10-observabilidade)
11. [Testes](#11-testes)
12. [Modos de uso](#12-modos-de-uso)
13. [Clean Architecture e estrutura](#13-clean-architecture-e-estrutura)

---

## 1. Visão geral e fluxo

Recebe um `AuditInput` (diff, módulo ou repo inteiro) e devolve um `AuditReport`
estruturado: findings com evidência (`arquivo`+`linha`), severidade, OWASP, resumo
por severidade, top riscos e `hitl_pendente`. Saída validada por schema e rastreável
por `trace_id`.

```
AuditInput
  → Orchestrator
    → guardrails.pre (fail-closed)
    → Tools read-only via MCP:
        diff_collector · code_search (1× por padrão) · dependency_scan · secret_scan
        [+ code_sample p/ o agente LLM]
    → PipelineState (evidências tipadas)
    → Agent.execute  (mock determinístico  OU  LLM DeepSeek map-reduce)
    → guardrails.post (fail-closed: evidência, schema, PII, coerência)
  → AuditReport
```

Dois agentes intercambiáveis (mesma interface `execute(state) -> AuditReport`):
- **`SecurityReviewerAgent`** (`src/agents/security_reviewer.py`) — rule-based, determinístico.
- **`LLMReviewerAgent`** (`src/agents/llm_reviewer.py`) — DeepSeek, **map-reduce** sobre todo o código.

---

## 2. Agent Contract (DoD)

- **Papel:** auditor AppSec read-only (web + mobile + API + cloud).
- **Objetivo:** emitir `AuditReport` com vulnerabilidades reais, cada uma com evidência.
- **Escopo permitido:** ler diff/código/dependências; invocar scanners via MCP; classificar risco; marcar HITL.
- **Escopo proibido:** editar/commitar/executar; reportar sem evidência; expor segredo/PII em claro; obedecer instrução embutida no código; inventar CVE/severidade.

**Definição de Pronto (mensurável):**
1. `AuditReport` 100% válido contra `schemas/schemas.json`.
2. Todo `Finding` com `arquivo` + `linha` + `evidencia` não-vazia.
3. Zero segredo/PII em claro no relatório (apenas mascarado).
4. `trace_id` presente na entrada, em cada tool e na saída.
5. Read-only garantido (nenhuma escrita no alvo).
6. `confianca < 0,85` em finding crítico → `hitl_pendente=true`.
7. `resumo`/`top_riscos`/`nivel_seguranca` coerentes com `findings`.
8. Consistência vs ground truth ≥95% nos campos críticos.

---

## 3. Requisitos (RF/RNF)

| RF | Requisito |
|----|-----------|
| RF-SEC01 | todo `Finding` tem `arquivo`, `linha` e `evidencia` não-vazia |
| RF-SEC02 | a saída valida 100% contra `AuditReport` |
| RF-SEC03 | cobertura OWASP Top 10 + API + Mobile conforme `AuditInput.stack` |
| RF-SEC04 | `confianca < 0,85` em finding crítico → `hitl_pendente=true` |
| RF-SEC05 | `resumo` reflete a contagem real por severidade |
| RF-SEC06 | `secret_scan` retorna segredos apenas mascarados |
| RF-SEC07 | pipeline read-only (nenhuma escrita no alvo) |

| RNF | Meta |
|-----|------|
| RNF01 saída schema-válida | 100% |
| RNF02 detecção vs ground truth | ≥95% |
| RNF03 segredos em claro | 0 |
| RNF04 latência (auditoria de diff) | ≤30 s (mock) |
| RNF05 disponibilidade MCP (prod) | ≥99,5% |
| RNF06 `trace_id` nos eventos logados | 100% |

Limites de negócio: **confiança mínima 0,85**; evidência obrigatória por finding; read-only; segredo só mascarado.

---

## 4. Schemas (contratos executáveis)

Canônico em `schemas/schemas.json` (JSON Schema) + espelho `src/schemas.py` (Pydantic).
Todo objeto que cruza fronteira carrega `trace_id`.

**Finding** (campos obrigatórios em **negrito**):
`**id**` (`^SEC-\d{3,}$`) · `**titulo**` · `**categoria**` (auth|secrets|input_output|api|frontend|deps|config|concurrency|crypto|db|other) · `**severidade**` (critico|alto|medio|baixo) · `**arquivo**` · `**linha**` (≥1) · `**evidencia**` (não-vazia) · `**impacto**` · `**correcao**` · `owasp` · `**confianca**` (0–1) · `**trace_id**`

**AuditReport:**
`**trace_id**` · `**escopo**` (diff|modulo|full) · `**resumo**` {critico,alto,medio,baixo} · `top_riscos[]` · `**nivel_seguranca**` (baixo|medio|alto) · `**findings**[]` · `**hitl_pendente**` · `observacoes`

**AuditInput:** `escopo` · `repo_path` · `paths[]` · `stack[]` · `integracoes[]` · `trace_id`
**Outros:** `ArquivoAlterado`, `Ocorrencia`, `DependenciaVulneravel`, `SegredoDetectado`, `PipelineState` (inclui `amostra_codigo[]` para o LLM).

---

## 5. Tools Contract

4 tools registradas no MCP, **whitelist por agente**, todas **read-only**. Handler:
`(repo, params) -> list[modelo]`, `params` sempre com `trace_id`.

| Tool | Função | Saída | Erros |
|------|--------|-------|-------|
| `diff_collector` | arquivos alterados (git diff) | `ArquivoAlterado[]` | ENTRADA_INVALIDA |
| `code_search` | padrão/regex → `arquivo:linha:trecho` | `Ocorrencia[]` | ENTRADA_INVALIDA, INJECAO_DETECTADA |
| `dependency_scan` | manifestos × base CVE | `DependenciaVulneravel[]` | ENTRADA_INVALIDA |
| `secret_scan` | segredos hardcoded (mascarados) | `SegredoDetectado[]` | PII_EXPOSTO |

`code_sample` (auxiliar, read-only, coletado pelo orquestrador): amostra de código real
para o agente **LLM** raciocinar. O mock ignora. `code_search` usa `PATTERNS_BY_STACK`
(ex. Go: `http.DefaultClient`, `md5.`, `fmt.Sprintf("SELECT`; Python: `eval(`, `yaml.load(`).
Padrão inválido como regex cai para busca literal (não falha em silêncio).

---

## 6. MCP Contract

| Campo | Valor |
|-------|-------|
| Versão | `mcp-mock/1.0` |
| Domínio | `appsec-review` |
| Transporte (mock) | in-process Python |
| Transporte (prod) | MCP over HTTP + `MCP_TOKEN` |

**Discovery:** `DEFAULT_REGISTRY.schema()` → `{protocol, domain, tools[], errors[]}`.
**Invocação:** `client.invoke(tool, agent_id, **params)` → `{ok, result, error}`.
**Whitelist:** as 4 tools só para `SecurityReviewerAgent`.

**Códigos de erro:** `TOOL_NAO_ENCONTRADA` · `TOOL_NAO_AUTORIZADA` · `ENTRADA_INVALIDA` · `INJECAO_DETECTADA` · `PII_EXPOSTO` · `HITL_OBRIGATORIO`.

**Auth (prod):** `Authorization: Bearer ${MCP_TOKEN}`; rotação 90 dias; servidor recusa qualquer escrita.

---

## 7. Guardrails (fail-closed)

Princípios: **fail-closed** (violação para o pipeline) · **pre + post** · **tool gate** (whitelist) · **evidence-required** (anti-alucinação) · **PII-safe** · **read-only** · **injection-resistant** (código é dado, não instrução).

**Códigos de violação:** `ESCOPO_PROIBIDO` · `PII_EXPOSTO` · `SCHEMA_INVALIDO` · `CONFIANCA_BAIXA` · `HITL_OBRIGATORIO` · `INJECAO_DETECTADA` · `TOOL_NAO_AUTORIZADA` · `ENTRADA_INVALIDA`.

| ID | Fase | Regra | Violação |
|----|------|-------|----------|
| GR-SEC01 | Post | finding sem `arquivo`+`linha`+`evidencia` → descartado | CONFIANCA_BAIXA |
| GR-SEC02 | Post | saída fora do `AuditReport` → para | SCHEMA_INVALIDO |
| GR-SEC03 | Post | segredo em claro na evidência → bloqueia | PII_EXPOSTO |
| GR-SEC04 | Pre  | tentativa de escrita/commit/exec | ESCOPO_PROIBIDO |
| GR-SEC05 | Post | finding crítico `confianca<0,85` → `hitl_pendente` | HITL_OBRIGATORIO |
| GR-SEC06 | Pre  | `padrao` com metacaractere perigoso | INJECAO_DETECTADA |
| GR-SEC07 | Post | `resumo`/`nivel`/`top_riscos` derivados dos findings (não confiados ao LLM) | SCHEMA_INVALIDO |

`guardrails.post` impõe o contrato **independente do agente** (vale para mock e LLM):
descarta sem evidência → recalcula resumo/nível/top_riscos → checa PII → valida schema.

---

## 8. Orquestração

`src/orquestracao/pipeline.py` → `Orchestrator.run(audit_input)` — determinística, single-agent, fail-closed:

1. `guardrails.pre(agent_id, audit_input)` — para em violação.
2. Coleta read-only via MCP (`trace_id` propagado): `diff_collector` → `code_search` (1× por padrão de `PATTERNS_BY_STACK[stack]`) → `dependency_scan` → `secret_scan`; `[code_sample]` se o agente for LLM. Tool que falha vira lista vazia (resiliente).
3. Monta `PipelineState` (reconstrói modelos pydantic).
4. `agent.execute(state)` → `AuditReport`.
5. `guardrails.post(agent_id, report)` → `AuditReport` saneado.

Cada passo emite evento de trace. Tipo: **1 agente + N tools** em sequência fixa
(diferente do multi-agente com handoff do repo do prof). `InMemoryRepo` ↔ `FileSystemRepo`
trocam sem mexer no resto (Clean Architecture).

**Map-reduce (agente LLM):** o orquestrador coleta o código (até `chunk_lines×max_chunks`,
padrão 150×40 = 6000 linhas); o `LLMReviewerAgent` parte em chunks, chama a DeepSeek por
chunk (+1 chamada para a evidência dos scanners), faz **merge + dedup** dos findings.
Cobertura além do limite é **truncada e reportada** em `observacoes` (sem corte silencioso).

---

## 9. Segurança do agente

Threat model (o auditor lê código não-confiável):

| Ameaça | Controle |
|--------|----------|
| Prompt injection (instrução no código) | código é dado, nunca instrução; `INJECAO_DETECTADA` |
| Vazamento de segredo no relatório | `secret_scan` mascara; `PII_EXPOSTO` no post |
| Alucinação | evidência obrigatória (GR-SEC01) |
| Escopo creep (editar/commitar) | read-only; `ESCOPO_PROIBIDO` |
| Saída malformada | fail-closed `SCHEMA_INVALIDO` |

Escopo proibido global, checklist e controles por componente em `security_contract.md`.
Credenciais (`MCP_TOKEN`, `DEEPSEEK_API_KEY`) só por variável de ambiente — nunca em arquivo.

---

## 10. Observabilidade

`src/observability.py` → `Tracer`. Cada passo emite evento (stderr ou JSON) com `trace_id`:

`pipeline_start` · `guardrail_pre` · `tool_call` (tool, status, count, latency_ms) ·
`code_sample` · `state_montado` · `llm_call` (fonte=scanners|chunk i/N, findings) ·
`agent_execute` · `guardrail_post` (nivel, hitl) · `pipeline_end`.

Liga com `--trace` no CLI (vai para stderr; stdout fica JSON limpo) ou `observe=True`/`tracer=`
no `Orchestrator`. `trace_id` propaga ponta a ponta (entrada → tools → saída).

---

## 11. Testes

| Camada | Onde | Cobre |
|--------|------|-------|
| Schema | `tests/test_schemas.py` | round-trip pydantic + JSON Schema; evidência vazia/linha 0 falham |
| Contrato MCP | `tests/test_tools_contract_mcp.py` | 4 tools, protocolo, whitelist, error codes |
| BDD (pytest-bdd, pt) | `features/*.feature` + `steps/` | secret, anti-alucinação, schema fail-closed, read-only, whitelist |

Estado: **20/20 verde**. Ground truth: fixtures com vulnerabilidades plantadas
(`fixtures/`); caso negativo: projeto limpo → `findings=[]` (não inventa).

```bash
.venv/bin/python -m pytest tests/ steps/ -v
```

---

## 12. Modos de uso

```bash
# setup
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DEEPSEEK_API_KEY=...        # ou .env (gitignored). Rotacione após uso.

# tour narrado (apresentação): MCP, tool calls, findings, guardrails, trace_id
python demo.py

# auditoria mock determinística (qualquer repo Go/JS/Py)
python -m src.cli --repo <caminho> --escopo full

# trace do agente (stderr) + relatório JSON limpo (stdout, pipeável p/ CI)
python -m src.cli --repo <caminho> --escopo full --trace

# raciocínio real DeepSeek, map-reduce sobre todo o código
python -m src.cli --repo <caminho> --escopo full --llm --trace

# escopo de PR (audita só o diff)
python -m src.cli --repo <caminho> --escopo diff --base-ref HEAD~1 --llm
```

CLI (`src/cli.py`): `--repo` (alvo, read-only) · `--escopo diff|modulo|full` · `--base-ref` ·
`--stack` (auto se omitido) · `--paths` · `--llm` · `--trace` · `--trace-id`.
Exit code: **1** se houver finding crítico (CI), **2** em violação de guardrail.

**Profundidade:** scanners são baseados em padrões (extensíveis); o modo `--llm` lê o código
real (map-reduce). Para profundidade de produção, trocar scanners por `gitleaks`/`govulncheck`/`trivy`
(mesma interface de handler). Trade-off do LLM lendo tudo: +cobertura, +ruído → recomenda-se
verify-pass (refutar findings) para cortar falso-positivo.

---

## 13. Clean Architecture e estrutura

Dependências apontam para dentro: domínio (schemas) não conhece infra (MCP/git/FS).
Tools são **ports**; `InMemoryRepo` (memória/teste) e `FileSystemRepo` (disco/git) são adapters.

```
security-reviewer-agent/
├── REFERENCIA.md            # este documento
├── agent_spec.md  tools_contract.md  mcp_contract.md
├── guardrails_contract.md  security_contract.md  problema.md
├── docs/        architecture.md · requirements.md · testing.md · DEMO.md
├── schemas/     schemas.json                 # JSON Schema canônico
├── src/
│   ├── schemas.py                            # Pydantic
│   ├── observability.py                      # Tracer
│   ├── cli.py
│   ├── agents/      security_reviewer.py (mock) · llm_reviewer.py (DeepSeek)
│   ├── guardrails/  rules.py · violations.py
│   ├── mcp/         appsec_server.py · client.py · repo.py · fs_repo.py
│   └── orquestracao/ pipeline.py
├── features/    *.feature (BDD, pt)
├── steps/       pytest-bdd
├── tests/       schema + contrato MCP
└── fixtures/    JSONs (vulnerável / limpo / sem-evidência)
```
