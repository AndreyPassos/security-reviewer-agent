# architecture.md — SecurityReviewerAgent

## Visão geral

Agente auditor AppSec orientado por contratos. Fase única, múltiplas tools
read-only, saída estruturada (`AuditReport`) validada por schema e rastreável.

## Clean Architecture (dependências apontam para dentro)

```
┌─────────────────────────────────────────────────────────┐
│  Interface (CLI / API / CI hook)                         │
│   └─ recebe AuditInput, devolve AuditReport (JSON)       │
├─────────────────────────────────────────────────────────┤
│  Use Cases / Orchestrator                                │
│   └─ orquestra tools, aplica guardrails pre/post         │
├─────────────────────────────────────────────────────────┤
│  Agent  ·  Guardrails  ·  Tools (ports)                  │
│   └─ SecurityReviewerAgent + regras GR-SEC + 4 scanners  │
├─────────────────────────────────────────────────────────┤
│  Contracts / Schemas (domínio puro)                      │
│   └─ AuditInput, Finding, AuditReport... (sem I/O)       │
├─────────────────────────────────────────────────────────┤
│  Infra (adapters): MCP server, git, filesystem, CVE db   │
└─────────────────────────────────────────────────────────┘
```

Regra: `Contracts/Schemas` não conhece infra. Tools são **ports** com adapters
na infra (MCP). O Agent depende de abstrações, nunca de implementações.

## Componentes

| Componente | Responsabilidade |
|------------|------------------|
| **Orchestrator** | Sequência determinística: pre → tools → agente → post; fail-closed |
| **SecurityReviewerAgent** | Raciocina sobre as evidências coletadas e gera `findings` |
| **Tools (4)** | `diff_collector`, `code_search`, `dependency_scan`, `secret_scan` (read-only) |
| **Guardrails** | Pre/Post; evidência, schema, PII, read-only, injection |
| **MCP Server** | Discovery + whitelist + invocação das tools |
| **Schemas** | Contratos executáveis (`schemas/schemas.json` + `src/schemas.py`) |

## Fluxo

```
AuditInput
  → guardrails.pre (trace_id, escopo, read-only)
  → diff_collector            → [ArquivoAlterado]
  → code_search ∥ dependency_scan ∥ secret_scan
                              → [Ocorrencia], [DependenciaVulneravel], [SegredoDetectado]
  → SecurityReviewerAgent     → [Finding]  (cada um com evidência)
  → guardrails.post (evidência, schema, PII, confiança)
  → AuditReport
        ↓ qualquer violação
    Pipeline para (fail-closed) + motivo logado
```

## Estrutura de pastas

```
security-reviewer-agent/
├── README.md
├── problema.md
├── agent_spec.md            # contrato do agente + DoD
├── tools_contract.md        # 4 tools, whitelist, checks por linguagem
├── mcp_contract.md          # protocolo, discovery, erros, auth
├── guardrails_contract.md   # fail-closed, pre/post, códigos de violação
├── security_contract.md     # threat model do próprio agente
├── docs/
│   ├── architecture.md
│   ├── requirements.md
│   └── testing.md
├── schemas/
│   └── schemas.json         # JSON Schema canônico
├── src/
│   ├── schemas.py           # Pydantic (espelho executável)
│   ├── agents/              # SecurityReviewerAgent.execute()
│   ├── guardrails/          # pre/post + GuardrailViolation
│   ├── mcp/                 # appsec_server.py + client.py
│   └── orquestracao/        # pipeline determinístico
├── features/                # cenários BDD (.feature, pt)
├── steps/                   # pytest-bdd
├── fixtures/                # JSONs de exemplo
├── exemplos/                # scripts de uso (discovery, invoke)
├── requirements.txt
└── pytest.ini
```

## Observabilidade

Log estruturado (JSON) por evento, correlacionado por `trace_id`:
`timestamp`, `nivel`, `evento`, `agente`, `tool`, `latencia_ms`, `status`.
Nunca inclui segredo/PII no payload. `correlation_id` propaga entre serviços.
