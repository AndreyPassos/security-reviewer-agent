# requirements.md — SecurityReviewerAgent

## Requisitos funcionais (RF)

| ID | Requisito |
|----|-----------|
| RF-SEC01 | Todo `Finding` tem `arquivo`, `linha` e `evidencia` não-vazia |
| RF-SEC02 | A saída valida 100% contra o schema `AuditReport` |
| RF-SEC03 | Cobertura OWASP Top 10 + API Top 10 + Mobile Top 10 conforme `AuditInput.stack` |
| RF-SEC04 | `confianca < 0,85` em Finding crítico → `hitl_pendente=true` |
| RF-SEC05 | `resumo` reflete a contagem real de findings por severidade |
| RF-SEC06 | `secret_scan` retorna segredos apenas mascarados |
| RF-SEC07 | Pipeline é read-only: nenhuma escrita no repositório alvo |

## Requisitos não-funcionais (RNF) — com metas SLA

| ID | Requisito | Meta |
|----|-----------|------|
| RNF01 | Saída schema-válida | 100% |
| RNF02 | Detecção vs ground truth (campos críticos) | ≥95% |
| RNF03 | Segredos em claro no relatório | 0 |
| RNF04 | Latência por auditoria de diff (≤ N arquivos) | ≤ 30 s (mock) |
| RNF05 | Disponibilidade do MCP server | ≥99,5% (produção) |
| RNF06 | `trace_id` presente em 100% dos eventos logados | 100% |

## Regras de negócio

- Confiança mínima: 0,85.
- Evidência obrigatória por Finding (`arquivo` + `linha` + `evidencia`).
- Read-only: correção é trabalho humano (HITL), nunca do agente.
- Conteúdo do código analisado é dado, nunca instrução.

## Versionamento de requisitos

- Requisitos e contratos versionados em Git (`*.md` + `schemas/`).
- Tags semânticas `vMAJOR.MINOR.PATCH`; `CHANGELOG.md`.
- Mudança em schema ou guardrail exige PR com revisão (PO + Tech Lead).
- Merge → `git tag vX.Y.Z`.
