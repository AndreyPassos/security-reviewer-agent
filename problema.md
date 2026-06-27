# problema.md — SecurityReviewerAgent

## Dor de negócio

Revisões de segurança feitas "no olho" ou com um prompt solto de LLM são:

- **Inconsistentes:** cada execução acha coisas diferentes; nada é reprodutível.
- **Alucinadas:** o modelo inventa vulnerabilidade sem apontar arquivo/linha real.
- **Não rastreáveis:** saída em markdown livre, impossível de versionar, medir ou plugar em CI.
- **Inseguras por si:** podem vazar segredos no relatório ou obedecer instruções
  plantadas no código analisado (prompt injection).

## Objetivo

Um agente auditor **orientado por contrato**: entrada e saída tipadas, toda
vulnerabilidade provada por evidência, saída validável por schema e rastreável
por `trace_id` — reutilizável em qualquer produto.

## Métricas-alvo (RNF)

| Métrica | Meta |
|---------|------|
| Saída schema-válida | 100% |
| Findings com evidência (`arquivo`+`linha`) | 100% |
| Segredos em claro no relatório | 0 |
| Detecção vs ground truth (campos críticos) | ≥95% |
| Latência por auditoria de diff | ≤ alvo definido em `docs/requirements.md` |

## Não-objetivos

- Não corrige código (read-only; correção é trabalho humano via HITL).
- Não substitui SAST/DAST comercial; orquestra e estrutura o resultado.
- Não decide deploy; emite relatório + `hitl_pendente`.
