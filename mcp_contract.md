# mcp_contract.md — SecurityReviewerAgent

## Protocolo

| Campo | Valor |
|-------|-------|
| **Versão** | mcp-mock/1.0 |
| **Domínio** | appsec-review |
| **Transporte (mock)** | In-process Python |
| **Transporte (prod)** | MCP over HTTP + `MCP_TOKEN` |

## Discovery

```python
from src.mcp.appsec_server import DEFAULT_REGISTRY
schema = DEFAULT_REGISTRY.schema()
# → { protocol, domain, tools[], errors[] }
```

## Invocação

```python
from src.mcp.client import MCPClient
client = MCPClient()
resp = client.invoke("code_search", "SecurityReviewerAgent",
                     padrao="http.DefaultClient", repo_path="./alvo")
# → { ok: bool, result: [...], error: None | code }
```

## Códigos de erro

| Código | Significado |
|--------|-------------|
| `TOOL_NAO_ENCONTRADA` | Tool não registrada no MCP |
| `TOOL_NAO_AUTORIZADA` | Agente fora da whitelist (`tools_contract.md`) |
| `ENTRADA_INVALIDA` | Parâmetros rejeitados (schema/validação) |
| `INJECAO_DETECTADA` | Padrão de injeção no `padrao` de busca |
| `PII_EXPOSTO` | Segredo/PII retornado em claro (deve ser mascarado) |
| `HITL_OBRIGATORIO` | Resultado exige revisão humana |

## Whitelist (agente × tool)

| Tool | Agente autorizado |
|------|-------------------|
| `diff_collector` | SecurityReviewerAgent |
| `code_search` | SecurityReviewerAgent |
| `dependency_scan` | SecurityReviewerAgent |
| `secret_scan` | SecurityReviewerAgent |

## Auth (produção)

- Header: `Authorization: Bearer ${MCP_TOKEN}`
- Whitelist: `agent_id` deve constar em `tools_contract.md`
- Rotação de token: 90 dias
- Todas as tools são read-only; o servidor MCP recusa qualquer operação de escrita.
