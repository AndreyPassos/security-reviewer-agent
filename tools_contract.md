# tools_contract.md — SecurityReviewerAgent

> Cada tool é whitelist por agente. Ver `mcp_contract.md` para discovery e auth.
> Todas as tools são **read-only**: leem o repositório alvo, nunca escrevem.

## MCP — Model Context Protocol

| Campo | Valor |
|-------|-------|
| **Contrato MCP** | `mcp_contract.md` |
| **Server mock** | `src/mcp/appsec_server.py` |
| **Cliente** | `src/mcp/client.py` |
| **Discovery** | `MCPRegistry.schema()` |
| **Auth** | Whitelist por `agent_id` (produção: `MCP_TOKEN`) |

### Fluxo contrato → MCP → teste

```
tools_contract.md + mcp_contract.md  →  MCPRegistry  →  test_tools_contract_mcp.py
features/*.feature                   →  steps/       →  pytest-bdd
```

### Tools MCP registradas (4)

- `diff_collector`
- `code_search`
- `dependency_scan`
- `secret_scan`

## diff_collector
- **Agente:** SecurityReviewerAgent
- **Modo:** MCP mock + whitelist · read-only
- **Função:** Lista arquivos alterados do PR/diff dentro de `repo_path`
- **Parâmetros:** validados por `AuditInput` (`escopo`, `repo_path`, `paths`, `trace_id`)
- **Saída:** `list[ArquivoAlterado]`
- **Erros:** TOOL_NAO_AUTORIZADA, ENTRADA_INVALIDA

## code_search
- **Agente:** SecurityReviewerAgent
- **Modo:** MCP mock + whitelist · read-only
- **Função:** Procura padrão/regex no código e retorna ocorrências `arquivo:linha:trecho`
- **Parâmetros:** `padrao` (string), `paths` (opcional), `trace_id`
- **Saída:** `list[Ocorrencia]`
- **Erros:** TOOL_NAO_AUTORIZADA, ENTRADA_INVALIDA, INJECAO_DETECTADA

## dependency_scan
- **Agente:** SecurityReviewerAgent
- **Modo:** MCP mock + whitelist · read-only
- **Função:** Lê manifestos (`go.mod`, `package.json`, `requirements.txt`...) e mapeia CVEs
- **Parâmetros:** `repo_path`, `trace_id`
- **Saída:** `list[DependenciaVulneravel]`
- **Erros:** TOOL_NAO_AUTORIZADA, ENTRADA_INVALIDA

## secret_scan
- **Agente:** SecurityReviewerAgent
- **Modo:** MCP mock + whitelist · read-only
- **Função:** Detecta segredos hardcoded (chaves, tokens, senhas, private keys)
- **Parâmetros:** `repo_path`, `paths` (opcional), `trace_id`
- **Saída:** `list[SegredoDetectado]` — `valor_mascarado` SEMPRE mascarado
- **Erros:** TOOL_NAO_AUTORIZADA, ENTRADA_INVALIDA, PII_EXPOSTO

---

## Checks por linguagem (dirigidos por `AuditInput.stack`)

> O agente usa `code_search` com os padrões idiomáticos da stack detectada.
> Inclua apenas o bloco relevante.

### Bloco A: Golang
- `context` sem `WithTimeout`/cancelamento em chamadas externas
- Goroutines sem controle (leak), falta de `WaitGroup`
- Race: acesso concorrente sem mutex, `map` inseguro
- Erros ignorados (`_ =`), vazamento de info sensível
- `http.DefaultClient`, falta de timeout, TLS inseguro
- SQL injection, queries sem prepared statements
- Cripto: MD5/SHA1, `math/rand` para token, falta de bcrypt/argon2

### Bloco B: Node / TypeScript
- Promises sem catch, `await` sem timeout, unhandled rejection
- Injection: template string em query, `eval`, `child_process` com input
- Prototype pollution; desserialização insegura
- Stack trace exposto; `console.log` com dado sensível
- fetch/axios sem timeout, `rejectUnauthorized:false`
- Cripto: MD5/SHA1, `Math.random()` para token, falta de bcrypt/argon2/scrypt

### Bloco C: Python
- Requests sem timeout, threads/async sem cancelamento
- Injection: f-string em SQL, `eval`/`exec`, `subprocess(shell=True)`
- Desserialização: `pickle`, `yaml.load` sem `safe_load`
- Traceback exposto, `except: pass`, log com dado sensível
- `requests` com `verify=False`, TLS fraco
- Cripto: MD5/SHA1, `random` para token, falta de bcrypt/argon2

> Outra linguagem: aplique o equivalente idiomático dos 7 eixos
> (concorrência/timeout, injection, desserialização, erros, HTTP/TLS, banco, cripto).
