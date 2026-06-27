# DEPS_SCAN_REAL.md — Scanner de dependências real (CVE + pacote malicioso)

> **Status:** design aprovado, implementação pendente.
> **Origem:** pergunta "dá pra validar na pipeline se há gap real / se sobe lib
> comprometida?". Resposta curta: o **encanamento** (CI, exit-code, fail-closed,
> escopo diff) já é real; a **detecção** de dependência ainda é mock.
> Este doc é a referência para trocar o mock por scanners reais sem quebrar o contrato.

## 1. Problema

`dependency_scan` (`src/mcp/appsec_server.py:133`) cruza o manifest com uma **base
hardcoded de 4 CVEs** por substring:

```python
base_cve = {
    ("left-pad", "1.0.0"): ("CVE-2099-0001", "alto", "1.0.1"),
    ("lodash", "4.17.15"): ("CVE-2020-8203", "alto", "4.17.19"),
    ("log4j-core", "2.14.1"): ("CVE-2021-44228", "critico", "2.17.1"),
    ("urllib3", "1.26.4"): ("CVE-2021-33503", "alto", "1.26.5"),
}
```

Match é `pacote in conteudo and versao in conteudo` — não pega vuln real fora dessas
4 strings, nem range de versão. Objetivo: detecção real de **dois controles ortogonais**.

## 2. Dois controles ortogonais (não confundir)

| | CVE conhecido | Pacote comprometido/malicioso |
|---|---|---|
| Natureza | pacote **legítimo**, bug numa versão | o pacote/versão **é** o ataque |
| Exemplo | lodash 4.17.15 (prototype pollution) | event-stream, ua-parser-js hijack, typosquat `reqeusts` |
| Mantenedor | honesto | conta sequestrada / ator malicioso |
| Correção | **upgrade** de versão | **remover** + **rotacionar segredos** |
| Fonte | OSV / NVD / GHSA | Socket, OSV `MAL-`, GitHub malware advisory |
| Janela | estável | curta (some quando o registry derruba o pacote) |

Scanner de CVE é **cego** para malicioso (não há CVE); feed de malicioso não lista bug
comum. Por isso precisa dos dois.

## 3. Ferramentas

### osv-scanner (CVE conhecido) — sem chave
- Binário Go oficial (projeto OSV.dev / Google). `osv-scanner --format json -r <repo>`
  ou `--lockfile=<arquivo>`.
- Lê lockfiles/manifests de N ecossistemas, cruza com base pública (NVD/GHSA agregados).
  Dados abertos, grátis, sem auth. Faz o parsing de lockfile de graça.
- **Bônus:** OSV também indexa malicioso com prefixo `MAL-` (base `malicious-packages`).
  Então osv-scanner sozinho já pega **parte** do malicioso conhecido, sem chave.

### Socket (pacote malicioso) — precisa de chave
- Socket.dev é **serviço comercial (SaaS)**, não dado aberto. API REST HTTP,
  `Authorization: Bearer $SOCKET_API_KEY`.
- **Por que a chave:** feed proprietário/pago (malware, install-scripts, typosquat,
  score comportamental) que OSV não tem. Sem chave, sem consulta.
- ⚠️ **Side-effect:** enviar `pacote@versão` ao Socket = **mandar a lista de deps do
  projeto para serviço externo**. Sai metadata. Em repo sensível, pesar.
- Alternativa de IDs: Socket usa alert-id próprio; OSV usa `MAL-`; GitHub usa `GHSA-`.

## 4. Blocker de schema

`src/schemas.py:77`:
```python
cve: str = Field(pattern=r"^CVE-\d{4}-\d+$")   # obrigatório — casa SÓ CVE
```
Pacote malicioso não tem CVE (`MAL-2024-1234`, `GHSA-xxxx-...`, alert-id Socket) → o
regex falha → `ValidationError` → guardrail fail-closed derruba o relatório.

**Mudança proposta** (espelhar em `schemas/schemas.json` + `src/schemas.py` + mapeamento
em `src/agents/security_reviewer.py:76`):
```python
class DependenciaVulneravel(BaseModel):
    pacote: str
    versao: str
    identificador: str            # CVE-… | GHSA-… | MAL-… | SOCKET-…  (genérico)
    tipo: str                     # "vuln_conhecida" | "pacote_malicioso"
    cve: Optional[str] = None     # mantido p/ compat; preenchido quando houver CVE
    severidade: Severidade
    versao_corrigida: Optional[str] = None
    fonte: Optional[str] = None   # "osv" | "socket"
    trace_id: str
```

## 5. Ponto de integração (1 handler, 3 modos)

O scanner é a tool `dependency_scan` (`appsec_server.py:133`), chamada pelo Orchestrator
(`pipeline.py:135`). Os 3 modos compartilham o núcleo → **trocar 1 handler propaga**:

- **CLI** (`src/cli.py`) → Orchestrator → `dependency_scan`. Exit **1** se houver
  finding crítico (`src/cli.py:94`); exit **2** em violação de guardrail.
- **CI** (`.github/workflows/security-review.yml`) → chama o CLI → exit 1 **falha o
  build**. Pacote malicioso deve ser marcado `critico`.
- **MCP** (Claude Code) → tool `scan_deps`, mesmo handler.

A interface do handler (`(repo, params) -> list[DependenciaVulneravel]`) **não muda** —
só o corpo. Guardrails, exit-code e os 3 modos continuam funcionando.

## 6. Decisão de design (aprovada)

Três eixos:

| Eixo | Opções | Escolha |
|---|---|---|
| **Fonte de malicioso** | A. só OSV (CVE+`MAL-`, sem chave) · B. OSV+Socket (chave) · C. OSV sempre + Socket se houver chave | **C** |
| **Ativação** | opt-in (`--deps-scan real`, mock segue default) · sempre-real | **opt-in** |
| **Falha do scanner** | fail-closed (bloqueia) · degrada+avisa · híbrido | **híbrido** |

**Híbrido = OSV obrigatório quando ligado (fail-closed se o binário sumir) + Socket só
se `SOCKET_API_KEY` existir (degrada+avisa se faltar).** Cobre malicioso sem forçar
ninguém a pagar Socket, mas aproveita a chave quando presente.

Racional:
- **opt-in** mantém os 20/20 testes BDD verdes e o CI keyless intacto (mock é o default
  determinístico). Real liga via flag/env.
- **fail-closed no OSV** porque gate de CVE silenciosamente degradado passa PR vulnerável
  achando que checou — pior caso.
- **degrada no Socket** porque exigir chave paga de todo consumidor quebraria o build de
  quem não tem Socket; o aviso registra a lacuna sem travar.

## 7. Checklist de implementação (futuro)

- [ ] Relaxar schema `DependenciaVulneravel` (`identificador`, `tipo`, `cve` opcional,
      `fonte`) em `schemas/schemas.json` **e** `src/schemas.py`.
- [ ] Atualizar o mapeamento dep→Finding em `src/agents/security_reviewer.py:76`
      (malicioso → `severidade="critico"`, `owasp="A06:2021"`, evidência = identificador).
- [ ] Reescrever `dependency_scan`: subprocess `osv-scanner --format json`, parsear,
      mapear vuln + `MAL-` → `DependenciaVulneravel`. Fail-closed se binário ausente
      quando o modo real estiver ligado.
- [ ] Adicionar fonte Socket (HTTP, `SOCKET_API_KEY` via env): degrada+avisa se faltar
      chave. Mesma interface de saída.
- [ ] Flag/env de ativação (`--deps-scan mock|real`) no `src/cli.py`; default `mock`.
- [ ] Testes: BDD mock seguem determinísticos; novos testes mockam a chamada osv/socket
      (sem rede no CI). Feature de degradação (sem chave) e fail-closed (sem binário).
- [ ] CI: instalar osv-scanner no workflow só no job real; passar `SOCKET_API_KEY` via
      secret (nunca interpolar `${{ }}` direto no `run:` — usar `env:`).
- [ ] Doc: atualizar `README.md` (próximos passos) e `docs/INTEGRACAO.md`.

## 8. Verify-pass (relacionado, opcional)

Para o modo `--llm`, reduzir falso-positivo refutando finding antes de gravar
(já listado em README "Próximos passos"). Ortogonal a este doc, mas combina: scanner
real dá menos ruído, verify-pass corta o resto.
