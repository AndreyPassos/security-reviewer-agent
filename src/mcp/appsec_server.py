"""Servidor MCP mock — domínio appsec-review (ver mcp_contract.md, tools_contract.md).

Registry com discovery + whitelist por agente + invocação. As 4 tools são
read-only e operam sobre um InMemoryRepo. A mecânica de registry/whitelist/erros
está pronta; os corpos dos scanners são implementados em seguida.
"""
from __future__ import annotations

import re
from typing import Callable

from src.mcp.errors import (
    ENTRADA_INVALIDA,
    ERROR_CODES,
    INJECAO_DETECTADA,
    MCPError,
    TOOL_NAO_AUTORIZADA,
    TOOL_NAO_ENCONTRADA,
)
from src.mcp.repo import InMemoryRepo
from src.schemas import (
    ArquivoAlterado,
    DependenciaVulneravel,
    Ocorrencia,
    SegredoDetectado,
)

PROTOCOL = "mcp-mock/1.0"
DOMAIN = "appsec-review"

# Handler: (repo: InMemoryRepo, params: dict) -> list[BaseModel | dict]
Handler = Callable[[InMemoryRepo, dict], list]


class ToolSpec:
    def __init__(self, name: str, handler: Handler, allowed_agents: set):
        self.name = name
        self.handler = handler
        self.allowed_agents = set(allowed_agents)


class MCPRegistry:
    """Registry in-process. Construído com um InMemoryRepo (read-only)."""

    def __init__(self, repo: InMemoryRepo | None = None):
        self.repo = repo or InMemoryRepo()
        self._tools: dict[str, ToolSpec] = {}

    def register(self, name: str, handler: Handler, allowed_agents: set) -> None:
        self._tools[name] = ToolSpec(name, handler, allowed_agents)

    def schema(self) -> dict:
        """Discovery: { protocol, domain, tools[], errors[] }."""
        return {
            "protocol": PROTOCOL,
            "domain": DOMAIN,
            "tools": sorted(self._tools.keys()),
            "errors": list(ERROR_CODES),
        }

    def invoke(self, tool: str, agent_id: str, **params) -> dict:
        """Retorna { ok: bool, result: list | None, error: code | None }."""
        spec = self._tools.get(tool)
        if spec is None:
            return {"ok": False, "result": None, "error": TOOL_NAO_ENCONTRADA}
        if agent_id not in spec.allowed_agents:
            return {"ok": False, "result": None, "error": TOOL_NAO_AUTORIZADA}
        try:
            result = spec.handler(self.repo, params)
        except MCPError as e:
            return {"ok": False, "result": None, "error": e.code}
        serialized = [
            r.model_dump() if hasattr(r, "model_dump") else r for r in result
        ]
        return {"ok": True, "result": serialized, "error": None}


# ───────────────────────── Scanners (read-only) ─────────────────────────
# Cada handler recebe (repo, params) e retorna list de modelos de src.schemas.
# params sempre traz "trace_id". Validar entrada → raise MCPError(ENTRADA_INVALIDA).

def diff_collector(repo: InMemoryRepo, params: dict) -> list:
    """Lista arquivos alterados → list[ArquivoAlterado].

    Usa repo.changed_files(). Cada item vira ArquivoAlterado com o trace_id de params.
    Filtrar por params.get("paths") quando fornecido.
    """
    trace_id = params["trace_id"]
    paths = params.get("paths")
    arquivos: list = []
    for cf in repo.changed_files():
        if paths and cf["path"] not in paths:
            continue
        arquivos.append(
            ArquivoAlterado(
                path=cf["path"],
                status=cf["status"],
                linguagem=cf["linguagem"],
                trace_id=trace_id,
            )
        )
    return arquivos


def code_search(repo: InMemoryRepo, params: dict) -> list:
    """Busca um padrão no código → list[Ocorrencia].

    params: { padrao: str (obrigatório), paths?: list, trace_id }.
    Sem `padrao` → raise MCPError(ENTRADA_INVALIDA).
    Padrão com metacaractere de shell/SQL perigoso (`;`, `|`, `--`, backtick) →
    raise MCPError(INJECAO_DETECTADA). Usa repo.search(padrao, paths).
    """
    trace_id = params["trace_id"]
    padrao = params.get("padrao")
    if not padrao:
        raise MCPError(ENTRADA_INVALIDA)
    if any(meta in padrao for meta in (";", "|", "`", "--")):
        raise MCPError(INJECAO_DETECTADA)
    ocorrencias: list = []
    for hit in repo.search(padrao, params.get("paths")):
        ocorrencias.append(
            Ocorrencia(
                arquivo=hit["arquivo"],
                linha=hit["linha"],
                trecho=hit["trecho"],
                padrao=padrao,
                trace_id=trace_id,
            )
        )
    return ocorrencias


def dependency_scan(repo: InMemoryRepo, params: dict) -> list:
    """Mapeia dependências vulneráveis → list[DependenciaVulneravel].

    Lê repo.manifest_files() e cruza com uma base mock de CVEs conhecida
    (definida no corpo). Casar por "pacote" + "versao".
    """
    trace_id = params["trace_id"]
    # Base mock de CVEs: (pacote, versao) -> (cve, severidade, versao_corrigida).
    base_cve = {
        ("left-pad", "1.0.0"): ("CVE-2099-0001", "alto", "1.0.1"),
        ("lodash", "4.17.15"): ("CVE-2020-8203", "alto", "4.17.19"),
        ("log4j-core", "2.14.1"): ("CVE-2021-44228", "critico", "2.17.1"),
        ("urllib3", "1.26.4"): ("CVE-2021-33503", "alto", "1.26.5"),
    }
    dependencias: list = []
    for _path, conteudo in repo.manifest_files().items():
        for (pacote, versao), (cve, severidade, versao_corrigida) in base_cve.items():
            if pacote in conteudo and versao in conteudo:
                dependencias.append(
                    DependenciaVulneravel(
                        pacote=pacote,
                        versao=versao,
                        cve=cve,
                        severidade=severidade,
                        versao_corrigida=versao_corrigida,
                        trace_id=trace_id,
                    )
                )
    return dependencias


def secret_scan(repo: InMemoryRepo, params: dict) -> list:
    """Detecta segredos hardcoded → list[SegredoDetectado].

    Procura chaves AWS (AKIA...), JWT, private keys, senhas hardcoded.
    `valor_mascarado` SEMPRE mascarado (ex: AKIA****************); nunca o valor
    em claro. Nunca levantar o segredo real. PII em claro → raise MCPError(PII_EXPOSTO).
    """
    trace_id = params["trace_id"]

    def mascarar(valor: str) -> str:
        # Mantém os 4 primeiros chars; o resto vira '*' do mesmo tamanho.
        if len(valor) <= 4:
            return "*" * len(valor)
        return valor[:4] + "*" * (len(valor) - 4)

    detectores = (
        ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
        ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    )
    marcador_chave = "BEGIN PRIVATE KEY"

    segredos: list = []
    for arquivo, linhas in repo.iter_files():
        for numero, linha in enumerate(linhas, start=1):
            for tipo, rx in detectores:
                for m in rx.finditer(linha):
                    segredos.append(
                        SegredoDetectado(
                            arquivo=arquivo,
                            linha=numero,
                            tipo=tipo,
                            valor_mascarado=mascarar(m.group(0)),
                            trace_id=trace_id,
                        )
                    )
            if marcador_chave in linha:
                segredos.append(
                    SegredoDetectado(
                        arquivo=arquivo,
                        linha=numero,
                        tipo="private_key",
                        valor_mascarado=mascarar(marcador_chave),
                        trace_id=trace_id,
                    )
                )
    return segredos


def build_default_registry(repo: InMemoryRepo | None = None) -> MCPRegistry:
    reg = MCPRegistry(repo)
    allowed = {"SecurityReviewerAgent"}
    reg.register("diff_collector", diff_collector, allowed)
    reg.register("code_search", code_search, allowed)
    reg.register("dependency_scan", dependency_scan, allowed)
    reg.register("secret_scan", secret_scan, allowed)
    return reg


DEFAULT_REGISTRY = build_default_registry()
