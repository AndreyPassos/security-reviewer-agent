"""Orchestrator determinístico (ver architecture.md, agent_spec.md).

Sequência: guardrails.pre → tools (via MCP client) → agent.execute → guardrails.post.
Fail-closed: GuardrailViolation propaga e para o pipeline.
"""
from __future__ import annotations

from src import guardrails
from src.agents.security_reviewer import SecurityReviewerAgent
from src.mcp.client import MCPClient
from src.observability import Tracer, now_ms
from src.schemas import AuditInput, AuditReport, PipelineState
from src.schemas import (
    ArquivoAlterado,
    DependenciaVulneravel,
    Ocorrencia,
    SegredoDetectado,
)

# Padrões de risco por linguagem usados em code_search (mock, extensível).
# NOTA: as strings abaixo (ex. "eval(", "yaml.load(", "md5.") são ANTI-PADRÕES que
# o scanner PROCURA no código analisado — não são chamadas executadas aqui. São
# literais de detecção passados como regex/substring para repo.search().
PATTERNS_BY_STACK = {
    "golang": [
        ("http.DefaultClient", "api", "medio"),
        ("md5.", "crypto", "alto"),
        ("math/rand", "crypto", "medio"),
        ("fmt.Sprintf(\"SELECT", "db", "alto"),
    ],
    "javascript": [("eval(", "input_output", "alto")],
    "typescript": [("eval(", "input_output", "alto")],
    "python": [("eval(", "input_output", "alto"), ("yaml.load(", "input_output", "alto")],
}


def _amostra_codigo(repo, paths, trace_id: str, max_total: int = 150) -> list:
    """Amostra read-only de linhas de código real, para o agente LLM raciocinar.

    Bounded (max_total linhas) para limitar payload/custo. Só arquivos de código
    (com linguagem reconhecida), pulando linhas vazias.
    """
    from src.schemas import Ocorrencia
    out: list = []
    for arquivo, linhas in repo.iter_files(paths):
        if repo.linguagem(arquivo) is None:
            continue
        for numero, linha in enumerate(linhas, start=1):
            txt = linha.strip()
            if not txt:
                continue
            out.append(Ocorrencia(arquivo=arquivo, linha=numero, trecho=txt[:200],
                                   padrao="(amostra)", trace_id=trace_id))
            if len(out) >= max_total:
                return out
    return out


class Orchestrator:
    def __init__(self, client: MCPClient | None = None, agent: SecurityReviewerAgent | None = None,
                 observe: bool = False, tracer: Tracer | None = None):
        self.client = client or MCPClient()
        self.agent = agent or SecurityReviewerAgent()
        self.observe = observe
        self._tracer = tracer

    def run(self, audit_input: AuditInput) -> AuditReport:
        """Executa o pipeline completo e retorna um AuditReport saneado.

        Passos:
        1. guardrails.pre(self.agent.agent_id, audit_input)  [fail-closed]
        2. Coletar via MCP (todas read-only), passando trace_id=audit_input.trace_id:
           - diff_collector → arquivos
           - code_search por cada (padrao, cat, sev) de PATTERNS_BY_STACK[stack] das stacks
             em audit_input.stack → ocorrencias (anexar cat/sev na ocorrência se útil)
           - dependency_scan → dependencias
           - secret_scan → segredos
           Se algum invoke retornar ok=False, ignore o resultado daquela tool
           (lista vazia) — a falha de uma tool não derruba o pipeline aqui;
           guardrails de saída cuidam da integridade do relatório.
        3. Montar PipelineState(trace_id=..., input=audit_input, arquivos, ocorrencias,
           dependencias, segredos).
        4. report = self.agent.execute(state)
        5. return guardrails.post(self.agent.agent_id, report)
        """
        agent_id = self.agent.agent_id
        trace_id = audit_input.trace_id
        tr = self._tracer or Tracer(trace_id, enabled=self.observe)
        tr.event("pipeline_start", agent=agent_id, escopo=audit_input.escopo.value,
                 stack=",".join(audit_input.stack) or "-")

        # 1. Guardrails de entrada (fail-closed): propaga GuardrailViolation.
        try:
            guardrails.pre(agent_id, audit_input)
            tr.event("guardrail_pre", status="ok")
        except guardrails.GuardrailViolation as e:
            tr.event("guardrail_pre", status="violacao", code=e.code)
            raise

        # Escopo != full → restringe a coleta aos paths informados; full → repo todo.
        paths = audit_input.paths if audit_input.escopo.value != "full" else None

        def _coletar(tool: str, label: str = "", **params) -> list:
            """Invoca uma tool read-only e devolve a lista serializada (lista de dicts).

            Resiliente por contrato: ok=False OU qualquer exceção da tool vira lista
            vazia — a falha de uma tool não derruba o pipeline aqui (guardrails de
            saída cuidam da integridade do relatório). Cada chamada é rastreada.
            """
            t0 = now_ms()
            try:
                resp = self.client.invoke(tool, agent_id, trace_id=trace_id, **params)
            except Exception as e:  # noqa: BLE001 — resiliência por contrato
                tr.tool_call(tool, status=f"erro:{type(e).__name__}", count=0,
                             latency_ms=round(now_ms() - t0, 2), label=label)
                return []
            ms = round(now_ms() - t0, 2)
            if not resp.get("ok"):
                tr.tool_call(tool, status=resp.get("error"), count=0, latency_ms=ms, label=label)
                return []
            res = resp.get("result") or []
            tr.tool_call(tool, status="ok", count=len(res), latency_ms=ms, label=label)
            return res

        # 2. Coleta read-only via MCP (client serializa cada resultado como dict).
        arquivos_raw = _coletar("diff_collector", paths=paths)

        ocorrencias_raw: list = []
        for stack in audit_input.stack:
            for padrao, _categoria, _severidade in PATTERNS_BY_STACK.get(stack, []):
                ocorrencias_raw.extend(
                    _coletar("code_search", label=padrao, padrao=padrao, paths=paths)
                )

        dependencias_raw = _coletar("dependency_scan")
        segredos_raw = _coletar("secret_scan")

        # Código real — só para o agente LLM (mock ignora). Read-only.
        # wants_full_code → coleta ampla (map-reduce cobre tudo); senão amostra de 150.
        amostra = []
        if getattr(self.agent, "wants_code_sample", False):
            if getattr(self.agent, "wants_full_code", False):
                cl = getattr(self.agent, "chunk_lines", 150)
                mc = getattr(self.agent, "max_chunks", 40)
                cap = cl * mc + cl  # capacidade do agente + 1 chunk p/ detectar truncamento real
            else:
                cap = 150
            t0 = now_ms()
            amostra = _amostra_codigo(self.client.registry.repo, paths, trace_id, max_total=cap)
            tr.tool_call("code_sample", status="ok", count=len(amostra),
                         latency_ms=round(now_ms() - t0, 2))

        # 3. Reconstruir os modelos pydantic a partir dos dicts retornados pelo client.
        state = PipelineState(
            trace_id=trace_id,
            input=audit_input,
            arquivos=[ArquivoAlterado(**d) for d in arquivos_raw],
            ocorrencias=[Ocorrencia(**d) for d in ocorrencias_raw],
            dependencias=[DependenciaVulneravel(**d) for d in dependencias_raw],
            segredos=[SegredoDetectado(**d) for d in segredos_raw],
            amostra_codigo=amostra,
        )

        tr.event("state_montado", arquivos=len(state.arquivos), ocorrencias=len(state.ocorrencias),
                 dependencias=len(state.dependencias), segredos=len(state.segredos))

        # 4. Raciocínio do agente → AuditReport (LLM emite trace por chamada via tracer).
        if hasattr(self.agent, "tracer"):
            self.agent.tracer = tr
        report = self.agent.execute(state)
        tr.event("agent_execute", findings=len(report.findings))

        # 5. Guardrails de saída (fail-closed) → retorna o AuditReport saneado.
        try:
            saneado = guardrails.post(agent_id, report)
        except guardrails.GuardrailViolation as e:
            tr.event("guardrail_post", status="violacao", code=e.code)
            raise
        tr.event("guardrail_post", status="ok", findings=len(saneado.findings),
                 nivel=saneado.nivel_seguranca.value, hitl=saneado.hitl_pendente)
        tr.event("pipeline_end", nivel=saneado.nivel_seguranca.value)
        return saneado
