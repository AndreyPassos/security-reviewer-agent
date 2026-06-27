"""LLMReviewerAgent — variante real do agente, raciocínio via LLM (DeepSeek).

Mesma interface de SecurityReviewerAgent (agent_id + execute(state) -> AuditReport).
As TOOLS (scanners) continuam determinísticas; o LLM interpreta as evidências e,
em modo MAP-REDUCE, audita TODO o código em blocos (chunks):
  - 1 chamada para as evidências de scanners (segredos/deps/ocorrências)
  - 1 chamada por chunk de código (cobertura total, não só amostra)
  - merge + dedup dos findings de todas as chamadas
Cada chamada é rastreada (self.tracer) e os guardrails de saída validam o resultado.

SEGURANÇA: chave só de os.environ["DEEPSEEK_API_KEY"]; segredos vão mascarados;
trechos de código são enviados ao LLM (dado sai da máquina — ciente para demo).
"""
from __future__ import annotations

import json
import os
import urllib.request

from src.schemas import AuditReport, Finding, ResumoSeveridade, PipelineState

AGENT_ID = "SecurityReviewerAgent"

_SYSTEM = (
    "Você é um auditor AppSec sênior. Recebe um BLOCO de dados (evidências de "
    "scanners e/ou trechos de código real com arquivo:linha) e deve achar "
    "vulnerabilidades. REGRAS: todo finding DEVE citar arquivo, linha e um trecho "
    "REAL presente no bloco; NUNCA invente vulnerabilidade nem cite linha/arquivo "
    "fora do bloco; NUNCA exponha segredo em claro (use o mascarado). Procure: SQL "
    "injection, cripto fraca (md5/sha1), segredos, eval/exec, desserialização "
    "insegura, dados sensíveis/PII, validação ausente, TLS desativado. "
    "Responda APENAS JSON no formato: "
    '{"findings":[{"titulo":str,"categoria":"auth|secrets|input_output|api|frontend|'
    'deps|config|concurrency|crypto|db|other","severidade":"critico|alto|medio|baixo",'
    '"arquivo":str,"linha":int,"evidencia":str,"impacto":str,"correcao":str,'
    '"owasp":str,"confianca":0.0-1.0}]}'
)


class LLMReviewerAgent:
    agent_id = AGENT_ID
    wants_code_sample = True   # orquestrador injeta código real no state
    wants_full_code = True     # ...sem o cap de amostra (map-reduce cobre tudo)

    def __init__(self, model: str = "deepseek-chat", base_url: str = "https://api.deepseek.com",
                 timeout: int = 90, chunk_lines: int = 150, max_chunks: int = 40):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.chunk_lines = chunk_lines
        self.max_chunks = max_chunks
        self.tracer = None  # orquestrador injeta para rastrear cada chamada

    # ── infra ──
    def _trace(self, event: str, **fields) -> None:
        if self.tracer is not None:
            self.tracer.event(event, **fields)

    def _call(self, user: str) -> str:
        key = os.environ.get("DEEPSEEK_API_KEY")
        if not key:
            raise RuntimeError(
                "DEEPSEEK_API_KEY não definida. Exporte no ambiente (ou use .env) "
                "antes de rodar — a chave nunca deve ir para arquivo."
            )
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "system", "content": _SYSTEM},
                         {"role": "user", "content": user}],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=body, method="POST",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]

    @staticmethod
    def _parse_findings(raw: str, trace_id: str) -> list:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        out: list = []
        for i, f in enumerate(data.get("findings", []), start=1):
            f = dict(f)
            f["id"] = f"SEC-{i:03d}"  # precisa casar ^SEC-\d{3,}$; _reduce re-numera no fim
            f["trace_id"] = trace_id
            f.setdefault("confianca", 0.7)
            try:
                out.append(Finding(**f))
            except Exception:
                continue  # finding malformado é ignorado (guardrails fariam o mesmo)
        return out

    def _chunks(self, amostra: list) -> tuple:
        """Parte a lista de linhas (Ocorrencia) em blocos. Retorna (blocos, truncado)."""
        blocos = [amostra[i:i + self.chunk_lines]
                  for i in range(0, len(amostra), self.chunk_lines)]
        truncado = len(blocos) > self.max_chunks
        return blocos[:self.max_chunks], truncado

    # ── execução: MAP (scanners + chunks) → REDUCE (merge/dedup) ──
    def execute(self, state: PipelineState) -> AuditReport:
        escopo = state.input.escopo.value if state.input is not None else "full"
        brutos: list = []

        # MAP 1: evidências dos scanners (segredos já mascarados, deps, ocorrências)
        ev = {
            "segredos": [{"arquivo": s.arquivo, "linha": s.linha, "tipo": s.tipo,
                          "valor_mascarado": s.valor_mascarado} for s in state.segredos],
            "dependencias": [{"pacote": d.pacote, "versao": d.versao, "cve": d.cve,
                              "severidade": d.severidade.value,
                              "versao_corrigida": d.versao_corrigida} for d in state.dependencias],
            "ocorrencias": [{"arquivo": o.arquivo, "linha": o.linha, "trecho": o.trecho}
                            for o in state.ocorrencias],
        }
        if any(ev.values()):
            raw = self._call("BLOCO = evidências de scanners:\n"
                             + json.dumps(ev, ensure_ascii=False, indent=2))
            f = self._parse_findings(raw, state.trace_id)
            brutos.extend(f)
            self._trace("llm_call", fonte="scanners", findings=len(f))

        # MAP 2..N: código real em chunks (cobertura total)
        blocos, truncado = self._chunks(state.amostra_codigo)
        for i, bloco in enumerate(blocos, start=1):
            linhas = "\n".join(f"{o.arquivo}:{o.linha}: {o.trecho}" for o in bloco)
            raw = self._call(f"BLOCO = trechos de código (arquivo:linha: conteúdo):\n{linhas}")
            f = self._parse_findings(raw, state.trace_id)
            brutos.extend(f)
            self._trace("llm_call", fonte=f"chunk {i}/{len(blocos)}", findings=len(f))

        return self._reduce(brutos, state.trace_id, escopo, truncado, len(blocos))

    # ── REDUCE: dedup + reconstrói relatório coerente ──
    def _reduce(self, brutos: list, trace_id: str, escopo: str,
                truncado: bool, n_chunks: int) -> AuditReport:
        vistos = set()
        findings: list = []
        for f in brutos:
            chave = (f.arquivo, f.linha, f.categoria.value)
            if chave in vistos:
                continue
            vistos.add(chave)
            f.id = f"SEC-{len(findings) + 1:03d}"
            findings.append(f)

        contagem = {"critico": 0, "alto": 0, "medio": 0, "baixo": 0}
        for f in findings:
            contagem[f.severidade.value] += 1
        nivel = "baixo" if contagem["critico"] else "medio" if contagem["alto"] else "alto"

        obs = f"map-reduce: {n_chunks} bloco(s) de código auditado(s)."
        if truncado:
            obs += (f" COBERTURA TRUNCADA em {self.max_chunks} blocos "
                    f"(~{self.max_chunks * self.chunk_lines} linhas) — repo maior que o limite.")

        return AuditReport(
            trace_id=trace_id, escopo=escopo,
            resumo=ResumoSeveridade(**contagem), nivel_seguranca=nivel,
            findings=findings,
            top_riscos=[f.id for f in findings if f.severidade.value in ("critico", "alto")],
            hitl_pendente=False, observacoes=obs,
        )
