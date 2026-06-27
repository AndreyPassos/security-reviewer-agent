"""SecurityReviewerAgent — raciocínio rule-based determinístico (mock, sem LLM).

Transforma as evidências coletadas (segredos, dependências, ocorrências) em
Findings com evidência. Determinístico para os testes serem reprodutíveis.
"""
from __future__ import annotations

from src.schemas import AuditReport, Finding, ResumoSeveridade, PipelineState

AGENT_ID = "SecurityReviewerAgent"

# Derivação determinística de categoria a partir do padrão buscado (code_search).
# As chaves espelham PATTERNS_BY_STACK (crypto/db/input_output/api); sem dica → "other".
_PADRAO_CATEGORIA = (
    (("md5", "sha1", "math/rand", "rand", "rc4", "crypt"), "crypto"),
    (("select", "sql", "query"), "db"),
    (("eval(", "exec(", "yaml.load", "pickle", "deserialize", "subprocess", "os.system"), "input_output"),
    (("http", "tls", "ssl"), "api"),
)


def _categoria_por_padrao(padrao: str) -> str:
    """Mapeia um padrão de busca para uma Categoria; 'other' quando não há dica."""
    p = (padrao or "").lower()
    for chaves, categoria in _PADRAO_CATEGORIA:
        if any(c in p for c in chaves):
            return categoria
    return "other"


class SecurityReviewerAgent:
    agent_id = AGENT_ID

    def execute(self, state: PipelineState) -> AuditReport:
        """Gera AuditReport a partir de state (PipelineState).

        Regras (cada Finding com evidencia = trecho real):
        - cada SegredoDetectado → Finding categoria="secrets", severidade="critico",
          evidencia=valor_mascarado, owasp="A07:2021".
        - cada DependenciaVulneravel → Finding categoria="deps",
          severidade=dep.severidade, evidencia="<pacote>@<versao> (<cve>)", owasp="A06:2021".
        - cada Ocorrencia → Finding com categoria/severidade derivadas do padrão
          (ver mapa abaixo), evidencia=trecho.
        IDs sequenciais "SEC-001", "SEC-002"... `confianca` 0.9 (alta) por padrão.
        Calcular `resumo` (contagem por severidade), `nivel_seguranca`
        (critico>0 → "baixo"; alto>0 → "medio"; senão "alto"),
        `top_riscos` (ids critico/alto), `hitl_pendente` inicial False.
        trace_id = state.trace_id.
        """
        findings: list[Finding] = []
        contagem = {"critico": 0, "alto": 0, "medio": 0, "baixo": 0}

        def _proximo_id() -> str:
            return f"SEC-{len(findings) + 1:03d}"

        # 1) Segredos detectados → secrets / critico (OWASP A07:2021).
        for seg in state.segredos:
            findings.append(
                Finding(
                    id=_proximo_id(),
                    titulo=f"Segredo detectado: {seg.tipo}",
                    categoria="secrets",
                    severidade="critico",
                    arquivo=seg.arquivo,
                    linha=seg.linha,
                    evidencia=seg.valor_mascarado,
                    impacto="Credencial exposta permite acesso indevido.",
                    correcao="Mover para secret manager e rotacionar.",
                    owasp="A07:2021",
                    confianca=0.95,
                    trace_id=state.trace_id,
                )
            )

        # 2) Dependências vulneráveis → deps (OWASP A06:2021).
        for dep in state.dependencias:
            findings.append(
                Finding(
                    id=_proximo_id(),
                    titulo=f"Dependência vulnerável: {dep.pacote} ({dep.cve})",
                    categoria="deps",
                    severidade=dep.severidade,
                    arquivo="(dependências)",
                    linha=1,
                    evidencia=f"{dep.pacote}@{dep.versao} ({dep.cve})",
                    impacto="Dependência vulnerável.",
                    correcao=f"Atualizar para {dep.versao_corrigida}.",
                    owasp="A06:2021",
                    confianca=0.9,
                    trace_id=state.trace_id,
                )
            )

        # 3) Ocorrências de padrões → categoria derivada do padrão, severidade média.
        for oc in state.ocorrencias:
            findings.append(
                Finding(
                    id=_proximo_id(),
                    titulo=f"Padrão potencialmente inseguro: {oc.padrao}",
                    categoria=_categoria_por_padrao(oc.padrao),
                    severidade="medio",
                    arquivo=oc.arquivo,
                    linha=oc.linha,
                    evidencia=oc.trecho,
                    impacto="Padrão potencialmente inseguro.",
                    correcao="Revisar e aplicar prática segura.",
                    confianca=0.85,
                    trace_id=state.trace_id,
                )
            )

        for f in findings:
            contagem[f.severidade.value] += 1

        resumo = ResumoSeveridade(**contagem)

        if contagem["critico"] > 0:
            nivel_seguranca = "baixo"
        elif contagem["alto"] > 0:
            nivel_seguranca = "medio"
        else:
            nivel_seguranca = "alto"

        top_riscos = [f.id for f in findings if f.severidade.value in ("critico", "alto")]

        escopo = state.input.escopo if state.input is not None else "full"

        return AuditReport(
            trace_id=state.trace_id,
            escopo=escopo,
            resumo=resumo,
            nivel_seguranca=nivel_seguranca,
            findings=findings,
            top_riscos=top_riscos,
            hitl_pendente=False,
        )
