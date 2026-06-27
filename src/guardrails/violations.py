"""Códigos de violação de guardrail (ver guardrails_contract.md)."""

ESCOPO_PROIBIDO = "ESCOPO_PROIBIDO"
PII_EXPOSTO = "PII_EXPOSTO"
SCHEMA_INVALIDO = "SCHEMA_INVALIDO"
CONFIANCA_BAIXA = "CONFIANCA_BAIXA"
HITL_OBRIGATORIO = "HITL_OBRIGATORIO"
INJECAO_DETECTADA = "INJECAO_DETECTADA"
TOOL_NAO_AUTORIZADA = "TOOL_NAO_AUTORIZADA"
ENTRADA_INVALIDA = "ENTRADA_INVALIDA"

VIOLATION_CODES = [
    ESCOPO_PROIBIDO,
    PII_EXPOSTO,
    SCHEMA_INVALIDO,
    CONFIANCA_BAIXA,
    HITL_OBRIGATORIO,
    INJECAO_DETECTADA,
    TOOL_NAO_AUTORIZADA,
    ENTRADA_INVALIDA,
]

# Limite de confiança abaixo do qual o achado/relatório exige revisão humana.
CONFIANCA_MINIMA = 0.85


class GuardrailViolation(Exception):
    """Violação de guardrail (fail-closed). `.code` é um dos VIOLATION_CODES."""

    def __init__(self, code: str, message: str = ""):
        self.code = code
        super().__init__(message or code)
