"""Códigos de erro do MCP (ver mcp_contract.md)."""

TOOL_NAO_ENCONTRADA = "TOOL_NAO_ENCONTRADA"
TOOL_NAO_AUTORIZADA = "TOOL_NAO_AUTORIZADA"
ENTRADA_INVALIDA = "ENTRADA_INVALIDA"
INJECAO_DETECTADA = "INJECAO_DETECTADA"
PII_EXPOSTO = "PII_EXPOSTO"
HITL_OBRIGATORIO = "HITL_OBRIGATORIO"

ERROR_CODES = [
    TOOL_NAO_ENCONTRADA,
    TOOL_NAO_AUTORIZADA,
    ENTRADA_INVALIDA,
    INJECAO_DETECTADA,
    PII_EXPOSTO,
    HITL_OBRIGATORIO,
]


class MCPError(Exception):
    """Erro de tool/MCP. `.code` é um dos ERROR_CODES."""

    def __init__(self, code: str, message: str = ""):
        self.code = code
        super().__init__(message or code)
