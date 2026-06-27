# language: pt
Funcionalidade: Whitelist de tools no MCP — SecurityReviewerAgent
  Como plataforma
  Quero que apenas agentes autorizados invoquem tools
  Para impedir uso indevido dos scanners

  Cenário: Discovery expõe as 4 tools
    Dado o servidor MCP "appsec-review"
    Quando consulto o discovery
    Então existem 4 tools registradas
    E o protocolo é "mcp-mock/1.0"

  Cenário: Agente fora da whitelist é recusado
    Dado um agente "AgenteDesconhecido" fora da whitelist
    Quando ele invoca a tool "secret_scan"
    Então a resposta indica "TOOL_NAO_AUTORIZADA"

  Cenário: Tool inexistente é recusada
    Dado o agente "SecurityReviewerAgent"
    Quando ele invoca a tool "apagar_repositorio"
    Então a resposta indica "TOOL_NAO_ENCONTRADA"
