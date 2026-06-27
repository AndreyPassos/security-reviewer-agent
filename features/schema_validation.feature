# language: pt
Funcionalidade: Validação de schema fail-closed — SecurityReviewerAgent
  Como orquestrador
  Quero que saídas fora do contrato parem o pipeline
  Para nunca propagar um relatório malformado

  Cenário: Saída fora do schema AuditReport
    Dado um AuditReport sem o campo obrigatório "resumo"
    Quando os guardrails de saída são aplicados
    Então a resposta indica "SCHEMA_INVALIDO"
    E o pipeline para (fail-closed)

  Cenário: score de severidade incoerente com findings
    Dado um AuditReport cujo "resumo" não bate com a lista de findings
    Quando os guardrails de saída são aplicados
    Então a resposta indica "SCHEMA_INVALIDO"
