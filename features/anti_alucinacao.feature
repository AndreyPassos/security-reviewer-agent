# language: pt
Funcionalidade: Anti-alucinação por evidência — SecurityReviewerAgent
  Como engenheiro de segurança
  Quero que todo Finding seja provado por evidência
  Para não confiar em vulnerabilidades inventadas pelo modelo

  Cenário: Finding sem evidência é descartado
    Dado um Finding candidato sem o campo "evidencia"
    Quando os guardrails de saída são aplicados
    Então o Finding é descartado pela regra "GR-SEC01"
    E a violação registrada é "CONFIANCA_BAIXA"

  Cenário: Projeto limpo não gera achado inventado
    Dado um repositório sem vulnerabilidades conhecidas
    Quando audito o escopo "full"
    Então a lista de findings está vazia
    E o nivel_seguranca é coerente com zero findings
