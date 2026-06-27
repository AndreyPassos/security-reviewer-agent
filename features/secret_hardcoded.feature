# language: pt
Funcionalidade: Detecção de segredo hardcoded — SecurityReviewerAgent
  Como engenheiro de segurança
  Quero que segredos hardcoded sejam detectados no diff
  Para evitar vazamento de credenciais em produção

  Cenário: Chave AWS hardcoded no diff
    Dado um diff contendo uma chave AWS hardcoded em "config/aws.go" linha 12
    Quando audito o escopo "diff"
    Então existe um Finding de categoria "secrets"
    E a severidade é pelo menos "alto"
    E o Finding tem arquivo e linha preenchidos
    E o segredo aparece apenas mascarado no relatório

  Cenário: Segredo nunca exposto em claro
    Dado um diff contendo uma chave AWS hardcoded em "config/aws.go" linha 12
    Quando audito o escopo "diff"
    Então o relatório não contém o valor do segredo em claro
