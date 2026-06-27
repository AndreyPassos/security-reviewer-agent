"""Contratos Pydantic — SecurityReviewerAgent (auditor AppSec orientado por contratos).

Espelho executável de schemas/schemas.json. Todo objeto que cruza fronteira de
agente/tool carrega trace_id. Reutilizável em qualquer produto: a stack alvo é
informada em AuditInput.stack, não fixada no código.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severidade(str, Enum):
    CRITICO = "critico"
    ALTO = "alto"
    MEDIO = "medio"
    BAIXO = "baixo"


class Categoria(str, Enum):
    AUTH = "auth"
    SECRETS = "secrets"
    INPUT_OUTPUT = "input_output"
    API = "api"
    FRONTEND = "frontend"
    DEPS = "deps"
    CONFIG = "config"
    CONCURRENCY = "concurrency"
    CRYPTO = "crypto"
    DB = "db"
    OTHER = "other"


class NivelSeguranca(str, Enum):
    BAIXO = "baixo"
    MEDIO = "medio"
    ALTO = "alto"


class Escopo(str, Enum):
    DIFF = "diff"
    MODULO = "modulo"
    FULL = "full"


class AuditInput(BaseModel):
    escopo: Escopo
    repo_path: str = Field(min_length=1)
    paths: list[str] = Field(default_factory=list)
    stack: list[str] = Field(default_factory=list)
    integracoes: list[str] = Field(default_factory=list)
    trace_id: str = Field(min_length=1)


class ArquivoAlterado(BaseModel):
    path: str = Field(min_length=1)
    status: str  # added | modified | deleted
    linguagem: Optional[str] = None
    linhas_adicionadas: int = Field(default=0, ge=0)
    linhas_removidas: int = Field(default=0, ge=0)
    trace_id: str = Field(min_length=1)


class Ocorrencia(BaseModel):
    arquivo: str = Field(min_length=1)
    linha: int = Field(ge=1)
    trecho: str = Field(min_length=1)
    padrao: str
    trace_id: str = Field(min_length=1)


class DependenciaVulneravel(BaseModel):
    pacote: str = Field(min_length=1)
    versao: str = Field(min_length=1)
    cve: str = Field(pattern=r"^CVE-\d{4}-\d+$")
    severidade: Severidade
    versao_corrigida: Optional[str] = None
    trace_id: str = Field(min_length=1)


class SegredoDetectado(BaseModel):
    arquivo: str = Field(min_length=1)
    linha: int = Field(ge=1)
    tipo: str  # aws_access_key | jwt | senha | private_key | api_token
    valor_mascarado: str  # SEMPRE mascarado, nunca em claro
    trace_id: str = Field(min_length=1)


class Finding(BaseModel):
    id: str = Field(pattern=r"^SEC-\d{3,}$")
    titulo: str = Field(min_length=1)
    categoria: Categoria
    severidade: Severidade
    arquivo: str = Field(min_length=1)
    linha: int = Field(ge=1)
    # Evidência obrigatória e não-vazia: a regra anti-alucinação do guardrail GR-SEC01.
    evidencia: str = Field(min_length=1)
    impacto: str = Field(min_length=1)
    correcao: str = Field(min_length=1)
    owasp: Optional[str] = None
    confianca: float = Field(ge=0.0, le=1.0)
    trace_id: str = Field(min_length=1)


class ResumoSeveridade(BaseModel):
    critico: int = Field(default=0, ge=0)
    alto: int = Field(default=0, ge=0)
    medio: int = Field(default=0, ge=0)
    baixo: int = Field(default=0, ge=0)


class AuditReport(BaseModel):
    trace_id: str = Field(min_length=1)
    escopo: Escopo
    resumo: ResumoSeveridade
    nivel_seguranca: NivelSeguranca
    findings: list[Finding] = Field(default_factory=list)
    top_riscos: list[str] = Field(default_factory=list)
    hitl_pendente: bool = False
    observacoes: Optional[str] = None


class PipelineState(BaseModel):
    trace_id: str = Field(min_length=1)
    input: Optional[AuditInput] = None
    arquivos: list[ArquivoAlterado] = Field(default_factory=list)
    ocorrencias: list[Ocorrencia] = Field(default_factory=list)
    dependencias: list[DependenciaVulneravel] = Field(default_factory=list)
    segredos: list[SegredoDetectado] = Field(default_factory=list)
    # Amostra de código real (read-only) usada só pelo agente LLM; mock ignora.
    amostra_codigo: list[Ocorrencia] = Field(default_factory=list)
    report: Optional[AuditReport] = None
    hitl_pendente: bool = False
