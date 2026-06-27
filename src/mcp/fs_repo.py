"""FileSystemRepo — adapter read-only sobre um repositório real no disco.

Mesma interface do InMemoryRepo (changed_files, iter_files, search, manifest_files,
lines, linguagem). É o "seam" da Clean Architecture: troca-se o repo e o resto
(agent, guardrails, orquestrador, contratos) fica idêntico.
"""
from __future__ import annotations

import os
import re
import subprocess
from typing import Iterable, Optional

from src.mcp.repo import _EXT_LANG, _MANIFEST_NAMES

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "vendor", "dist", "build", "__pycache__"}
_MAX_BYTES = 1_000_000  # ignora arquivos > 1 MB (binários/grandes)


class FileSystemRepo:
    def __init__(self, root: str, base_ref: Optional[str] = None):
        """
        root:     caminho do repositório alvo (read-only).
        base_ref: ref git para o diff (ex. "HEAD~1", "origin/main"). Se None,
                  changed_files() retorna vazio (use escopo "full" para varrer tudo).
        """
        self.root = os.path.abspath(root)
        self.base_ref = base_ref

    # ── leitura básica ──
    def linguagem(self, path: str) -> Optional[str]:
        for ext, lang in _EXT_LANG.items():
            if path.endswith(ext):
                return lang
        return None

    def _abs(self, rel: str) -> str:
        return os.path.join(self.root, rel)

    def _read(self, rel: str) -> str:
        try:
            if os.path.getsize(self._abs(rel)) > _MAX_BYTES:
                return ""
            with open(self._abs(rel), "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except (OSError, ValueError):
            return ""

    def lines(self, path: str) -> list[str]:
        return self._read(path).splitlines()

    # ── enumeração ──
    def _walk(self) -> Iterable[str]:
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for name in filenames:
                rel = os.path.relpath(os.path.join(dirpath, name), self.root)
                yield rel

    def iter_files(self, paths: Optional[list] = None) -> Iterable[tuple]:
        for rel in self._walk():
            if paths and rel not in paths:
                continue
            content = self._read(rel)
            if content:
                yield rel, content.splitlines()

    def changed_files(self) -> list[dict]:
        if not self.base_ref:
            return []
        try:
            out = subprocess.run(
                ["git", "-C", self.root, "diff", "--name-status", self.base_ref],
                capture_output=True, text=True, timeout=30,
            ).stdout
        except (subprocess.SubprocessError, OSError):
            return []
        status_map = {"A": "added", "M": "modified", "D": "deleted"}
        changed: list[dict] = []
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            status = status_map.get(parts[0][0], "modified")
            path = parts[-1]
            changed.append({"path": path, "status": status, "linguagem": self.linguagem(path)})
        return changed

    def search(self, pattern: str, paths: Optional[list] = None) -> list[dict]:
        try:
            rx = re.compile(pattern)
        except re.error:
            rx = re.compile(re.escape(pattern))
        out: list[dict] = []
        for path, lines in self.iter_files(paths):
            for i, line in enumerate(lines, start=1):
                if rx.search(line):
                    out.append({"arquivo": path, "linha": i, "trecho": line.strip()[:240]})
        return out

    def manifest_files(self) -> dict:
        result: dict = {}
        for rel in self._walk():
            if rel.split("/")[-1] in _MANIFEST_NAMES:
                result[rel] = self._read(rel)
        return result
