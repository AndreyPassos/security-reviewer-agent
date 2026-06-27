"""InMemoryRepo — repositório em memória para scanners determinísticos (mock).

Permite testar o pipeline sem tocar o filesystem. Os scanners do MCP recebem
uma instância de InMemoryRepo e leem dela (read-only).
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

_EXT_LANG = {
    ".go": "golang",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".py": "python",
    ".rb": "ruby",
    ".java": "java",
}

_MANIFEST_NAMES = ("go.mod", "go.sum", "package.json", "requirements.txt", "Pipfile", "pom.xml")


class InMemoryRepo:
    def __init__(self, files: Optional[dict] = None, changed=None):
        """
        files:   dict[path -> conteúdo (str)]
        changed: dict[path -> status ("added"|"modified"|"deleted")] OU
                 list[path] (assume "modified"). Subconjunto de `files`.
        """
        self.files: dict[str, str] = dict(files or {})
        if changed is None:
            self.changed: dict[str, str] = {}
        elif isinstance(changed, dict):
            self.changed = dict(changed)
        else:
            self.changed = {p: "modified" for p in changed}

    def linguagem(self, path: str) -> Optional[str]:
        for ext, lang in _EXT_LANG.items():
            if path.endswith(ext):
                return lang
        return None

    def changed_files(self) -> list[dict]:
        return [
            {"path": p, "status": s, "linguagem": self.linguagem(p)}
            for p, s in self.changed.items()
        ]

    def lines(self, path: str) -> list[str]:
        return self.files.get(path, "").splitlines()

    def iter_files(self, paths: Optional[list] = None) -> Iterable[tuple]:
        for path, content in self.files.items():
            if paths and path not in paths:
                continue
            yield path, content.splitlines()

    def search(self, pattern: str, paths: Optional[list] = None) -> list[dict]:
        """Retorna [{arquivo, linha (1-based), trecho}] para cada linha que casa `pattern`.

        Aceita regex; se o padrão não compilar (ex.: `eval(` tem parêntese solto),
        cai para busca literal (re.escape) em vez de falhar silenciosamente.
        """
        try:
            rx = re.compile(pattern)
        except re.error:
            rx = re.compile(re.escape(pattern))
        out: list[dict] = []
        for path, lines in self.iter_files(paths):
            for i, line in enumerate(lines, start=1):
                if rx.search(line):
                    out.append({"arquivo": path, "linha": i, "trecho": line.strip()})
        return out

    def manifest_files(self) -> dict:
        return {p: c for p, c in self.files.items() if p.split("/")[-1] in _MANIFEST_NAMES}
