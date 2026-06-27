"""Observabilidade — trace estruturado do agente por trace_id.

Emite um evento por passo (pipeline_start, guardrail_pre, tool_call, agent_execute,
guardrail_post, pipeline_end) com tool, status, contagem e latência. Vai para stderr
por padrão, então o stdout (relatório JSON) continua limpo para piping/CI.
"""
from __future__ import annotations

import json
import sys
import time


class Tracer:
    def __init__(self, trace_id: str, enabled: bool = True, stream=None, as_json: bool = False):
        self.trace_id = trace_id
        self.enabled = enabled
        self.stream = stream or sys.stderr
        self.as_json = as_json
        self._seq = 0

    def event(self, event: str, **fields) -> None:
        if not self.enabled:
            return
        self._seq += 1
        if self.as_json:
            rec = {"ts": round(time.time(), 3), "seq": self._seq,
                   "trace_id": self.trace_id, "event": event, **fields}
            self.stream.write(json.dumps(rec, ensure_ascii=False) + "\n")
        else:
            extra = "  ".join(f"{k}={v}" for k, v in fields.items())
            self.stream.write(f"  [{self.trace_id}] {self._seq:>2} {event:<14} {extra}\n")
        self.stream.flush()

    def tool_call(self, tool: str, *, status, count=None, latency_ms=None, label="") -> None:
        nome = f"{tool}('{label}')" if label else tool
        self.event("tool_call", tool=nome, status=status, count=count, latency_ms=latency_ms)


def now_ms() -> float:
    return time.perf_counter() * 1000.0
