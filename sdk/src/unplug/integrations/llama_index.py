"""LlamaIndex integration: node post-processing on retrieved chunks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from unplug import Guard
from unplug.core.taint import TrustLevel
from unplug.integrations.haystack import DocumentAction, DocumentScanOutcome, scan_document
from unplug.integrations.hooks import AgentHooks


class _TextNode(Protocol):
    text: str
    metadata: dict[str, Any]


@dataclass
class LlamaIndexGuardReport:
    """Summary of post-processing applied to retrieved nodes."""

    total: int = 0
    kept: int = 0
    wrapped: int = 0
    redacted: int = 0
    dropped: int = 0
    max_risk: float = 0.0


@dataclass
class UnplugNodePostprocessor:
    """LlamaIndex-style postprocessor: scan, wrap, redact, or drop retrieved nodes.

    Works with any object exposing ``text`` and ``metadata`` (LlamaIndex ``TextNode``,
    plain dicts, or custom RAG types). Does **not** import LlamaIndex at load time.

    Usage::

        from unplug.integrations.llama_index import UnplugNodePostprocessor

        post = UnplugNodePostprocessor()
        safe_nodes = post.postprocess_nodes(nodes)
    """

    hooks: AgentHooks = field(default_factory=AgentHooks)
    drop_on_block: bool = True
    wrap_safe: bool = True

    @property
    def guard(self) -> Guard:
        return self.hooks.guard

    def postprocess_nodes(self, nodes: list[Any]) -> list[Any]:
        """Return nodes that survived scanning (content may be wrapped/redacted)."""
        kept: list[Any] = []
        for node in nodes:
            outcome = self._scan_node(node)
            if outcome.dropped:
                continue
            self._set_node_text(node, outcome.content)
            kept.append(node)
        return kept

    def postprocess_nodes_with_report(
        self, nodes: list[Any]
    ) -> tuple[list[Any], LlamaIndexGuardReport]:
        report = LlamaIndexGuardReport(total=len(nodes))
        kept: list[Any] = []
        for node in nodes:
            outcome = self._scan_node(node)
            report.max_risk = max(report.max_risk, outcome.risk_score)
            if outcome.action == DocumentAction.DROPPED:
                report.dropped += 1
                continue
            if outcome.action == DocumentAction.REDACTED:
                report.redacted += 1
            elif outcome.action == DocumentAction.WRAPPED:
                report.wrapped += 1
            else:
                report.kept += 1
            self._set_node_text(node, outcome.content)
            kept.append(node)
        return kept, report

    def _scan_node(self, node: Any) -> DocumentScanOutcome:
        text, meta = self._read_node(node)
        trust = TrustLevel.EXTERNAL if meta.get("source_type") == "web" else TrustLevel.RETRIEVED
        return scan_document(
            self.guard,
            text,
            trust_level=trust,
            drop_on_block=self.drop_on_block,
            wrap_safe=self.wrap_safe,
        )

    @staticmethod
    def _read_node(node: Any) -> tuple[str, dict[str, Any]]:
        if isinstance(node, dict):
            return str(node.get("text") or node.get("content") or ""), dict(
                node.get("metadata") or {}
            )
        get_content = getattr(node, "get_content", None)
        if callable(get_content):
            text = str(get_content())
        else:
            text = str(getattr(node, "text", "") or "")
        meta = dict(getattr(node, "metadata", None) or {})
        return text, meta

    @staticmethod
    def _set_node_text(node: Any, content: str) -> None:
        if isinstance(node, dict):
            node["text"] = content
            return
        # Wrappers like LlamaIndex ``NodeWithScore`` proxy reads (``get_content``)
        # to an inner ``.node`` but don't expose a settable ``.text`` of their own.
        # Write to that inner node so the redaction reaches the text actually
        # inserted into the prompt instead of being silently dropped on the wrapper.
        target = getattr(node, "node", node)
        if hasattr(target, "text"):
            target.text = content
        elif hasattr(target, "set_content"):
            target.set_content(content)
        else:
            msg = f"Cannot write scanned content back to node type {type(node).__name__}"
            raise TypeError(msg)
