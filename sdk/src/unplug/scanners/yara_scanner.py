"""Optional YARA scanner: multi-string code/SQL/template/XSS rules from NeMo corpus."""

from __future__ import annotations

from collections.abc import Generator

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.normalize import Normalizer
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.taint import TaintedText
from unplug.data.maps_loader import default_scanner_config
from unplug.models import Finding
from unplug.scanners.base import BaseScanner
from unplug.scanners.yara_loader import get_yara_rules

_DEFAULT_CONFIG = default_scanner_config("yara")

# YARA rules use AND conditions regex cannot express in one pass (e.g. SQL keyword + comment).
_RULE_SCORES: dict[str, float] = {
    "sql_injection": 0.92,
    "import_shells": 0.90,
    "import_networking": 0.85,
    "jinja_injection": 0.88,
    "markdown_xss": 0.86,
}


class YaraCodeScanner(BaseScanner):
    """Scan normalized text with bundled YARA rules (requires yara-python)."""

    name = "yara"

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        super().__init__(config=config or _DEFAULT_CONFIG, metrics=metrics)
        self._normalizer = Normalizer()

    def _scan(self, text: TaintedText, context: ExecutionContext) -> Generator[Finding, None, None]:
        rules = get_yara_rules()
        norm = self._normalizer.normalize(text.text)
        scan_text = norm.text
        if not scan_text.strip():
            return

        matches = rules.match(data=scan_text)
        if not matches:
            return

        seen_rules: set[str] = set()
        for match in matches:
            rule_name = match.rule
            if rule_name in seen_rules:
                continue
            seen_rules.add(rule_name)

            span_start: int | None = None
            span_end: int | None = None
            for string_match in match.strings:
                for instance in string_match.instances:
                    norm_start = instance.offset
                    norm_end = instance.offset + instance.matched_length
                    o_start, o_end = norm.to_original_span(norm_start, norm_end)
                    span_start = o_start if span_start is None else min(span_start, o_start)
                    span_end = o_end if span_end is None else max(span_end, o_end)

            if span_start is None or span_end is None:
                span_start, span_end = 0, len(text.text)

            score = _RULE_SCORES.get(rule_name, self._config.base_score)
            yield Finding(
                category=self.name,
                subcategory=rule_name,
                stage="yara",
                span_start=max(0, span_start),
                span_end=min(len(text.text), span_end),
                score=score,
                evidence=f"YARA rule matched: {rule_name}",
                replacement=f"[BLOCKED:{rule_name}]",
            )
