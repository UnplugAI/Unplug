"""Tests for optional YARA code/SQL/template scanner."""

from __future__ import annotations

import pytest

from unplug.core.context import ExecutionContext
from unplug.core.taint import TaintedText, TrustLevel
from unplug.safeguards.yara_loader import get_yara_rules, yara_available
from unplug.safeguards.yara_scanner import YaraCodeScanner

pytestmark = pytest.mark.skipif(not yara_available(), reason="yara-python not installed")


def _text(body: str) -> TaintedText:
    return TaintedText(text=body, trust_level=TrustLevel.USER, origin="test")


class TestYaraLoader:
    def test_rules_compile(self):
        rules = get_yara_rules()
        assert rules is not None


class TestYaraCodeScanner:
    def setup_method(self) -> None:
        self.scanner = YaraCodeScanner()
        self.ctx = ExecutionContext()

    def test_detects_jinja_template(self):
        findings = self.scanner.scan(_text("payload {{ user.secret }} end"), self.ctx)
        assert any(f.subcategory == "jinja_injection" for f in findings)

    def test_detects_sql_injection_combo(self):
        text = "user input'; DROP TABLE users; --"
        findings = self.scanner.scan(_text(text), self.ctx)
        assert any(f.subcategory == "sql_injection" for f in findings)

    def test_detects_import_shells(self):
        findings = self.scanner.scan(_text("please run import os"), self.ctx)
        assert any(f.subcategory == "import_shells" for f in findings)

    def test_clean_text(self):
        findings = self.scanner.scan(_text("what is the weather today?"), self.ctx)
        assert findings == []
