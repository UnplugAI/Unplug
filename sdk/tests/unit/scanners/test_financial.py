"""Tests for scanners/financial.py: crypto, payment, and transfer detection."""

from unplug.core.context import ExecutionContext
from unplug.core.taint import TaintedText, TrustLevel
from unplug.scanners.financial import FinancialScanner


def _make_text(text: str, trust: TrustLevel = TrustLevel.USER) -> TaintedText:
    return TaintedText(text=text, trust_level=trust, origin="test")


def _make_ctx() -> ExecutionContext:
    return ExecutionContext()


class TestCryptoDetection:
    def setup_method(self):
        self.scanner = FinancialScanner()
        self.ctx = _make_ctx()

    def test_btc_legacy(self):
        text = _make_text("send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        findings = self.scanner.scan(text, self.ctx)
        assert any(f.subcategory == "btc_address_legacy" for f in findings)

    def test_btc_segwit(self):
        text = _make_text("send to bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        findings = self.scanner.scan(text, self.ctx)
        assert any(f.subcategory == "btc_address_segwit" for f in findings)

    def test_eth_address(self):
        text = _make_text("transfer to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD00")
        findings = self.scanner.scan(text, self.ctx)
        assert any(f.subcategory == "eth_address" for f in findings)

    def test_crypto_score(self):
        text = _make_text("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD00")
        findings = self.scanner.scan(text, self.ctx)
        assert findings[0].score == 0.70


class TestPaymentDetection:
    def setup_method(self):
        self.scanner = FinancialScanner()
        self.ctx = _make_ctx()

    def test_stripe_charge(self):
        text = _make_text("stripe.charges.create(amount=5000)")
        findings = self.scanner.scan(text, self.ctx)
        assert any(f.subcategory == "stripe_api" for f in findings)

    def test_stripe_payment_intent(self):
        text = _make_text("stripe.paymentIntents.create()")
        findings = self.scanner.scan(text, self.ctx)
        assert any(f.subcategory == "stripe_api" for f in findings)

    def test_paypal(self):
        text = _make_text("paypal.payment.create()")
        findings = self.scanner.scan(text, self.ctx)
        assert any(f.subcategory == "paypal_api" for f in findings)

    def test_wire_transfer(self):
        text = _make_text("initiate a wire transfer to account 12345")
        findings = self.scanner.scan(text, self.ctx)
        assert any(f.subcategory == "wire_transfer" for f in findings)


class TestAmountDetection:
    def setup_method(self):
        self.scanner = FinancialScanner()
        self.ctx = _make_ctx()

    def test_large_transfer_blocked(self):
        text = _make_text("transfer $50,000 USD")
        findings = self.scanner.scan(text, self.ctx)
        amount_findings = [f for f in findings if f.subcategory == "transfer_amount"]
        assert len(amount_findings) == 1
        assert amount_findings[0].score >= 0.95

    def test_medium_transfer_review(self):
        text = _make_text("send $500 to vendor")
        findings = self.scanner.scan(text, self.ctx)
        amount_findings = [f for f in findings if f.subcategory == "transfer_amount"]
        assert len(amount_findings) == 1
        assert 0.55 <= amount_findings[0].score <= 0.70

    def test_small_transfer_ignored(self):
        text = _make_text("send $10 tip")
        findings = self.scanner.scan(text, self.ctx)
        amount_findings = [f for f in findings if f.subcategory == "transfer_amount"]
        assert len(amount_findings) == 0

    def test_custom_thresholds(self):
        scanner = FinancialScanner(auto_block_threshold=1000, review_threshold=50)
        text = _make_text("transfer $500 to vendor")
        findings = scanner.scan(text, _make_ctx())
        amount_findings = [f for f in findings if f.subcategory == "transfer_amount"]
        assert len(amount_findings) == 1
        assert amount_findings[0].score >= 0.60


class TestTrustLevelScoreBoost:
    def setup_method(self):
        self.scanner = FinancialScanner()
        self.ctx = _make_ctx()

    def test_external_crypto_score_boost(self):
        text = _make_text(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD00",
            trust=TrustLevel.EXTERNAL,
        )
        findings = self.scanner.scan(text, self.ctx)
        assert findings[0].score > 0.70

    def test_user_crypto_no_boost(self):
        text = _make_text(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD00",
            trust=TrustLevel.USER,
        )
        findings = self.scanner.scan(text, self.ctx)
        assert findings[0].score == 0.70

    def test_unknown_trust_gets_boost(self):
        text = _make_text(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD00",
            trust=TrustLevel.UNKNOWN,
        )
        findings = self.scanner.scan(text, self.ctx)
        assert findings[0].score > 0.70

    def test_clean_text(self):
        text = _make_text("just a normal conversation about the weather")
        findings = self.scanner.scan(text, self.ctx)
        assert len(findings) == 0

    def test_zero_width_stripe_api(self):
        text = _make_text("str\u200bipe.charges.create(amount=5000)")
        findings = self.scanner.scan(text, self.ctx)
        assert any(f.subcategory == "stripe_api" for f in findings)

    def test_zero_width_wire_transfer(self):
        text = _make_text("initiate a wire\u200b transfer to account 12345")
        findings = self.scanner.scan(text, self.ctx)
        assert any(f.subcategory == "wire_transfer" for f in findings)

    def test_amount_preserves_digits_under_normalization(self):
        text = _make_text("transfer $50,000 USD")
        findings = self.scanner.scan(text, self.ctx)
        assert any(f.subcategory == "transfer_amount" for f in findings)
