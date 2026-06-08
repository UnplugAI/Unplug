.PHONY: install lint format fix check check-ci test test-security audit

install:
	uv sync --all-extras --dev

lint:
	uv run ruff check .

format:
	uv run ruff format .

fix:
	uv run ruff check --fix .
	uv run ruff format .

check: lint
	uv run ruff format --check .
	uv run pytest -q

check-ci: check
	uv run pytest tests/test_exfil_demo_integration.py -q
	uv run python examples/agent_exfil_demo.py
	uv run pytest \
		tests/test_adversarial.py \
		tests/test_false_positives.py \
		tests/test_encodings.py \
		tests/test_secrets.py \
		tests/test_scan_policy.py \
		tests/test_security_stress.py \
		tests/test_sdk_coverage.py \
		tests/test_agent_hardening.py \
		-q

test:
	uv run pytest -v

test-security:
	uv run pytest \
		tests/test_adversarial.py \
		tests/test_false_positives.py \
		tests/test_encodings.py \
		tests/test_secrets.py \
		tests/test_scan_policy.py \
		tests/test_security_stress.py \
		tests/test_sdk_coverage.py \
		tests/test_agent_hardening.py \
		tests/test_financial.py \
		-v

audit:
	uv run unplug-audit

audit-ml:
	uv run unplug-audit --require-ml
