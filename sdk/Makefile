.PHONY: install lint format fix check check-ci test test-security test-ml smoke-ml audit audit-ml scenarios

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
		tests/test_deployment_modes.py \
		tests/test_ml_validation.py \
		tests/test_ml_integration.py \
		tests/test_scenario_replay.py \
		-q
	$(MAKE) scenarios

test-ml:
	uv run pytest tests/test_ml_validation.py tests/test_ml_integration.py tests/test_guard_ml.py tests/test_head_tail.py tests/test_span_ml.py tests/test_dual_head_ml.py -v

smoke-ml:
	uv run python scripts/smoke_local_ml.py
	$(MAKE) audit-ml

scenarios:
	@for f in benchmarks/scenarios/*.yaml; do \
		uv run python benchmarks/run_scenario.py "$$f" || exit 1; \
	done

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
