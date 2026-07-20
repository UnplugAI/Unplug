.PHONY: install lint typecheck format fix check check-ci test test-cov test-security \
	test-ml test-ml-harness test-frameworks test-frameworks-live test-all-local \
	smoke-ml smoke-ml-hooks docker-e2e audit audit-ml scenarios attack-gate examples

install:
	uv sync --all-extras --dev

lint:
	uv run ruff check .

typecheck:
	uv run mypy

format:
	uv run ruff format .

fix:
	uv run ruff check --fix .
	uv run ruff format .

check: lint typecheck
	uv run ruff format --check .
	uv run pytest -q

check-ci: check
	uv run pytest tests/integration/test_exfil_demo_integration.py -q
	uv run python examples/agent_exfil_demo.py
	uv run pytest tests/security tests/integration/test_deployment_modes.py tests/unit/ml/test_ml_validation.py tests/integration/test_ml_integration.py tests/integration/test_scenario_replay.py -q
	$(MAKE) scenarios
	$(MAKE) attack-gate

attack-gate:
	uv run python -m benchmarks.attacks.ci_gate

# Offline ML unit + integration (synthetic checkpoints). Weight-backed cases
# skip cleanly when UNPLUG_MODEL_PATH / cache checkpoint is absent.
test-ml:
	uv run pytest tests/unit/ml tests/integration/test_ml_integration.py tests/integration/test_guard_ml.py -v

# Broader local ML harness: unit/integration ML + optional weight probes + offline smoke.
# Exits 0 when weights are missing (pytest skip / smoke-ml soft-fail documented in docs).
test-ml-harness:
	uv run pytest tests/unit/ml tests/integration/test_ml_integration.py tests/integration/test_guard_ml.py tests/unit/ml/test_ml_validation.py -v
	@if uv run python -c "from unplug.ml.validation import resolve_validation_checkpoint; import sys; sys.exit(0 if resolve_validation_checkpoint(require_weights=True) else 1)"; then \
		$(MAKE) smoke-ml; \
	else \
		echo "skip smoke-ml: no checkpoint weights (set UNPLUG_MODEL_PATH or run unplug-models download tiny)"; \
	fi
	$(MAKE) smoke-ml-hooks

smoke-ml:
	uv run python scripts/smoke_local_ml.py
	$(MAKE) audit-ml

# Offline: synthetic checkpoint + Guard + LangGraph-style hooks (no hub download).
smoke-ml-hooks:
	uv run python scripts/smoke_ml_hooks.py

# Framework adapters without installing agent SDKs (matrix + adapter unit/integration).
test-frameworks:
	uv run pytest tests/security/test_agent_integration_matrix.py tests/integration/test_integration_adapters.py tests/integration/test_integrations.py tests/unit/integrations -v

# Live framework imports (needs one or more framework extras; skips if missing).
test-frameworks-live:
	uv run pytest tests/optional/live -v -m requires_integrations

scenarios:
	@for f in benchmarks/scenarios/*.yaml; do \
		uv run python benchmarks/run_scenario.py "$$f" || exit 1; \
	done

examples:
	uv run python examples/agent_exfil_demo.py
	uv run python examples/langgraph_hooks_demo.py
	uv run python examples/agno_hooks_demo.py
	uv run pytest tests/integration/test_examples.py -q -k "not docker_e2e"

docker-e2e:
	RUN_DOCKER_E2E=1 bash scripts/docker_e2e.sh
	RUN_DOCKER_E2E=1 uv run pytest tests/integration/test_examples.py::test_docker_e2e_script -v -o addopts=

test:
	uv run pytest -v

test-cov:
	uv run pytest -q -m "not requires_docker and not slow" --cov=unplug --cov-report=xml:coverage.xml --cov-report=term --cov-fail-under=80 --junitxml=pytest.xml

test-security:
	uv run pytest tests/security tests/unit/core/agent/test_agent_hardening.py -v

# Local pre-release composition: CI parity + frameworks + ML harness + examples.
# Does not run docker-e2e or live framework installs (see docs/TESTING_HARNESS.md).
test-all-local: check-ci test-cov test-frameworks test-ml-harness examples

audit:
	uv run unplug-audit

audit-ml:
	uv run unplug-audit --require-ml
