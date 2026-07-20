.PHONY: install lint typecheck format fix check check-ci test test-cov test-security test-ml smoke-ml docker-e2e audit audit-ml scenarios attack-gate examples

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

test-ml:
	uv run pytest tests/unit/ml tests/integration/test_ml_integration.py tests/integration/test_guard_ml.py -v

smoke-ml:
	uv run python scripts/smoke_local_ml.py
	$(MAKE) audit-ml

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

audit:
	uv run unplug-audit

audit-ml:
	uv run unplug-audit --require-ml
