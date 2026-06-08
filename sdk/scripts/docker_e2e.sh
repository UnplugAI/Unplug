#!/usr/bin/env bash
# Build unplug-server sidecar in Docker and run SDK examples against it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd "${SDK_ROOT}/../.." && pwd)"
SERVER_DIR="${WORKSPACE_ROOT}/repos/unplug-server"
CHECKPOINT="${UNPLUG_SIDECAR_CHECKPOINT:-}"

if [[ -z "${CHECKPOINT}" ]]; then
  CHECKPOINT="${WORKSPACE_ROOT}/repos/unplug_exp/deliverables/v131-xsmall-pilot-checkpoints/extracted/v131-xsmall-ep5-8-9-10/checkpoint-66630"
fi

if [[ ! -f "${CHECKPOINT}/config.json" ]]; then
  echo "Checkpoint not found: ${CHECKPOINT}" >&2
  echo "Set UNPLUG_SIDECAR_CHECKPOINT to checkpoint-66630 directory." >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not installed" >&2
  exit 1
fi

export UNPLUG_SIDECAR_CHECKPOINT="${CHECKPOINT}"
export UNPLUG_SERVER_URL="${UNPLUG_SERVER_URL:-http://127.0.0.1:8000}"

cleanup() {
  (cd "${SERVER_DIR}" && docker compose -f docker-compose.sidecar.yml down -v --remove-orphans 2>/dev/null) || true
}
trap cleanup EXIT

echo "==> Building sidecar (checkpoint: ${CHECKPOINT})"
(cd "${SERVER_DIR}" && docker compose -f docker-compose.sidecar.yml build)

echo "==> Starting sidecar"
(cd "${SERVER_DIR}" && docker compose -f docker-compose.sidecar.yml up -d)

echo "==> Waiting for health"
for i in $(seq 1 90); do
  if curl -sf "${UNPLUG_SERVER_URL}/v1/health/live" >/dev/null 2>&1; then
    echo "    live after ${i}s"
    break
  fi
  if [[ "${i}" -eq 90 ]]; then
    echo "sidecar failed to become healthy" >&2
    (cd "${SERVER_DIR}" && docker compose -f docker-compose.sidecar.yml logs) >&2 || true
    exit 1
  fi
  sleep 2
done

curl -sf "${UNPLUG_SERVER_URL}/v1/health" | head -c 400
echo ""

cd "${SDK_ROOT}"
echo "==> unplug-sidecar doctor"
uv run unplug-sidecar doctor --url "${UNPLUG_SERVER_URL}"

echo "==> examples/local_sidecar_client.py"
uv run python examples/local_sidecar_client.py

echo "==> examples/hosted_client.py (no API key sidecar)"
uv run python examples/hosted_client.py

echo "==> Docker E2E passed"
