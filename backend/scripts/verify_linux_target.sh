#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

export SHADOWTRACE_REQUIRE_GEOIP=1
export SHADOWTRACE_REQUIRE_PYG_EXTENSIONS=1
PORT="${SHADOWTRACE_VERIFY_PORT:-8000}"
export SHADOWTRACE_VERIFY_PORT="${PORT}"

if command -v nmcli >/dev/null 2>&1; then
  NETWORK_STATE="$(nmcli networking 2>/dev/null || true)"
  if [[ "${NETWORK_STATE}" != "disabled" ]]; then
    echo "NetworkManager networking must be disabled before target verification; run: nmcli networking off" >&2
    exit 1
  fi
fi

python scripts/verify_offline.py --strict --runtime --runtime-dossier
python scripts/run_pipeline.py --sample
python -m pytest tests
python scripts/audit_prd_artifacts.py
uvicorn shadowtrace.main:app --host 127.0.0.1 --port "${PORT}" &
SERVER_PID=$!

SERVER_READY=0
for _attempt in {1..30}; do
  if ! kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    echo "FastAPI server exited before readiness check completed" >&2
    exit 1
  fi
  if python - <<'PY'
import os
from urllib.request import urlopen

try:
    port = os.environ["SHADOWTRACE_VERIFY_PORT"]
    with urlopen(f"http://127.0.0.1:{port}/api/alerts?limit=1&offset=0", timeout=1) as response:
        raise SystemExit(0 if response.status == 200 else 1)
except Exception:
    raise SystemExit(1)
PY
  then
    SERVER_READY=1
    break
  fi
  sleep 1
done

if [[ "${SERVER_READY}" != "1" ]]; then
  echo "FastAPI server did not become ready on 127.0.0.1:${PORT}" >&2
  exit 1
fi

python scripts/smoke_api.py --base-url "http://127.0.0.1:${PORT}"
