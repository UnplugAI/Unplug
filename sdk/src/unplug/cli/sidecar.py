"""CLI: unplug-sidecar — verify and configure local unplug-server sidecar."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

import httpx

DEFAULT_URL = "http://127.0.0.1:8000"


def _base_url() -> str:
    return os.environ.get("UNPLUG_SERVER_URL", DEFAULT_URL).rstrip("/")


def _cmd_doctor(args: argparse.Namespace) -> int:
    url = (args.url or _base_url()).rstrip("/")
    try:
        with httpx.Client(timeout=args.timeout) as client:
            live = client.get(f"{url}/v1/health/live")
            live.raise_for_status()
            health = client.get(f"{url}/v1/health")
            health.raise_for_status()
            data: dict[str, Any] = health.json()
    except httpx.RequestError as exc:
        print(f"Sidecar not reachable at {url}: {exc}", file=sys.stderr)
        print(
            "\nStart the sidecar:\n"
            "  cd repos/unplug-server\n"
            "  docker compose -f docker-compose.sidecar.yml up\n"
            "Or see sdk/docs/DEPLOYMENT.md for embedded vs sidecar paths.",
            file=sys.stderr,
        )
        return 1

    ok = data.get("status") in ("ok", "degraded")
    print(f"url:              {url}")
    print(f"status:           {data.get('status')}")
    print(f"version:          {data.get('version')}")
    print(f"scanners_loaded:  {data.get('scanners_loaded')}")
    print(f"model_loaded:     {data.get('model_loaded')}")
    if args.format == "json":
        print(json.dumps(data, indent=2))
    if not ok:
        print("warning: health status is not ok", file=sys.stderr)
        return 1
    print("\nSDK env (no API key for local sidecar):")
    print(f"  export UNPLUG_SERVER_URL={url}")
    print('  # Guard(mode="server") — see examples/local_sidecar_client.py')
    return 0


def _cmd_env(args: argparse.Namespace) -> int:
    url = (args.url or _base_url()).rstrip("/")
    lines = [
        f'export UNPLUG_SERVER_URL="{url}"',
        "# unset UNPLUG_API_KEY for auth-disabled sidecar",
    ]
    text = "\n".join(lines)
    if args.shell == "fish":
        text = text.replace("export ", "set -gx ").replace('"', "")
    print(text)
    return 0


def main() -> None:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--url", default=None, help=f"Sidecar base URL (default: {DEFAULT_URL})")

    parser = argparse.ArgumentParser(
        description="Verify local unplug-server sidecar and print SDK env hints",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser(
        "doctor",
        parents=[common],
        help="GET /v1/health and print SDK env hints",
    )
    doctor.add_argument("--timeout", type=float, default=5.0)
    doctor.add_argument("--format", choices=["text", "json"], default="text")
    doctor.set_defaults(func=_cmd_doctor)

    env = sub.add_parser(
        "env",
        parents=[common],
        help="Print shell exports for Guard(mode=server)",
    )
    env.add_argument("--shell", choices=["bash", "fish"], default="bash")
    env.set_defaults(func=_cmd_env)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
