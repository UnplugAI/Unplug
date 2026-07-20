"""CLI: unplug-models: list, download, and upgrade cached checkpoints."""

from __future__ import annotations

import argparse
import json
import sys

from unplug.core.runtime.model_runtime import active_model_status
from unplug.exceptions import ConfigError, ModelError
from unplug.ml.catalog import load_catalog
from unplug.ml.store import ModelStore


def _hf_error_hint(exc: BaseException) -> str | None:
    module = type(exc).__module__
    if module.startswith("huggingface_hub"):
        return (
            "Check network access and that the Hugging Face repo/revision exists "
            "for this catalog tier."
        )
    cause = exc.__cause__
    if cause is not None and cause is not exc:
        return _hf_error_hint(cause)
    return None


def _cmd_list(args: argparse.Namespace) -> int:
    store = ModelStore()
    rows = store.list_status()
    if args.format == "json":
        print(json.dumps(rows, indent=2))
        return 0
    cat = load_catalog()
    print(f"Default tier: {cat.default_tier}")
    print(f"Cache root:   {store.cache_root}\n")
    for row in rows:
        status = "installed" if row["installed"] else "not installed"
        if row.get("upgrade_available"):
            status = "upgrade available"
        print(f"  {row['tier']:8}  {row['name']:16}  [{status}]")
        print(f"            repo: {row['repo_id']} @ {row['catalog_revision']}")
        if row.get("path"):
            print(f"            path: {row['path']}")
        if row.get("description"):
            print(f"            {row['description']}")
        print()
    return 0


def _cmd_download(args: argparse.Namespace) -> int:
    store = ModelStore()
    tier = args.tier or load_catalog().default_tier
    try:
        path = store.ensure_tier(tier, force=args.force)
    except (ConfigError, ModelError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except ImportError as exc:
        print(
            f"Error: {exc}\n"
            f"Install ML extras: pip install 'unplug-ai[ml]'\n"
            f"Or set UNPLUG_MODEL_PATH to a local checkpoint directory.",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:
        hint = _hf_error_hint(exc)
        if hint is not None:
            print(f"Error: {exc}\n{hint}", file=sys.stderr)
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Downloaded {tier} → {path}")
    return 0


def _cmd_status(_args: argparse.Namespace) -> int:
    print(json.dumps(active_model_status(), indent=2))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="unplug-models",
        description="Manage Unplug ML model cache (download once, reuse locally)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for list",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    list_p = sub.add_parser("list", help="Show catalog tiers and install status")
    list_p.set_defaults(func=_cmd_list)

    dl_p = sub.add_parser("download", help="Download a tier from Hugging Face")
    dl_p.add_argument("tier", nargs="?", help="catalog tier (default: catalog default)")
    dl_p.add_argument("--force", action="store_true", help="Re-download even if cached")
    dl_p.set_defaults(func=_cmd_download)

    up_p = sub.add_parser("upgrade", help="Re-download tier to pick up catalog revision")
    up_p.add_argument("tier", nargs="?", help="catalog tier (default: catalog default)")

    def _upgrade_cmd(a: argparse.Namespace) -> int:
        return _cmd_download(argparse.Namespace(**{**vars(a), "force": True}))

    up_p.set_defaults(func=_upgrade_cmd)

    st_p = sub.add_parser("status", help="JSON status (cache paths, env overrides)")
    st_p.set_defaults(func=_cmd_status)

    args = parser.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
