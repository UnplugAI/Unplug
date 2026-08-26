"""Download public evaluation datasets into ../datasets/."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmarks.loader import Sample


def _repo_datasets_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "datasets"


def _export_jsonl(samples: list[Sample], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for s in samples:
            row = {
                "text": s.text,
                "label": s.label,
                "category": s.category,
                "source": s.source,
            }
            f.write(json.dumps(row) + "\n")


# unplug-tiny was fine-tuned on the "train" split of this dataset, so scoring the
# model against it measures memorisation. "test" is the held-out split the model
# card gates on. Do not change this default.
NEURALCHEMY_SPLIT = "test"


def download_neuralchemy(
    out_dir: Path, *, limit: int | None = None, split: str = NEURALCHEMY_SPLIT
) -> Path:
    from datasets import load_dataset

    ds = load_dataset("neuralchemy/Prompt-injection-dataset", "core", split=split)
    samples: list[Sample] = []
    for i, row in enumerate(ds):
        if limit is not None and i >= limit:
            break
        text = row.get("text") or row.get("prompt") or row.get("input") or ""
        if not text:
            continue
        label_raw = row.get("label", row.get("is_injection", 0))
        malicious = str(label_raw).lower() in ("1", "true", "injection", "malicious")
        label = 1 if malicious else int(label_raw)
        category = str(row.get("category", row.get("attack_type", "unknown")))
        samples.append(Sample(text=text, label=label, category=category, source="neuralchemy"))
    out = out_dir / "neuralchemy.jsonl"
    _export_jsonl(samples, out)
    return out


def download_microsoft_subset(out_dir: Path, *, limit: int = 5000) -> Path:
    import json

    from datasets import load_dataset

    ds = load_dataset("microsoft/llmail-inject-challenge", split="Phase1", streaming=True)
    samples: list[Sample] = []
    for i, row in enumerate(ds):
        if i >= limit:
            break
        text = row.get("body") or row.get("output") or row.get("text") or ""
        if not text:
            continue
        label = 0
        objectives_raw = row.get("objectives", "")
        if objectives_raw:
            try:
                objectives = json.loads(objectives_raw)
                if objectives.get("defense.undetected"):
                    label = 1
            except json.JSONDecodeError:
                pass
        if not label and row.get("scenario", ""):
            scenario = str(row["scenario"]).lower()
            if "inject" in scenario or scenario.startswith("level"):
                label = 1
        samples.append(
            Sample(text=text, label=int(label), category="indirect_injection", source="microsoft")
        )
    out = out_dir / "microsoft_indirect.jsonl"
    _export_jsonl(samples, out)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Download benchmark datasets")
    parser.add_argument(
        "--dataset",
        choices=["neuralchemy", "microsoft", "all"],
        default="all",
    )
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--neuralchemy-split",
        default=NEURALCHEMY_SPLIT,
        choices=["train", "validation", "test"],
        help="train overlaps unplug-tiny fine-tuning data; results are not comparable",
    )
    args = parser.parse_args()

    out_dir = args.out or _repo_datasets_dir()
    paths: list[Path] = []
    if args.dataset in ("neuralchemy", "all"):
        paths.append(download_neuralchemy(out_dir, limit=args.limit, split=args.neuralchemy_split))
    if args.dataset in ("microsoft", "all"):
        paths.append(download_microsoft_subset(out_dir, limit=args.limit or 5000))
    for p in paths:
        print(p)


if __name__ == "__main__":
    main()
