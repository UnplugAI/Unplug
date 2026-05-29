"""Dataset loaders for evaluation — downloads and normalizes public datasets."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Sample:
    """A single evaluation sample."""

    text: str
    label: int  # 1 = malicious, 0 = benign
    category: str = "unknown"
    source: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)


def load_jsonl(path: Path) -> list[Sample]:
    """Load samples from a JSONL file with fields: text, label, category."""
    samples = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            samples.append(
                Sample(
                    text=row["text"],
                    label=int(row.get("label", 0)),
                    category=row.get("category", "unknown"),
                    source=row.get("source", path.stem),
                    metadata={
                        k: v
                        for k, v in row.items()
                        if k not in ("text", "label", "category", "source")
                    },
                )
            )
    return samples


def load_csv(
    path: Path, text_col: str = "text", label_col: str = "label", category_col: str = "category"
) -> list[Sample]:
    """Load samples from a CSV file."""
    samples = []
    with path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            samples.append(
                Sample(
                    text=row[text_col],
                    label=int(row.get(label_col, 0)),
                    category=row.get(category_col, "unknown"),
                    source=path.stem,
                )
            )
    return samples


def load_parquet(
    path: Path, text_col: str = "text", label_col: str = "label", category_col: str = "category"
) -> list[Sample]:
    """Load samples from a Parquet file. Requires pyarrow."""
    try:
        import pyarrow.parquet as pq
    except ImportError:
        msg = "pyarrow required for parquet loading: uv add pyarrow"
        raise ImportError(msg) from None

    table = pq.read_table(path)
    df = table.to_pydict()
    samples = []
    for i in range(len(df[text_col])):
        samples.append(
            Sample(
                text=str(df[text_col][i]),
                label=int(df.get(label_col, [0] * len(df[text_col]))[i]),
                category=str(df.get(category_col, ["unknown"] * len(df[text_col]))[i]),
                source=path.stem,
            )
        )
    return samples


def load_auto(path: Path, **kwargs: Any) -> list[Sample]:
    """Auto-detect format by extension and load."""
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        return load_jsonl(path)
    if suffix == ".csv":
        return load_csv(path, **kwargs)
    if suffix == ".parquet":
        return load_parquet(path, **kwargs)
    msg = f"Unsupported format: {suffix}"
    raise ValueError(msg)
