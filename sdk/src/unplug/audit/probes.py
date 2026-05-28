"""FP and encoding probe batteries for unplug-audit."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from unplug import Guard
from unplug.audit.paths import resolve_probe_path
from unplug.config.guard import GuardConfig


def default_fp_probes_path(workspace_root: Path) -> Path:
    return resolve_probe_path("fp_probe_queries.json", workspace_root)


def default_encoding_probes_path(workspace_root: Path) -> Path:
    return resolve_probe_path("encoding_probe_queries.json", workspace_root)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def materialize_encoding_probe(probe: dict[str, Any]) -> str:
    fmt = probe.get("format", "literal")
    if fmt == "literal":
        return str(probe["text"])
    inner = str(probe["inner_text"])
    blob = _b64(inner)
    wrapper = str(probe.get("wrapper", "{blob}"))
    return wrapper.format(blob=blob)


def _confusion_rows(
    probes: list[dict[str, Any]],
    *,
    text_for: Any,
    guard: Guard,
) -> tuple[list[dict[str, Any]], int, int, int, int]:
    rows: list[dict[str, Any]] = []
    tp = fp = tn = fn = 0
    for probe in probes:
        text = text_for(probe)
        result = guard.scan(text)
        expect = bool(probe.get("expect_detected"))
        detected = not result.safe
        if expect and detected:
            tp += 1
            outcome = "tp"
        elif expect and not detected:
            fn += 1
            outcome = "fn"
        elif not expect and detected:
            fp += 1
            outcome = "fp"
        else:
            tn += 1
            outcome = "tn"
        rows.append(
            {
                "id": probe.get("id"),
                "expect_detected": expect,
                "outcome": outcome,
                "action": result.action.value,
                "safe": result.safe,
                "finding_count": len(result.findings),
            }
        )
    return rows, tp, fp, tn, fn


def run_fp_probe_suite(
    probes_path: Path,
    *,
    guard: Guard | None = None,
    base_config: GuardConfig | None = None,
) -> dict[str, Any]:
    if not probes_path.is_file():
        return {"error": f"fp probes not found: {probes_path}", "all_passed": False, "results": []}

    probes = json.loads(probes_path.read_text(encoding="utf-8"))
    g = guard or Guard(config=base_config)
    rows, tp, fp, tn, fn = _confusion_rows(
        probes,
        text_for=lambda probe: str(probe["text"]),
        guard=g,
    )
    return {
        "probes_file": str(probes_path),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "all_passed": fp == 0 and fn == 0,
        "results": rows,
    }


def run_encoding_probe_suite(
    probes_path: Path,
    *,
    guard: Guard | None = None,
    base_config: GuardConfig | None = None,
) -> dict[str, Any]:
    if not probes_path.is_file():
        return {
            "error": f"encoding probes not found: {probes_path}",
            "all_passed": False,
            "encoding_probes_pass": False,
            "results": [],
        }

    probes = json.loads(probes_path.read_text(encoding="utf-8"))
    g = guard or Guard(config=base_config)
    rows: list[dict[str, Any]] = []
    tp = fp = tn = fn = 0
    encoding_hits = 0
    control_fp = 0
    for probe in probes:
        text = materialize_encoding_probe(probe)
        result = g.scan(text)
        expect = bool(probe.get("expect_detected"))
        detected = not result.safe
        encoding_findings = sum(1 for f in result.findings if f.stage == "encoding")
        is_control = probe.get("suite") == "literal_control"
        if not is_control and encoding_findings:
            encoding_hits += 1
        if is_control and detected:
            control_fp += 1
        if expect and detected:
            tp += 1
            outcome = "tp"
        elif expect and not detected:
            fn += 1
            outcome = "fn"
        elif not expect and detected:
            fp += 1
            outcome = "fp"
        else:
            tn += 1
            outcome = "tn"
        rows.append(
            {
                "id": probe.get("id"),
                "expect_detected": expect,
                "outcome": outcome,
                "action": result.action.value,
                "safe": result.safe,
                "finding_count": len(result.findings),
                "encoding_findings": encoding_findings,
            }
        )

    encoding_rows = [
        (row, probe)
        for row, probe in zip(rows, probes, strict=True)
        if probe.get("suite") != "literal_control"
    ]
    enc_fp = sum(1 for row, _ in encoding_rows if row["outcome"] == "fp")
    enc_fn = sum(1 for row, _ in encoding_rows if row["outcome"] == "fn")

    return {
        "probes_file": str(probes_path),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "encoding_stage_hits": encoding_hits,
        "all_passed": fp == 0 and fn == 0,
        "encoding_probes_pass": enc_fp == 0 and enc_fn == 0,
        "literal_control_fp": control_fp,
        "results": rows,
    }
