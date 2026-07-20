"""Fine-tuned DeBERTa BIOES checkpoint → character spans (+ optional doc head)."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import TYPE_CHECKING

from unplug.exceptions import ModelError
from unplug.ml.bioes import decode_bioes_spans
from unplug.ml.device import resolve_torch_device
from unplug.ml.spans_merge import merge_char_spans
from unplug.ml.types import CharSpan, SpanPrediction
from unplug.optional.ml import get_torch, get_transformers

if TYPE_CHECKING:
    from transformers import PreTrainedModel, PreTrainedTokenizerBase

logger = logging.getLogger("unplug.ml.span_model")

_INJ_LABELS = ("B-INJ", "I-INJ", "E-INJ", "S-INJ")


class SpanInferenceModel:
    """Token-classification head → injection character spans on normalized text."""

    def __init__(
        self,
        checkpoint: str | Path,
        *,
        max_length: int | None = None,
        stride: int = 64,
        device: str | None = None,
        inj_threshold: float = 0.5,
        doc_threshold: float | None = None,
        local_files_only: bool = True,
    ) -> None:
        self._checkpoint = Path(checkpoint)
        self._max_length_override = max_length
        self._stride = stride
        self._device_preference = device
        self._device: str | None = None
        self._inj_threshold = inj_threshold
        self._doc_threshold = doc_threshold if doc_threshold is not None else inj_threshold
        self._local_files_only = local_files_only
        self._tokenizer: PreTrainedTokenizerBase | None = None
        self._model: PreTrainedModel | None = None
        self._label2id: dict[str, int] = {}
        self._id2label: dict[int, str] = {}
        self._is_dual_head = False
        self._doc_pos_index = 1
        self._max_length = max_length or 256
        self._has_disposition = False
        self._id2disposition: dict[int, str] = {}
        self._load_lock = threading.Lock()

    @property
    def checkpoint(self) -> Path:
        return self._checkpoint

    @property
    def device(self) -> str:
        if self._device is not None:
            return self._device
        pref = (self._device_preference or "").strip()
        if pref in ("", "auto"):
            return "auto"
        return pref

    @property
    def loaded(self) -> bool:
        return self._model is not None

    @property
    def is_dual_head(self) -> bool:
        return self._is_dual_head

    @property
    def doc_threshold(self) -> float:
        return self._doc_threshold

    def load(self) -> None:
        with self._load_lock:
            if self._model is not None:
                return
            self._load_unlocked()

    def _load_unlocked(self) -> None:
        self._device = resolve_torch_device(self._device_preference)
        torch = get_torch()
        get_transformers()
        from transformers import AutoConfig, AutoModelForTokenClassification, AutoTokenizer

        if not self._checkpoint.is_dir():
            msg = f"Checkpoint directory not found: {self._checkpoint}"
            raise FileNotFoundError(msg)

        tok_json = self._checkpoint / "tokenizer.json"
        try:
            self._tokenizer = AutoTokenizer.from_pretrained(
                self._checkpoint,
                local_files_only=self._local_files_only,
                use_fast=True,
                clean_up_tokenization_spaces=False,
            )
        except Exception as exc:
            logger.warning(
                "fast tokenizer load failed for %s, falling back: %s",
                self._checkpoint,
                exc,
            )
            if tok_json.is_file():
                from transformers import PreTrainedTokenizerFast

                self._tokenizer = PreTrainedTokenizerFast(
                    tokenizer_file=str(tok_json),
                    clean_up_tokenization_spaces=False,
                )
            else:
                self._tokenizer = AutoTokenizer.from_pretrained(
                    self._checkpoint,
                    local_files_only=self._local_files_only,
                    use_fast=False,
                    clean_up_tokenization_spaces=False,
                )

        config = AutoConfig.from_pretrained(
            self._checkpoint,
            local_files_only=self._local_files_only,
        )
        if self._max_length_override is None:
            self._max_length = int(getattr(config, "max_position_embeddings", 256))

        self._is_dual_head = bool(getattr(config, "dual_head", False))
        self._doc_pos_index = int(getattr(config, "doc_positive_index", 1))
        # v132 ternary checkpoints record the disposition head in config.json.
        self._has_disposition = bool(getattr(config, "disposition_head", False))
        disposition2id = getattr(config, "disposition2id", None) or {
            "benign": 0,
            "injection": 1,
            "harmful_not_injection": 2,
        }
        self._id2disposition = {int(v): str(k) for k, v in disposition2id.items()}

        if self._is_dual_head:
            from unplug.ml.dual_head_model import DebertaV2ForDualHead

            self._model = DebertaV2ForDualHead.from_pretrained(
                self._checkpoint,
                local_files_only=self._local_files_only,
                use_safetensors=True,
                torch_dtype=torch.float32,
            )
        else:
            self._model = AutoModelForTokenClassification.from_pretrained(
                self._checkpoint,
                local_files_only=self._local_files_only,
                use_safetensors=True,
                torch_dtype=torch.float32,
            )
        self._model.to(self._device)
        self._model.eval()
        self._label2id = dict(self._model.config.label2id)
        self._id2label = {int(k): v for k, v in self._model.config.id2label.items()}
        self._validate_inj_labels()
        logger.info("injection model loaded on %s", self._device)

    def _validate_inj_labels(self) -> None:
        if any(label in self._label2id for label in _INJ_LABELS):
            return
        labels = sorted(self._label2id)
        self._clear_state()
        raise ModelError(
            "Checkpoint label map has no *-INJ labels "
            "(expected BIOES scheme: B-INJ/I-INJ/E-INJ/S-INJ). "
            f"Got labels: {labels}"
        )

    def unload(self) -> None:
        with self._load_lock:
            self._clear_state()

    def _clear_state(self) -> None:
        self._model = None
        self._tokenizer = None
        self._device = None
        self._label2id = {}
        self._id2label = {}
        self._is_dual_head = False
        self._has_disposition = False
        self._id2disposition = {}

    def _require_loaded(self) -> tuple[PreTrainedTokenizerBase, PreTrainedModel]:
        with self._load_lock:
            if self._model is None:
                self._load_unlocked()
            if self._tokenizer is None or self._model is None:
                msg = "Model was unloaded during inference"
                raise ModelError(msg)
            return self._tokenizer, self._model

    def predict(self, text: str) -> SpanPrediction:
        return self.predict_batch([text], batch_size=1)[0]

    def predict_batch(
        self,
        texts: list[str],
        *,
        batch_size: int = 32,
    ) -> list[SpanPrediction]:
        torch = get_torch()

        with self._load_lock:
            if self._model is None:
                self._load_unlocked()
            if self._tokenizer is None or self._model is None:
                msg = "Model was unloaded during inference"
                raise ModelError(msg)
            tokenizer = self._tokenizer
            model = self._model

            if not texts:
                return []

            out: list[SpanPrediction] = []
            bs = max(1, batch_size)
            for start in range(0, len(texts), bs):
                chunk = texts[start : start + bs]
                encoding = tokenizer(
                    chunk,
                    return_offsets_mapping=True,
                    truncation=True,
                    max_length=self._max_length,
                    stride=self._stride,
                    padding=True,
                    return_overflowing_tokens=bool(
                        self._stride and self._stride < self._max_length
                    ),
                    return_tensors="pt",
                )
                if encoding.get("overflow_to_sample_mapping") is not None:
                    out.extend(self._predict_overflowing(encoding, chunk, model, tokenizer))
                    continue

                offset_mappings = encoding.pop("offset_mapping")
                skip_keys = frozenset(
                    {"offset_mapping", "overflow_to_sample_mapping", "num_overflowing_tokens"}
                )
                inputs = {
                    key: value.to(self._device)
                    for key, value in encoding.items()
                    if key not in skip_keys
                }
                with torch.no_grad():
                    outputs = model(**inputs)
                    logits = outputs.logits
                    probs = torch.softmax(logits, dim=-1)
                    doc_logits = getattr(outputs, "doc_logits", None)
                    disposition_logits = getattr(outputs, "disposition_logits", None)

                for i, body in enumerate(chunk):
                    offset_mapping = offset_mappings[i].tolist()
                    row_probs = probs[i]
                    spans = decode_bioes_spans(
                        offset_mapping,
                        probs=row_probs,
                        id2label=self._id2label,
                        label2id=self._label2id,
                        inj_threshold=self._inj_threshold,
                    )
                    doc_prob, doc_source = self._doc_score(
                        offset_mapping,
                        row_probs=row_probs,
                        doc_logits=doc_logits[i] if doc_logits is not None else None,
                    )
                    disposition_label, disposition_probs = self._disposition(
                        disposition_logits[i] if disposition_logits is not None else None
                    )
                    out.append(
                        SpanPrediction(
                            text_normalized=body,
                            spans=merge_char_spans(spans),
                            doc_score=doc_prob,
                            doc_score_source=doc_source,
                            disposition_label=disposition_label,
                            disposition_probs=disposition_probs,
                        )
                    )
            return out

    def _predict_overflowing(
        self,
        encoding: dict,
        bodies: list[str],
        model: PreTrainedModel,
        tokenizer: PreTrainedTokenizerBase,
    ) -> list[SpanPrediction]:
        torch = get_torch()

        sample_count = len(bodies)
        all_spans: list[list[CharSpan]] = [[] for _ in range(sample_count)]
        doc_scores: list[float] = [0.0] * sample_count
        doc_sources: list[str] = ["token_max"] * sample_count
        disposition_labels: list[str | None] = [None] * sample_count
        disposition_probs: list[dict[str, float] | None] = [None] * sample_count
        overflow_map = encoding["overflow_to_sample_mapping"].tolist()
        batch_size = int(encoding["input_ids"].shape[0])
        skip_keys = frozenset(
            {"offset_mapping", "overflow_to_sample_mapping", "num_overflowing_tokens"}
        )

        for chunk_idx in range(batch_size):
            sample_idx = int(overflow_map[chunk_idx])
            offset_mapping = encoding["offset_mapping"][chunk_idx].tolist()
            inputs = {
                key: value[chunk_idx : chunk_idx + 1].to(self._device)
                for key, value in encoding.items()
                if key not in skip_keys
            }
            with torch.no_grad():
                outputs = model(**inputs)
                logits = outputs.logits[0]
                probs = torch.softmax(logits, dim=-1)
                doc_logits = getattr(outputs, "doc_logits", None)
                disposition_logits = getattr(outputs, "disposition_logits", None)

            spans = decode_bioes_spans(
                offset_mapping,
                probs=probs,
                id2label=self._id2label,
                label2id=self._label2id,
                inj_threshold=self._inj_threshold,
            )
            all_spans[sample_idx].extend(spans)
            doc_prob, doc_source = self._doc_score(
                offset_mapping,
                row_probs=probs,
                doc_logits=doc_logits[0] if doc_logits is not None else None,
            )
            # Worst window wins: the chunk with the highest doc score also
            # supplies the document's disposition.
            if doc_prob >= doc_scores[sample_idx]:
                disp_label, disp_probs = self._disposition(
                    disposition_logits[0] if disposition_logits is not None else None
                )
                if disp_probs is not None:
                    disposition_labels[sample_idx] = disp_label
                    disposition_probs[sample_idx] = disp_probs
            if doc_source == "doc_head":
                doc_scores[sample_idx] = max(doc_scores[sample_idx], doc_prob)
                doc_sources[sample_idx] = "doc_head"
            else:
                doc_scores[sample_idx] = max(doc_scores[sample_idx], doc_prob)

        return [
            SpanPrediction(
                text_normalized=bodies[i],
                spans=merge_char_spans(all_spans[i]),
                doc_score=doc_scores[i],
                doc_score_source=doc_sources[i],
                disposition_label=disposition_labels[i],
                disposition_probs=disposition_probs[i],
            )
            for i in range(sample_count)
        ]

    def _doc_score(
        self,
        offset_mapping: list[tuple[int, int]],
        *,
        row_probs: object,
        doc_logits: object | None,
    ) -> tuple[float, str]:
        torch = get_torch()

        if self._is_dual_head and doc_logits is not None:
            doc_prob = float(torch.softmax(doc_logits, dim=-1)[self._doc_pos_index].item())
            return doc_prob, "doc_head"
        token_max = _token_max_inj_prob(
            offset_mapping,
            probs=row_probs,
            label2id=self._label2id,
        )
        return token_max, "token_max"

    def _disposition(
        self, disposition_logits: object | None
    ) -> tuple[str | None, dict[str, float] | None]:
        """Softmax the ternary head for one row; (None, None) without the head."""
        torch = get_torch()

        if not self._has_disposition or disposition_logits is None:
            return None, None
        disp = torch.softmax(disposition_logits, dim=-1)
        probs = {
            self._id2disposition.get(j, str(j)): float(disp[j].item())
            for j in range(disp.shape[-1])
        }
        label = max(probs, key=probs.get)  # type: ignore[arg-type]
        return label, probs


def _token_max_inj_prob(
    offset_mapping: list[tuple[int, int]],
    *,
    probs: object,
    label2id: dict[str, int],
) -> float:
    inj_cols = [label2id[t] for t in _INJ_LABELS if t in label2id]
    if not inj_cols:
        return 0.0
    best = 0.0
    for idx, (start, end) in enumerate(offset_mapping):
        if start == end == 0:
            continue
        token_prob = max(float(probs[idx][col].item()) for col in inj_cols)  # type: ignore[index]
        best = max(best, token_prob)
    return best
