"""Fine-tuned DeBERTa BIOES checkpoint → character spans."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from unplug.ml.bioes import decode_bioes_spans
from unplug.ml.device import resolve_torch_device
from unplug.ml.spans_merge import merge_char_spans
from unplug.ml.types import CharSpan, SpanPrediction

if TYPE_CHECKING:
    from transformers import PreTrainedModel, PreTrainedTokenizerBase


class SpanInferenceModel:
    """Token-classification head → injection character spans on normalized text."""

    def __init__(
        self,
        checkpoint: str | Path,
        *,
        max_length: int = 256,
        stride: int = 64,
        device: str | None = None,
        inj_threshold: float = 0.5,
        local_files_only: bool = True,
    ) -> None:
        self._checkpoint = Path(checkpoint)
        self._max_length = max_length
        self._stride = stride
        self._device = resolve_torch_device(device)
        self._inj_threshold = inj_threshold
        self._local_files_only = local_files_only
        self._tokenizer: PreTrainedTokenizerBase | None = None
        self._model: PreTrainedModel | None = None
        self._label2id: dict[str, int] = {}
        self._id2label: dict[int, str] = {}

    @property
    def checkpoint(self) -> Path:
        return self._checkpoint

    @property
    def device(self) -> str:
        return self._device

    @property
    def loaded(self) -> bool:
        return self._model is not None

    def load(self) -> None:
        if self._model is not None:
            return
        import torch
        from transformers import AutoModelForTokenClassification, AutoTokenizer

        if not self._checkpoint.is_dir():
            msg = f"Checkpoint directory not found: {self._checkpoint}"
            raise FileNotFoundError(msg)

        tok_json = self._checkpoint / "tokenizer.json"
        try:
            self._tokenizer = AutoTokenizer.from_pretrained(
                self._checkpoint,
                local_files_only=self._local_files_only,
                use_fast=True,
            )
        except Exception:
            if tok_json.is_file():
                from transformers import PreTrainedTokenizerFast

                self._tokenizer = PreTrainedTokenizerFast(tokenizer_file=str(tok_json))
            else:
                self._tokenizer = AutoTokenizer.from_pretrained(
                    self._checkpoint,
                    local_files_only=self._local_files_only,
                    use_fast=False,
                )
        self._model = AutoModelForTokenClassification.from_pretrained(
            self._checkpoint,
            local_files_only=self._local_files_only,
            torch_dtype=torch.float32,
        )
        self._model.to(self._device)
        self._model.eval()
        self._label2id = dict(self._model.config.label2id)
        self._id2label = {int(k): v for k, v in self._model.config.id2label.items()}

    def unload(self) -> None:
        self._model = None
        self._tokenizer = None
        self._label2id = {}
        self._id2label = {}

    def predict(self, text: str) -> SpanPrediction:
        import torch

        self.load()
        assert self._tokenizer is not None
        assert self._model is not None

        encoding = self._tokenizer(
            text,
            return_offsets_mapping=True,
            truncation=True,
            max_length=self._max_length,
            stride=self._stride,
            return_overflowing_tokens=True,
            return_tensors="pt",
        )
        all_spans: list[CharSpan] = []
        batch_size = int(encoding["input_ids"].shape[0])
        skip_keys = frozenset(
            {"offset_mapping", "overflow_to_sample_mapping", "num_overflowing_tokens"}
        )

        for chunk_idx in range(batch_size):
            offset_mapping = encoding["offset_mapping"][chunk_idx].tolist()
            inputs = {
                key: value[chunk_idx : chunk_idx + 1].to(self._device)
                for key, value in encoding.items()
                if key not in skip_keys
            }
            with torch.no_grad():
                logits = self._model(**inputs).logits[0]
                probs = torch.softmax(logits, dim=-1)
            all_spans.extend(
                decode_bioes_spans(
                    offset_mapping,
                    probs=probs,
                    id2label=self._id2label,
                    label2id=self._label2id,
                    inj_threshold=self._inj_threshold,
                )
            )

        merged = merge_char_spans(all_spans)
        return SpanPrediction(text_normalized=text, spans=merged)
