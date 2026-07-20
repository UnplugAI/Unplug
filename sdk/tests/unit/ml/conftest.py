"""ML unit fixtures: offline synthetic checkpoints (no hub downloads)."""

from __future__ import annotations

from pathlib import Path

import pytest

_BIOES_LABELS = ("O", "B-INJ", "I-INJ", "E-INJ", "S-INJ")
_VOCAB_WORDS = (
    "ignore",
    "all",
    "previous",
    "instructions",
    "and",
    "reveal",
    "secrets",
    "hello",
    "world",
    "the",
    "weather",
    "in",
    "tokyo",
    "please",
    "dump",
    "a",
    "b",
    "c",
    "test",
    "text",
)


def _write_bert_vocab(path: Path, *, vocab_size: int = 1000) -> None:
    special = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"]
    words = list(_VOCAB_WORDS)
    filler = [f"tok{i}" for i in range(vocab_size - len(special) - len(words))]
    vocab = special + words + filler
    if len(vocab) != vocab_size:
        raise AssertionError(f"vocab size {len(vocab)} != {vocab_size}")
    path.write_text("\n".join(vocab) + "\n", encoding="utf-8")


def _build_token_classification_checkpoint(
    root: Path,
    *,
    labels: tuple[str, ...],
    vocab_size: int = 1000,
    max_position_embeddings: int = 128,
) -> Path:
    pytest.importorskip("transformers")
    from transformers import BertConfig, BertForTokenClassification, BertTokenizerFast

    label2id = {label: idx for idx, label in enumerate(labels)}
    id2label = {idx: label for label, idx in label2id.items()}
    config = BertConfig(
        vocab_size=vocab_size,
        hidden_size=32,
        num_hidden_layers=1,
        num_attention_heads=2,
        intermediate_size=64,
        max_position_embeddings=max_position_embeddings,
        num_labels=len(labels),
        id2label=id2label,
        label2id=label2id,
    )
    model = BertForTokenClassification(config)
    root.mkdir(parents=True, exist_ok=True)
    vocab_path = root / "vocab.txt"
    _write_bert_vocab(vocab_path, vocab_size=vocab_size)
    tokenizer = BertTokenizerFast(vocab_file=str(vocab_path), do_lower_case=True)
    model.save_pretrained(root, safe_serialization=True)
    tokenizer.save_pretrained(root)
    return root


@pytest.fixture(scope="session")
def synthetic_ml_checkpoint(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Tiny random BIOES token-classification checkpoint (~200KB, offline)."""
    pytest.importorskip("torch")
    root = tmp_path_factory.mktemp("synthetic_ml_ckpt")
    return _build_token_classification_checkpoint(root, labels=_BIOES_LABELS)


@pytest.fixture(scope="session")
def synthetic_non_inj_checkpoint(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Checkpoint whose label map has no *-INJ labels (load must raise ModelError)."""
    pytest.importorskip("torch")
    root = tmp_path_factory.mktemp("synthetic_non_inj_ckpt")
    return _build_token_classification_checkpoint(
        root,
        labels=("O", "B-PER", "I-PER"),
        vocab_size=100,
        max_position_embeddings=64,
    )
