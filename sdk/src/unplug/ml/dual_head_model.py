"""Dual-head DeBERTa-v2: one backbone, a token (BIOES) head and a doc head."""

from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import nn
from transformers.modeling_outputs import ModelOutput
from transformers.models.deberta_v2.modeling_deberta_v2 import (
    DebertaV2Model,
    DebertaV2PreTrainedModel,
)


@dataclass
class DualHeadOutput(ModelOutput):
    """Loss first, then token logits, then doc logits (Trainer-friendly order)."""

    loss: torch.FloatTensor | None = None
    logits: torch.FloatTensor | None = None
    doc_logits: torch.FloatTensor | None = None


class DebertaV2ForDualHead(DebertaV2PreTrainedModel):
    """DeBERTa-v2 with joint token-classification + document-classification heads."""

    def __init__(self, config) -> None:
        super().__init__(config)
        self.num_labels = int(config.num_labels)
        self.num_doc_labels = int(getattr(config, "num_doc_labels", 2))
        self.doc_loss_weight = float(getattr(config, "doc_loss_weight", 1.0))

        self.deberta = DebertaV2Model(config)
        drop = getattr(config, "cls_dropout", None)
        if drop is None:
            drop = getattr(config, "hidden_dropout_prob", 0.1)
        self.dropout = nn.Dropout(float(drop))
        self.token_classifier = nn.Linear(config.hidden_size, self.num_labels)
        self.doc_classifier = nn.Linear(config.hidden_size, self.num_doc_labels)

        self.post_init()

    def forward(
        self,
        input_ids=None,
        attention_mask=None,
        token_type_ids=None,
        position_ids=None,
        inputs_embeds=None,
        labels=None,
        doc_labels=None,
        output_attentions=None,
        output_hidden_states=None,
        return_dict=None,
    ) -> DualHeadOutput:
        outputs = self.deberta(
            input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids,
            position_ids=position_ids,
            inputs_embeds=inputs_embeds,
            output_attentions=output_attentions,
            output_hidden_states=output_hidden_states,
            return_dict=True,
        )
        sequence_output = outputs.last_hidden_state
        token_logits = self.token_classifier(self.dropout(sequence_output))
        doc_repr = sequence_output[:, 0, :]
        doc_logits = self.doc_classifier(self.dropout(doc_repr))

        loss = None
        if labels is not None:
            loss_fct = nn.CrossEntropyLoss()
            if (labels != -100).any():
                token_loss = loss_fct(token_logits.view(-1, self.num_labels), labels.view(-1))
            else:
                token_loss = token_logits.sum() * 0.0
            loss = token_loss
            if doc_labels is not None:
                doc_loss = loss_fct(doc_logits.view(-1, self.num_doc_labels), doc_labels.view(-1))
                loss = token_loss + self.doc_loss_weight * doc_loss

        return DualHeadOutput(loss=loss, logits=token_logits, doc_logits=doc_logits)
