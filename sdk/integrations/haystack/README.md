# Haystack (RAG)

**Extra:** `pip install "unplug-ai[haystack]"`
**Module:** `unplug.integrations.haystack`

Defend the **retrieval path** — poisoned documents are the most common indirect injection vector.

## Pipeline guard (retrieve → prompt)

```python
from haystack import Pipeline
from unplug.integrations.haystack import UnplugDocumentGuard

pipe = Pipeline()
pipe.add_component("retriever", retriever)
pipe.add_component("guard", UnplugDocumentGuard())
pipe.add_component("prompt", prompt_builder)
pipe.connect("retriever.documents", "guard.documents")
pipe.connect("guard.documents", "prompt.documents")
```

## Ingestion gate (write → store)

```python
from unplug import Guard
from unplug.integrations.haystack import scan_for_ingestion


def index_document(text: str, meta_update: dict) -> None:
    ...  # wire this to your own doc.meta.update(...) + document_store.write_documents([doc])


document_text = "The quarterly report shows steady growth."
decision = scan_for_ingestion(Guard(), document_text)
if decision.index_ok:
    index_document(document_text, decision.meta_update)
```

See [`docs/RAG_DEFENSE.md`](../../docs/RAG_DEFENSE.md) for the threat model.

## Without Haystack installed

`scan_document` and `scan_for_ingestion` work without Haystack — only `UnplugDocumentGuard` lazy-imports it.
