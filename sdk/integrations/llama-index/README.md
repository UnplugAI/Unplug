# LlamaIndex

**Extra:** `pip install "unplug-ai[llama-index]"`
**Module:** `unplug.integrations.llama_index`

Uses the same scanning core as Haystack (`scan_document`) — no LlamaIndex import at load time.

## Node postprocessor

```python
from unplug.integrations.llama_index import UnplugNodePostprocessor

post = UnplugNodePostprocessor(drop_on_block=True, wrap_safe=True)
retrieved_nodes = [{"text": "Some retrieved passage.", "metadata": {}}]
safe_nodes, report = post.postprocess_nodes_with_report(retrieved_nodes)
print(report.dropped, report.max_risk)
```

Works with LlamaIndex `TextNode`, plain dicts, or any object with `.text` / `.metadata`.

## With LlamaIndex query engine

```python
from llama_index.core.postprocessor.types import BaseNodePostprocessor

class UnplugPostprocessor(BaseNodePostprocessor):
    def __init__(self):
        self._guard = UnplugNodePostprocessor()

    def _postprocess_nodes(self, nodes, query_bundle=None):
        return self._guard.postprocess_nodes(nodes)
```

Register on your query engine's `node_postprocessors` list.

## Ingestion

Use `scan_for_ingestion` from `unplug.integrations.haystack` before writing to the index.
