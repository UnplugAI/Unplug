# Public SDK API Surface

Use `unplug.api.*` for cross-repository integrations. Treat `unplug.core.*` and
most of `unplug.ml.*` as private implementation details that can move during SDK
refactors.

## Import Map

| Need | Public import | Previous/internal import |
|------|---------------|--------------------------|
| Wire types | `unplug.api` or `unplug.api.types` | `unplug.models` |
| Actions / sources | `unplug.api.enums` | `unplug.models` |
| Policy helpers | `unplug.api.policy` | `unplug.core.policy` |
| Privacy filters | `unplug.api.privacy` | `unplug.core.privacy` |
| Scan cache | `unplug.api.cache` | `unplug.core.runtime.cache`, `unplug.core.cache` |
| Boundary wrapping | `unplug.api.boundaries` | `unplug.core.agent.boundaries` |
| Normalization | `unplug.api.normalization` | `unplug.core.normalize` |
| Encoded-payload scanning | `unplug.api.encoding` | `unplug.core.normalize.encodings` |
| Span model runtime | `unplug.api.ml` | `unplug.ml.span_model` |
| Rebuild scan result | `unplug.api.results` | `unplug.guard_scan` / internal policy |

## Examples

Server-side scan result enrichment:

```python
from unplug.api.policy import policy_from_request
from unplug.api.privacy import PrivacyFilterService
from unplug.api.results import refresh_scan_result
from unplug.api.types import ScanRequest, ScanResult
```

Shared scan cache:

```python
from unplug.api.cache import ScanCache, SafePrefixState, merge_suffix_result
```

MCP untrusted-content wrapping:

```python
from unplug.api.boundaries import sanitize_boundary_markers, wrap_external_content
```

Hosted semantic layer / local model runtime:

```python
from unplug.api.ml import SpanInferenceModel
from unplug.api.normalization import Normalizer
from unplug.api.encoding import HeuristicEncodingClassifier
```

## Compatibility

The older paths still work for now, but new code should not import from them:

- `unplug.models` remains a compatibility re-export for wire types.
- `unplug.core.cache` remains a deprecated compatibility path.
- `unplug.core.*` modules are private and may change in minor releases.

Downstream repos should add import-surface tests that import only from
`unplug.api.*`.

Runnable demo:

```bash
cd sdk
python examples/public_api_surface_demo.py
```
