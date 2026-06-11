# Publish unplug-ai to PyPI

Package: **`unplug-ai`** | Import: **`from unplug import Guard`**

## One-time setup

1. Create a [PyPI account](https://pypi.org/account/register/) (org account recommended).
2. Create an API token with **Upload** scope for project `unplug-ai`.
3. In [UnplugAI/Unplug](https://github.com/UnplugAI/Unplug) -> **Settings -> Environments -> `pypi`**, add:

   | Secret       | Value        |
   |--------------|--------------|
   | `PYPI_TOKEN` | `pypi-...`   |

## Publish

**CI (recommended):** Actions -> **Publish to PyPI** -> Run workflow  
Or tag a GitHub Release - workflow runs on `release: published`.

**Local:**

```bash
cd sdk
uv sync --dev
uv run pytest -q
uv build
UV_PUBLISH_TOKEN=pypi-... uv publish
```

## After publish

- Site links: `pip install unplug-ai` -> https://pypi.org/project/unplug-ai/
- Bump `sdkVersion` in `unplug-site/public/js/core/site-config.jsx` when releasing new versions.
