"""Optional LiteLLM judge — BYOLLM for borderline cases and SDK smoke testing."""

from __future__ import annotations

from unplug.core.extras import require_extra
from unplug.core.judge import CallableJudge, JudgeProvider


def create_litellm_judge(
    model: str = "gpt-4o",
    *,
    timeout: float = 30.0,
    api_key: str | None = None,
) -> JudgeProvider:
    """Return a JudgeProvider backed by LiteLLM (any provider LiteLLM supports).

    Requires: pip install 'unplug-ai[litellm]'
    """
    require_extra(
        "litellm",
        pip_extra="litellm",
        feature="LiteLLM judge",
    )
    import litellm

    async def _call(prompt: str) -> str:
        kwargs: dict[str, object] = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
        }
        if api_key is not None:
            kwargs["api_key"] = api_key
        response = await litellm.acompletion(**kwargs)
        content = response.choices[0].message.content
        return str(content or "")

    return CallableJudge(_call, timeout=timeout)


def litellm_available() -> bool:
    try:
        require_extra("litellm", pip_extra="litellm", feature="LiteLLM")
    except ImportError:
        return False
    return True
