"""Guard: main entry point for Unplug."""

from __future__ import annotations

import os
import threading
from typing import Any, ClassVar

from unplug.api.enums import Action, Source
from unplug.api.types import Finding, ScanRequest, ScanResult
from unplug.client import UnplugClient
from unplug.config.guard import GuardConfig, resolve_input_scanners
from unplug.config.policy import ScanPolicy
from unplug.core.agent.approval import ApprovalProvider, NullApprovalProvider
from unplug.core.agent.boundaries import maybe_wrap_untrusted
from unplug.core.agent.canary import CanaryRegistry
from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.judge import JudgeProvider
from unplug.core.limits import LimitConfig, LimitViolation
from unplug.core.normalize import Normalizer
from unplug.core.normalize.encodings import EncodingClassifier, default_encoding_classifier
from unplug.core.policy import policy_from_request
from unplug.core.privacy import NullPrivacyFilter, PrivacyFilterService
from unplug.core.privacy.secrets import SecretsRegistry, SecretsSanitizer
from unplug.core.runtime.cache import SafePrefixState, ScanCache, merge_suffix_result
from unplug.core.runtime.logging import correlation_scope, get_logger
from unplug.core.runtime.model_runtime import (
    load_active_model_provider,
    merge_catalog_models,
    model_cache_version,
    prepare_active_model_spec,
)
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.runtime.versions import MODEL_VERSION_LOCAL, NORMALIZER_VERSION
from unplug.core.taint import TaintedText, TrustLevel
from unplug.pipelines.input import InputPipeline
from unplug.pipelines.output import OutputPipeline
from unplug.pipelines.toolcall import ToolCallPipeline
from unplug.scanners import ScannerRegistry
from unplug.scanners.injection_ml import InjectionSpanScanner
from unplug.streaming import StreamScanner, scan_stream

_log = get_logger("guard")


def _fail_closed(exc: Exception) -> ScanResult:
    return ScanResult(
        safe=False,
        action=Action.BLOCK,
        risk_score=1.0,
        findings=[
            Finding(
                category="guard",
                subcategory="guard_error",
                stage="error",
                span_start=0,
                span_end=0,
                score=1.0,
                evidence=f"Guard failed: {type(exc).__name__}",
            )
        ],
        latency_ms=0.0,
    )


def _limit_result(violation: LimitViolation, text_len: int = 0) -> ScanResult:
    return ScanResult(
        safe=False,
        action=Action.BLOCK,
        risk_score=1.0,
        findings=[
            Finding(
                category="limits",
                subcategory=violation.kind,
                stage="limits",
                span_start=0,
                span_end=text_len,
                score=1.0,
                evidence=violation.message,
            )
        ],
        latency_ms=0.0,
        stages_run=["limits"],
    )


class Guard:
    """Entry point for Unplug: scans text, output, and tool calls."""

    _instance: Guard | None = None
    _lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(
        self,
        *,
        scanners: list[str] | None = None,
        mode: str = "local",
        server_url: str | None = None,
        server_api_key: str | None = None,
        fail_mode: str = "closed",
        secrets_registry: SecretsRegistry | None = None,
        config: GuardConfig | None = None,
        limits: LimitConfig | None = None,
        judge: JudgeProvider | Any | None = None,
        privacy_filter: PrivacyFilterService | None = None,
        shared_scan_cache: ScanCache | None = None,
        encoding_classifier: EncodingClassifier | None = None,
        scan_encodings: bool = True,
        approval: ApprovalProvider | None = None,
    ) -> None:
        cfg = config or GuardConfig()
        if fail_mode == "open":
            import warnings

            warnings.warn(
                'fail_mode="open" is deprecated and ignored; errors always fail closed',
                DeprecationWarning,
                stacklevel=2,
            )
        overrides: dict[str, Any] = {"mode": mode, "fail_closed": fail_mode == "closed"}
        if scanners is not None:
            overrides["scanners"] = scanners
        if server_url is not None:
            overrides["server_url"] = server_url
        if server_api_key is not None:
            overrides["server_api_key"] = server_api_key
        if limits is not None:
            overrides["limits"] = limits
        cfg = cfg.model_copy(update=overrides)
        cfg = merge_catalog_models(cfg)

        self._config = cfg
        self._limits = cfg.limits
        self._judge = judge
        self._metrics = MetricsCollector()
        self._secrets_registry = secrets_registry or SecretsRegistry()
        self._canaries = CanaryRegistry()
        scan_cache = (
            ScanCache(max_chunk_entries=cfg.cache.max_chunk_entries) if cfg.cache.enabled else None
        )
        self._context = ExecutionContext(
            secrets_registry=self._secrets_registry,
            scan_cache=scan_cache,
        )
        # Privacy Filter loads only with unplug-safeguard model (not in public SDK v1).
        self._privacy_filter = privacy_filter or NullPrivacyFilter()
        self._shared_scan_cache = shared_scan_cache
        self._approval: ApprovalProvider = approval or NullApprovalProvider()

        self._server_client: UnplugClient | None = None
        if cfg.mode == "server":
            url = cfg.server_url or os.environ.get("UNPLUG_SERVER_URL", "http://localhost:8000")
            key = cfg.server_api_key or os.environ.get("UNPLUG_API_KEY")
            self._server_client = UnplugClient(base_url=url, api_key=key)

        self._registry = ScannerRegistry(metrics=self._metrics)
        self._ml_provider = None
        self._ml_degraded = False
        self._model_cache_version = MODEL_VERSION_LOCAL

        scanner_names = list(cfg.scanners)
        self._validate_optional_scanners(scanner_names)
        if cfg.mode != "server" and cfg.active_model:
            spec = prepare_active_model_spec(cfg)
            if spec is not None:
                from unplug.exceptions import ModelError

                provider = None
                load_error: Exception | None = None
                try:
                    provider = load_active_model_provider(cfg)
                except Exception as exc:
                    load_error = exc
                    if cfg.require_ml:
                        tier = cfg.active_model
                        raise ModelError(
                            f"require_ml=true but model tier {tier!r} could not be loaded: "
                            f"{type(exc).__name__}: {exc}"
                        ) from exc
                    _log.warning(
                        "active_model=%s configured but injection_ml failed to load (%s). "
                        'Fix: pip install "unplug-ai[ml]", then unplug-models download %s '
                        "(or set UNPLUG_MODEL_PATH). Continuing with regex scanners only.",
                        cfg.active_model,
                        type(exc).__name__,
                        cfg.active_model,
                    )
                    self._ml_degraded = True
                if provider is not None:
                    self._ml_provider = provider
                    self._model_cache_version = model_cache_version(spec)
                elif cfg.require_ml:
                    raise ModelError(
                        f"require_ml=true but model tier {cfg.active_model!r} could not be loaded. "
                        f"Run: unplug-models download {cfg.active_model}"
                    )
                elif load_error is None:
                    _log.warning(
                        "active_model=%s configured but injection_ml is not loaded. "
                        "Run: unplug-models download %s (or set UNPLUG_MODEL_PATH). "
                        "Continuing with regex scanners only.",
                        cfg.active_model,
                        cfg.active_model,
                    )
                    self._ml_degraded = True

        v2_scanners = self._registry.get_many(scanner_names, configs=cfg.scanner_configs)
        if self._ml_provider is not None:
            ml_cfg = cfg.get_scanner_config("injection_ml")
            v2_scanners.append(
                InjectionSpanScanner(
                    config=ml_cfg,
                    metrics=self._metrics,
                    model=self._ml_provider,
                )
            )

        self._input_pipeline = InputPipeline(
            scanners=v2_scanners,
            normalizer=Normalizer(),
            config=cfg.pipeline,
            metrics=self._metrics,
            judge=judge if cfg.judge_enabled or judge is not None else None,
            judge_low=cfg.judge_low,
            judge_high=cfg.judge_high,
            encoding_classifier=encoding_classifier
            or default_encoding_classifier(self._ml_provider),
            scan_encodings=scan_encodings,
            boundary_config=cfg.boundaries,
            trajectory_config=cfg.trajectory,
            degradation_config=cfg.degradation,
        )

        self._output_pipeline = OutputPipeline(
            secrets_sanitizer=SecretsSanitizer(self._secrets_registry),
            leakage_scanner=self._registry.get("leakage"),
            secrets_scanner=self._registry.get("secrets"),
            url_scanner=self._registry.get("urls"),
            pii_scanner=self._registry.get("pii") if "pii" in cfg.scanners else None,
            config=cfg.pipeline,
            metrics=self._metrics,
            trajectory_config=cfg.trajectory,
            boundary_config=cfg.boundaries,
            degradation_config=cfg.degradation,
        )

        self._tool_pipeline = ToolCallPipeline(
            destructive_scanner=self._registry.get("destructive"),
            financial_scanner=self._registry.get("financial"),
            config=cfg.pipeline,
            metrics=self._metrics,
            tool_policy=cfg.tools,
            intent_config=cfg.intent,
            toolchain_config=cfg.toolchain,
            collusion_config=cfg.collusion,
            trajectory_config=cfg.trajectory,
            degradation_config=cfg.degradation,
        )

    @property
    def context(self) -> ExecutionContext:
        return self._context

    @property
    def secrets(self) -> SecretsRegistry:
        return self._secrets_registry

    @property
    def canaries(self) -> CanaryRegistry:
        return self._canaries

    def add_canary(self, prompt: str, *, label: str = "system_prompt") -> str:
        """Plant a canary token in a prompt (Rebuff pattern).

        Any reappearance of the token in scanned output raises a
        leakage/prompt_leak_canary finding and gets redacted.
        """
        wrapped, record = self._canaries.add_canary(prompt, label=label)
        self._secrets_registry.register(record.registry_name, record.token, source="canary")
        return wrapped

    @property
    def limits(self) -> LimitConfig:
        return self._limits

    @property
    def metrics(self) -> MetricsCollector:
        return self._metrics

    @property
    def scanner_registry(self) -> ScannerRegistry:
        return self._registry

    def notify_taint_source(self, tool_name: str, *, origin: str = "") -> None:
        """Mark session tainted after a taint-source tool runs (web_fetch, read, etc.)."""
        if not self._config.tools.session_taint_enabled:
            return
        label = f"tool:{tool_name}"
        if origin:
            label = f"{label}:{origin}"
        self._context.mark_session_tainted(label)

    def _maybe_mark_session_tainted_from_scan(self, source: Source) -> None:
        if not self._config.tools.session_taint_enabled:
            return
        if source in (Source.RETRIEVED, Source.TOOL_OUTPUT):
            self._context.mark_session_tainted(f"scan:{source.value}")

    def reset_session_taint(self) -> None:
        """Clear session taint and degradation (e.g. new trusted user turn)."""
        self._context.reset_security_state()

    def wrap_for_context(self, text: str, source: Source | str = Source.RETRIEVED) -> str:
        """Wrap untrusted content before inserting into LLM context (OpenClaw adapter pattern)."""
        if isinstance(source, str):
            source = Source(source)
        wrapped, _, _ = maybe_wrap_untrusted(text, source=source, config=self._config.boundaries)
        return wrapped

    def scan_context_file(
        self,
        content: str,
        *,
        filename: str = "context",
    ) -> tuple[str, ScanResult]:
        """Hermes-style gate for AGENTS.md, SKILL.md, DESCRIPTION.md before system prompt.

        Returns ``(text_for_prompt, scan_result)``. When injection is detected, ``text_for_prompt``
        is a blocked placeholder and the original content must not be sent to the model.
        """
        result = self.scan(content, source=Source.RETRIEVED)
        if result.safe:
            return content, result

        triggers = ", ".join(dict.fromkeys(f.subcategory for f in result.findings))[:200]
        label = triggers or "injection"
        blocked = (
            f"[BLOCKED: {filename} contained potential prompt injection ({label}). "
            "Content not loaded.]"
        )
        return blocked, result

    def _capture_user_intent(self, request: ScanRequest) -> None:
        if request.source == Source.USER:
            self._context.user_intent = TaintedText(
                text=request.text,
                trust_level=TrustLevel.USER,
                origin="user_message",
            )

    @property
    def config(self) -> GuardConfig:
        return self._config

    @classmethod
    def with_tiny(
        cls,
        *,
        auto_download: bool = True,
        require_ml: bool = False,
        **kwargs: Any,
    ) -> Guard:
        """Local guard with unplug-tiny from Hugging Face (Unplug-AI/unplug-tiny-v1)."""
        cfg = kwargs.pop("config", None) or GuardConfig()
        cfg = cfg.model_copy(
            update={
                "active_model": "tiny",
                "auto_download_model": auto_download,
                "require_ml": require_ml,
                "mode": "local",
            }
        )
        return cls(config=cfg, **kwargs)

    def scan(self, text: str, source: Source | str = Source.USER) -> ScanResult:
        """Scan text and return findings with optional redaction."""
        if isinstance(source, str):
            source = Source(source)
        return self.scan_request(self._build_scan_request(text, source))

    def scan_stream(
        self,
        chunks: list[str] | tuple[str, ...],
        *,
        source: Source | str = Source.USER,
        document_id: str | None = None,
    ) -> ScanResult:
        """Scan streamed chunks as one document (sliding-window ML covers all text)."""
        return scan_stream(
            self,
            chunks,
            source=source,
            document_id=document_id,
        )

    def stream_scanner(
        self,
        *,
        source: Source | str = Source.TOOL_OUTPUT,
        scan_every_chars: int = 1024,
        document_id: str | None = None,
    ) -> StreamScanner:
        """Incremental scanner for token/chunk streams (e.g. LLM output)."""
        return StreamScanner(
            self,
            source=source,
            scan_every_chars=scan_every_chars,
            document_id=document_id,
        )

    def _build_scan_request(
        self,
        text: str,
        source: Source = Source.USER,
    ) -> ScanRequest:
        ctx = self._context
        policy = self._config.policy
        return ScanRequest(
            text=text,
            source=source,
            session_id=ctx.session_id,
            agent_id=ctx.agent_id,
            turn_id=ctx.turn_id,
            document_id=ctx.document_id,
            block_coverage_ratio=policy.block_coverage_ratio,
            redact_threshold=policy.redact_threshold,
            review_threshold=policy.review_threshold,
            block_threshold=policy.block_threshold,
        )

    def _apply_request_context(self, request: ScanRequest) -> ScanPolicy:
        ctx = self._context
        if request.session_id:
            ctx.session_id = request.session_id
        if request.agent_id is not None:
            ctx.agent_id = request.agent_id
        if request.turn_id is not None:
            ctx.turn_id = request.turn_id
        if request.document_id is not None:
            ctx.document_id = request.document_id
        policy = policy_from_request(request, self._config.policy)
        ctx.scan_policy = policy
        return policy

    def _request_context(self, request: ScanRequest, *, isolated: bool) -> ExecutionContext:
        policy = policy_from_request(request, self._config.policy)
        if not isolated:
            self._apply_request_context(request)
            return self._context

        cache: ScanCache | None = None
        if self._config.cache.enabled:
            cache = self._shared_scan_cache or ScanCache(
                max_chunk_entries=self._config.cache.max_chunk_entries
            )

        return ExecutionContext(
            session_id=request.session_id or self._context.session_id,
            agent_id=request.agent_id if request.agent_id is not None else self._context.agent_id,
            turn_id=request.turn_id if request.turn_id is not None else self._context.turn_id,
            document_id=(
                request.document_id
                if request.document_id is not None
                else self._context.document_id
            ),
            secrets_registry=self._secrets_registry,
            scan_policy=policy,
            scan_cache=cache,
        )

    def _model_version_for_cache(self) -> str:
        return self._model_cache_version

    def _run_input_with_cache(self, request: ScanRequest, ctx: ExecutionContext) -> ScanResult:
        cache = ctx.scan_cache
        if cache is None or not self._config.cache.enabled:
            return self._input_pipeline.run(
                request.text,
                source=request.source,
                context=ctx,
            )

        parts = cache.cache_key_parts(
            request.text,
            document_id=request.document_id,
            normalizer_version=NORMALIZER_VERSION,
            model_version=self._model_version_for_cache(),
        )
        hit = cache.get_chunk(parts.full_hash)
        if hit is not None:
            return hit

        prefix_state = cache.get_safe_prefix(parts)
        prefix_len = 0
        if prefix_state is not None and prefix_state.verify(request.text):
            prefix_len = prefix_state.prefix_len

        if 0 < prefix_len < len(request.text):
            suffix_result = self._input_pipeline.run(
                request.text[prefix_len:],
                source=request.source,
                context=ctx,
            )
            result = merge_suffix_result(suffix_result, prefix_len)
        else:
            result = self._input_pipeline.run(
                request.text,
                source=request.source,
                context=ctx,
            )

        if cache.should_advance_prefix(
            result.action,
            advance_on_redact=self._config.cache.advance_prefix_on_redact,
        ):
            cache.set_safe_prefix(
                parts,
                SafePrefixState.from_text(request.text, len(request.text)),
            )
        cache.set_chunk(parts.full_hash, result)
        return result

    def scan_output(self, text: str | TaintedText) -> ScanResult:
        """Scan agent output for secrets and data leakage."""
        raw = text.text if isinstance(text, TaintedText) else text
        return self.scan_output_request(
            self._build_scan_request(raw, source=Source.TOOL_OUTPUT),
        )

    def scan_output_request(
        self,
        request: ScanRequest,
        *,
        isolated: bool = False,
    ) -> ScanResult:
        """Scan output from a ScanRequest (hosted server or local pipeline)."""
        violation = self._limits.check_input_length(request.text)
        if violation is not None:
            return _limit_result(violation, len(request.text))
        try:
            with correlation_scope():
                if self._server_client is not None:
                    return self._server_client.scan_output_request(request)
                ctx = self._request_context(request, isolated=isolated)
                body: str | TaintedText = request.text
                result = self._output_pipeline.run(body, context=ctx)
                if not isolated:
                    self._maybe_mark_session_tainted_from_scan(Source.TOOL_OUTPUT)
                return result
        except Exception as exc:
            _log.error("guard.scan_output_request failed: %s", exc)
            return _fail_closed(exc)

    def check_tool_call(
        self,
        tool_name: str,
        arguments: dict,
        *,
        taint_sources: list[TaintedText] | None = None,
        approved: bool | None = None,
    ) -> ScanResult:
        """Check a proposed tool call for destructive, taint, and financial risks."""
        _ = approved  # resume-only via ApprovalProvider; caller flag is ignored
        if not self._limits.is_tool_allowed(tool_name):
            return _limit_result(
                LimitViolation(
                    kind="tool_blocked",
                    limit=0,
                    actual=0,
                    message=f"Tool not allowed: {tool_name}",
                ),
            )
        if not self._config.tools.is_permitted(tool_name):
            return _limit_result(
                LimitViolation(
                    kind="tool_profile_blocked",
                    limit=0,
                    actual=0,
                    message=(
                        f"Tool blocked by profile '{self._config.tools.profile}': {tool_name}"
                    ),
                ),
            )
        count_violation = self._limits.check_tool_call_count(len(self._context.tool_calls) + 1)
        if count_violation is not None:
            return _limit_result(count_violation)
        tc = ToolCall(
            tool_name=tool_name,
            arguments=arguments,
            taint_sources=taint_sources or [],
            approved=None,
        )
        try:
            with correlation_scope():
                result = self._tool_pipeline.run(tc, context=self._context)
                if (
                    result.action == Action.REVIEW
                    and tc.approved is not True
                    and result.approval is not None
                    and self._approval.request_approval(result.approval)
                ):
                    tc.approved = True
                    result = self._tool_pipeline.run(tc, context=self._context)
                if result.action == Action.ALLOW:
                    self._context.add_tool_call(tc)
                    if self._config.tools.is_taint_source(tool_name):
                        self.notify_taint_source(tool_name)
                return result
        except Exception as exc:
            _log.error("guard.check_tool_call failed: %s", exc)
            return _fail_closed(exc)

    def scan_request(
        self,
        request: ScanRequest,
        *,
        isolated: bool = False,
    ) -> ScanResult:
        """Scan from a ScanRequest object."""
        violation = self._limits.check_input_length(request.text)
        if violation is not None:
            return _limit_result(violation, len(request.text))
        try:
            with correlation_scope():
                if self._server_client is not None:
                    return self._server_client.scan_request(request)
                ctx = self._request_context(request, isolated=isolated)
                if request.scanners:
                    ctx.allowed_scanners = resolve_input_scanners(list(request.scanners))
                if not isolated:
                    self._capture_user_intent(request)
                result = self._run_input_with_cache(request, ctx)
                if not isolated:
                    self._maybe_mark_session_tainted_from_scan(request.source)
                return result
        except Exception as exc:
            _log.error("guard.scan_request failed: %s", exc)
            return _fail_closed(exc)

    @property
    def is_server_mode(self) -> bool:
        return self._server_client is not None

    @property
    def ml_model_loaded(self) -> bool:
        return self._ml_provider is not None and self._ml_provider.loaded

    @property
    def ml_degraded(self) -> bool:
        """True when active_model is configured but ML failed to load."""
        return self._ml_degraded

    @staticmethod
    def _validate_optional_scanners(names: list[str]) -> None:
        from unplug.exceptions import ConfigError

        if "pii" in names:
            try:
                from unplug.optional.presidio import get_analyzer_engine_class

                get_analyzer_engine_class()
            except ImportError as exc:
                msg = 'pii scanner requires pip install "unplug-ai[presidio]"'
                raise ConfigError(msg) from exc
        if "yara" in names:
            try:
                from unplug.scanners.yara_loader import get_yara_rules

                get_yara_rules()
            except Exception as exc:
                msg = 'yara scanner requires pip install "unplug-ai[yara]"'
                raise ConfigError(msg) from exc

    @property
    def scanners_loaded(self) -> list[str]:
        names = list(self._config.scanners)
        if self._ml_provider is not None and "injection_ml" not in names:
            names.append("injection_ml")
        return names

    def stats(self) -> dict:
        """Full metrics snapshot."""
        return self._metrics.snapshot()

    @classmethod
    def init(cls, **kwargs: Any) -> Guard:
        """Initialize a global Guard and auto-instrument detected frameworks."""
        with cls._lock:
            cls._instance = Guard(**kwargs)
            return cls._instance

    @classmethod
    def get(cls) -> Guard:
        """Get the global Guard instance."""
        with cls._lock:
            if cls._instance is None:
                raise RuntimeError("Guard.init() has not been called")
            return cls._instance
