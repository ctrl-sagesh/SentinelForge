"""LLM provider abstraction — supports Ollama, Anthropic, and OpenAI.

Features:
  - Auto-detect available provider from env vars
  - Retry with exponential backoff (max 3 retries)
  - Token counting and cost estimation
  - All I/O passes through Guardian sanitization
  - Graceful fallback when no LLM is available
"""

from __future__ import annotations

import os
from typing import Any

from sentinelforge.core.config import LLMConfig, LLMProvider, get_settings
from sentinelforge.core.logging import get_logger

logger = get_logger("llm")

MAX_RETRIES = 3
BASE_DELAY = 1.0

COST_PER_1K_INPUT = {
    "claude-sonnet-4-20250514": 0.003,
    "claude-sonnet-4-6": 0.003,
    "gpt-4o": 0.005,
    "gpt-4o-mini": 0.00015,
}
COST_PER_1K_OUTPUT = {
    "claude-sonnet-4-20250514": 0.015,
    "claude-sonnet-4-6": 0.015,
    "gpt-4o": 0.015,
    "gpt-4o-mini": 0.0006,
}


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def estimate_cost(model: str, input_text: str, output_text: str) -> float:
    input_tokens = estimate_tokens(input_text)
    output_tokens = estimate_tokens(output_text)
    in_cost = COST_PER_1K_INPUT.get(model, 0) * input_tokens / 1000
    out_cost = COST_PER_1K_OUTPUT.get(model, 0) * output_tokens / 1000
    return round(in_cost + out_cost, 6)


def auto_detect_provider() -> LLMProvider | None:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return LLMProvider.ANTHROPIC
    if os.environ.get("OPENAI_API_KEY"):
        return LLMProvider.OPENAI
    if os.environ.get("OLLAMA_HOST") or _check_ollama_available():
        return LLMProvider.OLLAMA
    return None


def _check_ollama_available() -> bool:
    try:
        import httpx
        resp = httpx.get("http://localhost:11434/api/tags", timeout=2)
        return resp.status_code == 200
    except Exception:
        return False


def build_llm(config: LLMConfig | None = None) -> Any:
    """Build a LangChain-compatible LLM from config.

    Auto-detects provider if the configured one isn't available.
    Returns None if no LLM is available (caller should use rule-based fallback).
    """
    cfg = config or get_settings().llm

    provider = cfg.provider
    api_key = cfg.api_key

    if provider == LLMProvider.ANTHROPIC and not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    elif provider == LLMProvider.OPENAI and not api_key:
        api_key = os.environ.get("OPENAI_API_KEY", "")

    if provider in (LLMProvider.ANTHROPIC, LLMProvider.OPENAI) and not api_key:
        detected = auto_detect_provider()
        if detected:
            logger.info("llm_provider_fallback", original=provider.value, detected=detected.value)
            provider = detected
            if detected == LLMProvider.ANTHROPIC:
                api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            elif detected == LLMProvider.OPENAI:
                api_key = os.environ.get("OPENAI_API_KEY", "")
        else:
            logger.warning("no_llm_available")
            return None

    try:
        return _create_llm(provider, cfg, api_key)
    except (ImportError, RuntimeError) as exc:
        logger.warning("llm_creation_failed", error=str(exc))
        return None


def _create_llm(provider: LLMProvider, cfg: LLMConfig, api_key: str) -> Any:
    if provider == LLMProvider.OLLAMA:
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=cfg.model,
            base_url=cfg.base_url,
            temperature=cfg.temperature,
            num_predict=cfg.max_tokens,
        )

    if provider == LLMProvider.ANTHROPIC:
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=cfg.model if cfg.model != "llama3.1:8b" else "claude-sonnet-4-20250514",
            api_key=api_key,
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
        )

    if provider == LLMProvider.OPENAI:
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=cfg.model if cfg.model != "llama3.1:8b" else "gpt-4o",
            api_key=api_key,
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
        )

    raise ValueError(f"Unknown LLM provider: {provider}")


async def invoke_llm_with_retry(
    llm: Any,
    prompt: str,
    max_retries: int = MAX_RETRIES,
    sanitize: bool = True,
) -> str:
    """Invoke an LLM with retry logic and optional input/output sanitization.

    Returns the response text. Raises after all retries exhausted.
    """
    from sentinelforge.core.safety import get_safety_engine
    engine = get_safety_engine()

    if sanitize:
        sanitized = engine.sanitize_input(prompt)
        if sanitized.startswith("[SANITIZED"):
            raise ValueError("Prompt injection detected in LLM input")

    last_error: Exception | None = None
    for attempt in range(max_retries):
        try:
            response = await llm.ainvoke(prompt)
            content = response.content if hasattr(response, "content") else str(response)

            if sanitize and engine.detect_prompt_injection(content):
                logger.warning("injection_in_llm_output", attempt=attempt)
                raise ValueError("Prompt injection detected in LLM output")

            model_name = getattr(llm, "model", getattr(llm, "model_name", "unknown"))
            cost = estimate_cost(str(model_name), prompt, content)
            logger.info(
                "llm_invocation",
                model=str(model_name),
                input_tokens=estimate_tokens(prompt),
                output_tokens=estimate_tokens(content),
                cost_usd=cost,
                attempt=attempt + 1,
            )

            return content

        except ValueError:
            raise
        except Exception as exc:
            last_error = exc
            delay = BASE_DELAY * (2 ** attempt)
            logger.warning(
                "llm_retry",
                attempt=attempt + 1,
                max_retries=max_retries,
                error=str(exc),
                delay=delay,
            )
            if attempt < max_retries - 1:
                import asyncio
                await asyncio.sleep(delay)

    raise RuntimeError(f"LLM invocation failed after {max_retries} retries: {last_error}")
