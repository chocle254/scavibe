"""Explicit OpenAI and NVIDIA NIM transports for Scavibe specialists."""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from typing import Literal, Protocol

import httpx


class AgentProtocolError(RuntimeError):
    """Raised when an agent response fails its declared contract."""


class Gateway(Protocol):
    async def generate(self, *, system_prompt: str, input_json: str) -> str: ...

    async def aclose(self) -> None: ...

    @property
    def audit_engine_label(self) -> str: ...


OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
OPENAI_MODEL = "gpt-5.6-terra"
OPENAI_REASONING_EFFORT = "medium"
MAX_OPENAI_OUTPUT_TOKENS = 2048
NVIDIA_NIM_CHAT_COMPLETIONS_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
# Assumption: this current NIM model is the default because NVIDIA documents it
# at the Chat Completions endpoint. Deployments can pin another NIM model with
# SCAVIBE_NVIDIA_MODEL.
DEFAULT_NVIDIA_NIM_MODEL = "nvidia/llama-3.3-nemotron-super-49b-v1.5"
SECURITY_NVIDIA_NIM_MODEL = "deepseek-ai/deepseek-v4-pro"
MAX_NVIDIA_NIM_OUTPUT_TOKENS = 2048
LOGGER = logging.getLogger("scavibe.agents.gateway")


@dataclass(frozen=True)
class OpenAISettings:
    """Server-only OpenAI configuration. The model is intentionally pinned in code."""

    api_key: str

    @classmethod
    def from_environment(cls) -> "OpenAISettings":
        api_key = os.environ.get("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is required to run an audit")
        return cls(api_key=api_key)


@dataclass(frozen=True)
class NvidiaNimSettings:
    """Server-only NVIDIA NIM configuration for an explicit fallback selection."""

    api_key: str
    model: str

    @classmethod
    def from_environment(cls, *, model_override: str | None = None) -> "NvidiaNimSettings":
        api_key = os.environ.get("NVIDIA_API_KEY", "").strip()
        model = (model_override or os.environ.get("SCAVIBE_NVIDIA_MODEL", DEFAULT_NVIDIA_NIM_MODEL)).strip()
        if not api_key:
            raise RuntimeError("NVIDIA_API_KEY is required when SCAVIBE_LLM_PROVIDER=nvidia")
        if not model:
            raise RuntimeError("SCAVIBE_NVIDIA_MODEL cannot be empty")
        return cls(api_key=api_key, model=model)


def selected_llm_provider() -> Literal["openai", "nvidia", "auto"]:
    """Read the explicit server-side provider selection, including logged auto fallback."""
    provider = os.environ.get("SCAVIBE_LLM_PROVIDER", "openai").strip().lower()
    if provider not in {"openai", "nvidia", "auto"}:
        raise RuntimeError("SCAVIBE_LLM_PROVIDER must be exactly openai, nvidia, or auto")
    return provider  # type: ignore[return-value]


class OpenAIGateway:
    """GPT-5.6 Terra adapter using OpenAI's Responses API."""

    def __init__(self, settings: OpenAISettings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings = settings
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(90.0, connect=15.0),
            max_redirects=0,
            transport=transport,
            headers={
                "Authorization": f"Bearer {settings.api_key}",
                "Content-Type": "application/json",
            },
        )

    async def generate(self, *, system_prompt: str, input_json: str) -> str:
        """Request one JSON-only specialist draft without logging source or credentials."""
        safety_identifier = f"scavibe-{hashlib.sha256(input_json.encode('utf-8')).hexdigest()[:32]}"
        payload = {
            "model": OPENAI_MODEL,
            "instructions": system_prompt,
            "input": input_json,
            "reasoning": {"effort": OPENAI_REASONING_EFFORT},
            "max_output_tokens": MAX_OPENAI_OUTPUT_TOKENS,
            "store": False,
            "safety_identifier": safety_identifier,
        }
        LOGGER.info(
            "openai_responses_request endpoint=%s model=%s reasoning_effort=%s max_output_tokens=%s",
            OPENAI_RESPONSES_URL,
            OPENAI_MODEL,
            OPENAI_REASONING_EFFORT,
            MAX_OPENAI_OUTPUT_TOKENS,
        )
        try:
            response = await self._client.post(OPENAI_RESPONSES_URL, json=payload)
            response.raise_for_status()
            response_payload = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise AgentProtocolError(f"OpenAI Responses request failed: {error}") from error
        content = _response_output_text(response_payload)
        if not content:
            raise AgentProtocolError("OpenAI Responses returned no output text")
        return content

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def audit_engine_label(self) -> str:
        return f"OpenAI GPT-5.6 Terra ({OPENAI_MODEL})"


class NvidiaNimGateway:
    """NVIDIA NIM Chat Completions fallback; it does not claim GPT-5.6 output."""

    def __init__(self, settings: NvidiaNimSettings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings = settings
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(90.0, connect=15.0),
            max_redirects=0,
            transport=transport,
            headers={
                "Authorization": f"Bearer {settings.api_key}",
                "Content-Type": "application/json",
            },
        )

    async def generate(self, *, system_prompt: str, input_json: str) -> str:
        """Request one JSON-only draft through NVIDIA's documented Chat Completions API."""
        payload = {
            "model": self._settings.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": input_json},
            ],
            "temperature": 0.0,
            "top_p": 1.0,
            "max_tokens": MAX_NVIDIA_NIM_OUTPUT_TOKENS,
            "stream": False,
        }
        LOGGER.info(
            "nvidia_nim_chat_completions_request endpoint=%s model=%s max_tokens=%s",
            NVIDIA_NIM_CHAT_COMPLETIONS_URL,
            self._settings.model,
            MAX_NVIDIA_NIM_OUTPUT_TOKENS,
        )
        try:
            response = await self._client.post(NVIDIA_NIM_CHAT_COMPLETIONS_URL, json=payload)
            response.raise_for_status()
            content = _nim_message_content(response.json())
        except (httpx.HTTPError, ValueError) as error:
            raise AgentProtocolError(f"NVIDIA NIM request failed: {error}") from error
        if not content:
            raise AgentProtocolError("NVIDIA NIM returned no message content")
        return content

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def audit_engine_label(self) -> str:
        return f"NVIDIA NIM ({self._settings.model})"


class AutoFallbackGateway:
    """OpenAI-first provider with one explicit NVIDIA retry for gateway failures."""

    def __init__(self, primary: OpenAIGateway, fallback: NvidiaNimGateway) -> None:
        self._primary = primary
        self._fallback = fallback
        self._successful_engines: list[str] = []

    async def generate(self, *, system_prompt: str, input_json: str) -> str:
        try:
            content = await self._primary.generate(system_prompt=system_prompt, input_json=input_json)
        except AgentProtocolError as primary_error:
            LOGGER.warning(
                "openai_gateway_failed_using_nvidia_fallback error_type=%s",
                type(primary_error).__name__,
            )
            content = await self._fallback.generate(system_prompt=system_prompt, input_json=input_json)
            self._record_engine(self._fallback.audit_engine_label)
            return content
        self._record_engine(self._primary.audit_engine_label)
        return content

    async def aclose(self) -> None:
        await self._primary.aclose()
        await self._fallback.aclose()

    @property
    def audit_engine_label(self) -> str:
        if not self._successful_engines:
            return "OpenAI preferred with NVIDIA NIM fallback (no successful model response)"
        return "; ".join(self._successful_engines)

    def _record_engine(self, engine: str) -> None:
        if engine not in self._successful_engines:
            self._successful_engines.append(engine)


def _response_output_text(payload: object) -> str | None:
    """Read text from the documented Responses result shape without accepting refusals."""
    if not isinstance(payload, dict):
        return None
    output_text = payload.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text
    output = payload.get("output")
    if not isinstance(output, list):
        return None
    fragments: list[str] = []
    for item in output:
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if isinstance(part, dict) and part.get("type") == "output_text" and isinstance(part.get("text"), str):
                fragments.append(part["text"])
    rendered = "".join(fragments).strip()
    return rendered or None


def _nim_message_content(payload: object) -> str | None:
    """Read the strict first-choice text shape from an OpenAI-compatible NIM result."""
    if not isinstance(payload, dict):
        return None
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    return content.strip() if isinstance(content, str) and content.strip() else None
