"""OpenAI Responses API configuration and transport for Scavibe specialists."""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from typing import Protocol

import httpx


class AgentProtocolError(RuntimeError):
    """Raised when an agent response fails its declared contract."""


class Gateway(Protocol):
    async def generate(self, *, system_prompt: str, input_json: str) -> str: ...


OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
OPENAI_MODEL = "gpt-5.6-terra"
OPENAI_REASONING_EFFORT = "medium"
MAX_OPENAI_OUTPUT_TOKENS = 2048
LOGGER = logging.getLogger("scavibe.openai")


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
