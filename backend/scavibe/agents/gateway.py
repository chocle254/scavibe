"""NVIDIA NIM gateway configuration and transport."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol


class AgentProtocolError(RuntimeError):
    """Raised when an agent response fails its declared contract."""


class Gateway(Protocol):
    async def generate(self, *, system_prompt: str, input_json: str) -> str: ...


NVIDIA_NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_NVIDIA_MODEL = "nvidia/llama-3.3-nemotron-super-49b-v1"
MAX_NIM_OUTPUT_TOKENS = 2048


@dataclass(frozen=True)
class NvidiaNimSettings:
    """NVIDIA NIM configuration for the selected free trial endpoint."""

    model: str

    @classmethod
    def from_environment(cls) -> "NvidiaNimSettings":
        model = os.environ.get("SCAVIBE_NVIDIA_MODEL", DEFAULT_NVIDIA_MODEL).strip()
        if not model:
            raise RuntimeError("SCAVIBE_NVIDIA_MODEL cannot be empty")
        if not os.environ.get("NVIDIA_API_KEY", "").strip():
            raise RuntimeError("NVIDIA_API_KEY is required to run an audit")
        return cls(model=model)


class NvidiaNimGateway:
    """NVIDIA NIM's OpenAI-compatible Chat Completions adapter."""

    def __init__(self, settings: NvidiaNimSettings) -> None:
        self._settings = settings
        try:
            from openai import AsyncOpenAI
        except ImportError as error:
            raise RuntimeError("openai package is required; run pip install -r requirements.txt") from error
        self._client = AsyncOpenAI(
            base_url=NVIDIA_NIM_BASE_URL,
            api_key=os.environ["NVIDIA_API_KEY"],
            max_retries=2,
            timeout=60.0,
        )

    async def generate(self, *, system_prompt: str, input_json: str) -> str:
        try:
            response = await self._client.chat.completions.create(
                model=self._settings.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": input_json},
                ],
                temperature=0.0,
                top_p=1.0,
                max_tokens=MAX_NIM_OUTPUT_TOKENS,
                stream=False,
            )
        except Exception as error:
            raise AgentProtocolError(f"NVIDIA NIM request failed: {error}") from error
        content = response.choices[0].message.content if response.choices else None
        if not content or not content.strip():
            raise AgentProtocolError("NVIDIA NIM returned no message content")
        return content
