"""Transport contract tests for the pinned OpenAI specialist gateway."""

from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

import httpx

from scavibe.agents.gateway import (
    DEFAULT_NVIDIA_NIM_MODEL,
    MAX_NVIDIA_NIM_OUTPUT_TOKENS,
    NVIDIA_NIM_CHAT_COMPLETIONS_URL,
    OPENAI_MODEL,
    OPENAI_REASONING_EFFORT,
    OPENAI_RESPONSES_URL,
    NvidiaNimGateway,
    NvidiaNimSettings,
    OpenAIGateway,
    OpenAISettings,
    selected_llm_provider,
)


class OpenAIGatewayTests(unittest.IsolatedAsyncioTestCase):
    async def test_posts_to_openai_responses_with_pinned_gpt_5_6_terra(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(
                status_code=200,
                json={
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": '{"stage":"security","summary":"ok","findings":[],"limitations":[]}',
                                }
                            ],
                        }
                    ]
                },
            )

        gateway = OpenAIGateway(
            OpenAISettings(api_key="test-openai-key"),
            transport=httpx.MockTransport(handler),
        )
        try:
            response = await gateway.generate(
                system_prompt="Return the required JSON.",
                input_json='{"stage":"security"}',
            )
        finally:
            await gateway.aclose()

        self.assertEqual(response, '{"stage":"security","summary":"ok","findings":[],"limitations":[]}')
        self.assertEqual(len(requests), 1)
        request = requests[0]
        self.assertEqual(str(request.url), OPENAI_RESPONSES_URL)
        self.assertEqual(request.headers["authorization"], "Bearer test-openai-key")
        payload = json.loads(request.content)
        self.assertEqual(payload["model"], OPENAI_MODEL)
        self.assertEqual(OPENAI_MODEL, "gpt-5.6-terra")
        self.assertEqual(payload["reasoning"], {"effort": OPENAI_REASONING_EFFORT})
        self.assertEqual(payload["input"], '{"stage":"security"}')
        self.assertFalse(payload["store"])

    def test_settings_requires_openai_api_key(self) -> None:
        environment = dict(os.environ)
        environment.pop("OPENAI_API_KEY", None)
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(RuntimeError, "OPENAI_API_KEY"):
                OpenAISettings.from_environment()

    async def test_posts_to_nvidia_nim_when_explicitly_selected(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(
                status_code=200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": '{"stage":"legal","summary":"ok","findings":[],"limitations":[]}'
                            }
                        }
                    ]
                },
            )

        gateway = NvidiaNimGateway(
            NvidiaNimSettings(api_key="test-nvidia-key", model=DEFAULT_NVIDIA_NIM_MODEL),
            transport=httpx.MockTransport(handler),
        )
        try:
            response = await gateway.generate(
                system_prompt="Return the required JSON.",
                input_json='{"stage":"legal"}',
            )
        finally:
            await gateway.aclose()

        self.assertEqual(response, '{"stage":"legal","summary":"ok","findings":[],"limitations":[]}')
        self.assertEqual(str(requests[0].url), NVIDIA_NIM_CHAT_COMPLETIONS_URL)
        self.assertEqual(requests[0].headers["authorization"], "Bearer test-nvidia-key")
        payload = json.loads(requests[0].content)
        self.assertEqual(payload["model"], DEFAULT_NVIDIA_NIM_MODEL)
        self.assertEqual(payload["max_tokens"], MAX_NVIDIA_NIM_OUTPUT_TOKENS)
        self.assertEqual(payload["temperature"], 0.0)
        self.assertFalse(payload["stream"])
        self.assertEqual(gateway.audit_engine_label, f"NVIDIA NIM ({DEFAULT_NVIDIA_NIM_MODEL})")

    def test_provider_selection_requires_an_exact_value(self) -> None:
        environment = dict(os.environ)
        environment["SCAVIBE_LLM_PROVIDER"] = "nvidia"
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(selected_llm_provider(), "nvidia")

        environment["SCAVIBE_LLM_PROVIDER"] = "free"
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(RuntimeError, "SCAVIBE_LLM_PROVIDER"):
                selected_llm_provider()
