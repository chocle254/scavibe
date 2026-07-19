"""Transport contract tests for the pinned OpenAI specialist gateway."""

from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

import httpx

from scavibe.agents.gateway import (
    OPENAI_MODEL,
    OPENAI_REASONING_EFFORT,
    OPENAI_RESPONSES_URL,
    OpenAIGateway,
    OpenAISettings,
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

