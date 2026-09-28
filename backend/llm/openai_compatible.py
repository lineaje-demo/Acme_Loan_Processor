"""
OpenAI-compatible model gateway client.

This keeps the request shape real and makes the selected model visible in each
agent file via the `model=` argument on every call.
"""

import asyncio
import logging
import os
from typing import Any, Optional

import re

import requests

_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(
        r'ignore\s+previous\s+instructions|forget\s+everything\s+above',
        re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(
        r'you\s+are\s+now\s+DAN|act\s+as\s+unrestricted',
        re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape
    (re.compile(
        r'</\s*system\s*>|<\s*system\s*>',
        re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    # 6. fake_system_message
    (re.compile(
        r'\[\s*system\s*\]|\[\s*tool\s*\]',
        re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt
    (re.compile(
        r'!\[.*?\]\(https?://[^)]+\)|send\s+(?:this\s+)?(?:data|info|prompt)\s+to\s+https?://|leak\s+the\s+system\s+prompt',
        re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # 10. command_injection
    (re.compile(
        r'(?:^|\s)(?:rm\s+-rf|sudo\s+|chmod\s+|curl\s+.*\|\s*sh|wget\s+.*\|\s*sh)',
        re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    # 12. jailbreak_attempt
    (re.compile(
        r'\bDAN\b|developer\s+mode\s+enabled|fictional\s+framing\s+bypass',
        re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
    # 5. hidden_text (zero-width characters)
    (re.compile(
        r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]'),
        '<prompt_injection_removed: hidden_text>'),
    # 8. context_poisoning
    (re.compile(
        r'context\s+poisoning|multi[- ]turn\s+manipulation',
        re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    # 11. split_payload
    (re.compile(
        r'fragmented\s+payload|split\s+payload',
        re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Replace known prompt injection patterns with their markers."""
    if not isinstance(text, str):
        return text
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


def _ai_app_sec_070_sanitize_messages(messages: list) -> list:
    """Return a copy of messages with all text content sanitized."""
    sanitized = []
    for msg in messages:
        content = msg.get('content')
        if isinstance(content, str):
            msg = dict(msg, content=_ai_app_sec_070_sanitize(content))
        elif isinstance(content, list):
            new_parts = []
            for part in content:
                if isinstance(part, dict) and part.get('type') == 'text':
                    part = dict(part, text=_ai_app_sec_070_sanitize(part.get('text', '')))
                new_parts.append(part)
            msg = dict(msg, content=new_parts)
        sanitized.append(msg)
    return sanitized
from lineaje_guardrail import lineaje_guardrail

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])

logger = logging.getLogger(__name__)


class OpenAICompatibleClient:
    """Minimal async wrapper around a chat-completions style API."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        # Use OpenRouter credentials from the environment.
        self.base_url = (
            base_url
            or os.getenv("OPENROUTER_BASE_URL")
            or "https://openrouter.ai/api/v1"
        ).rstrip("/")
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")

    async def chat(
        self,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 400,
    ) -> str:
        messages = _ai_app_sec_059_guardrail.evaluate(messages)
        messages = _ai_app_sec_070_sanitize_messages(messages)
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        def _post() -> str:
            try:
                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=20,
                )
                response.raise_for_status()
                data = response.json()
                choices = data.get("choices", [])
                if choices:
                    message = choices[0].get("message", {})
                    content = message.get("content", "")
                    if isinstance(content, str):
                        return content.strip()
                return f"Model API returned no content for model {model}."
            except requests.RequestException as exc:
                logger.warning(
                    "Model gateway request failed",
                    extra={"model": model, "error": str(exc)},
                )
                return f"Model gateway unavailable for {model}: {exc}"

        return await asyncio.to_thread(_post)

    async def chat_vision(
        self,
        model: str,
        image_base64: str,
        mime_type: str,
        prompt: str,
        max_tokens: int = 500,
    ) -> str:
        """Send an image to a vision-capable model as an image_url content block."""
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:{mime_type};base64,{image_base64}"},
                    },
                ],
            }
        ]
        prompt = _ai_app_sec_059_guardrail.evaluate(prompt)
        prompt = _ai_app_sec_070_sanitize(prompt)
        return await self.chat(model=model, messages=messages, temperature=0.0, max_tokens=max_tokens)
