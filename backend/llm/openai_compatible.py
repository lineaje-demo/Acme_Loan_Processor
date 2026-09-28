"""
OpenAI-compatible model gateway client.

This keeps the request shape real and makes the selected model visible in each
agent file via the `model=` argument on every call.
"""

import asyncio
import logging
import os
import time
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

# Retry transient upstream failures (5xx / gateway timeouts / connection
# resets / empty completions). meta-llama/llama-4-scout on OpenRouter
# occasionally returns a 504 Gateway Timeout, and deepseek/deepseek-r1 (only
# served by Novita) sometimes finishes with an empty `content`.
_MAX_ATTEMPTS = 4
_RETRY_BACKOFF_SEC = 1.5
# Reasoning models such as deepseek-r1 take 15-30s per call.
_REQUEST_TIMEOUT_SEC = 90


def _extract_content(message: dict[str, Any]) -> str:
    """Return the assistant text from a chat-completions message, accepting
    either a plain string or a list of content parts."""
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = [
            part.get("text", "") if isinstance(part, dict) else str(part)
            for part in content
        ]
        return "".join(parts).strip()
    return ""


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
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            # Ask OpenRouter to keep a reasoning model's chain-of-thought out of
            # the reply. Without this, Novita's deepseek-r1 often puts the whole
            # answer in `reasoning` and leaves `content` empty. Non-reasoning
            # models ignore it.
            "reasoning": {"exclude": True},
        }

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        def _post() -> str:
            last_exc: Optional[Exception] = None
            empty_responses = 0
            for attempt in range(1, _MAX_ATTEMPTS + 1):
                try:
                    response = requests.post(
                        f"{self.base_url}/chat/completions",
                        json=payload,
                        headers=headers,
                        timeout=_REQUEST_TIMEOUT_SEC,
                    )
                    response.raise_for_status()
                    data = response.json()
                    choices = data.get("choices") or []
                    content = _extract_content(choices[0].get("message") or {}) if choices else ""
                    if content:
                        return content

                    # 200 OK but no answer text: transient provider behaviour,
                    # so retry instead of surfacing an empty reply.
                    empty_responses += 1
                    last_exc = None
                    if attempt < _MAX_ATTEMPTS:
                        logger.warning(
                            "Model returned empty content — retrying (%d/%d)",
                            attempt, _MAX_ATTEMPTS,
                            extra={
                                "model": model,
                                "provider": data.get("provider"),
                                "finish_reason": choices[0].get("finish_reason") if choices else None,
                            },
                        )
                        time.sleep(_RETRY_BACKOFF_SEC * attempt)
                        continue
                    break
                except requests.HTTPError as exc:
                    last_exc = exc
                    status = exc.response.status_code if exc.response is not None else None
                    # Retry only on transient upstream 5xx (e.g. 504 gateway
                    # timeout). 4xx are caller errors — fail fast.
                    if status is not None and 500 <= status < 600 and attempt < _MAX_ATTEMPTS:
                        logger.warning(
                            "Model gateway %s — retrying (%d/%d)",
                            status, attempt, _MAX_ATTEMPTS,
                            extra={"model": model},
                        )
                        time.sleep(_RETRY_BACKOFF_SEC * attempt)
                        continue
                    break
                except (requests.Timeout, requests.ConnectionError) as exc:
                    last_exc = exc
                    if attempt < _MAX_ATTEMPTS:
                        logger.warning(
                            "Model gateway network error — retrying (%d/%d): %s",
                            attempt, _MAX_ATTEMPTS, exc,
                            extra={"model": model},
                        )
                        time.sleep(_RETRY_BACKOFF_SEC * attempt)
                        continue
                    break
                except requests.RequestException as exc:
                    last_exc = exc
                    break

            if last_exc is None and empty_responses:
                logger.warning(
                    "Model returned empty content on every attempt",
                    extra={"model": model, "attempts": empty_responses},
                )
                return (
                    f"{model} returned an empty response {empty_responses} times in a row. "
                    "The upstream provider is flaky right now — please try again."
                )

            logger.warning(
                "Model gateway request failed",
                extra={"model": model, "error": str(last_exc)},
            )
            return f"Model gateway unavailable for {model}: {last_exc}"

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
        return await self.chat(model=model, messages=messages, temperature=0.0, max_tokens=max_tokens)
