"""
OpenAI-compatible model gateway client.

This keeps the request shape real and makes the selected model visible in each
agent file via the `model=` argument on every call.
"""

import asyncio
import logging
import os
import re
import time
from typing import Any, Optional

import requests
from llm.unifai_guard import sanitize_prompt, find_prompt_attacks, redact_pii, mask_pii, sanitize_messages, find_code_execution, remove_suspicious_content, remove_hidden_prompts, remove_encoded_prompts, remove_leetspeak_prompts, find_command_requests

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


_HERE_IS_ANSWER = re.compile(r"here(?:'s| is| are)\b", re.IGNORECASE)
_FORMATTED_PARAGRAPH = re.compile(r"(?:\*\*|#{1,6}\s|[-*]\s|\d+\.\s)")
_MIN_RECOVERED_ANSWER_CHARS = 40


def _sanitize_model_text(text: str) -> str:
    text = redact_pii(text, categories=('ssn', 'year_of_birth', 'birthplace', 'phone', 'email', 'mothers_maiden_name', 'home_address', 'passport_number', 'drivers_license_number', 'taxpayer_id', 'credit_card', 'financial_account_number', 'fingerprints', 'retina_iris_scan', 'voice_signature', 'facial_image', 'medical_records', 'employee_id', 'school_id', 'vehicle_identification_number', 'ip_address', 'mac_address', 'fine_location', 'ethnicity', 'sexual_orientation', 'aws_access_key_id', 'aws_secret_access_key', 'gcp_service_account_key', 'azure_client_secret', 'private_key', 'password', 'api_key', 'oauth_token'))
    text = remove_hidden_prompts(text)
    text = remove_encoded_prompts(text)
    text = remove_leetspeak_prompts(text)
    text = sanitize_prompt(text)
    return text


def _sanitize_model_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized_messages = sanitize_messages(messages)
    for message in sanitized_messages:
        content = message.get("content")
        if isinstance(content, str):
            message["content"] = _sanitize_model_text(content)
        elif isinstance(content, list):
            sanitized_parts = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                    sanitized_part = dict(part)
                    sanitized_part["text"] = _sanitize_model_text(part["text"])
                    sanitized_parts.append(sanitized_part)
                else:
                    sanitized_parts.append(part)
            message["content"] = sanitized_parts
    return sanitized_messages


def _sanitize_model_output(text: str) -> str:
    findings = find_code_execution(text)
    if not findings:
        return text
    safe_lines = [line for line in text.splitlines() if not find_code_execution(line)]
    sanitized = "\n".join(safe_lines)
    return sanitized if sanitized else "Response blocked due to unsafe code execution content."


def _answer_from_reasoning(reasoning: str) -> str:
    """Recover the final answer when a reasoning model returns it inside
    `reasoning` instead of `content` (Novita's deepseek-r1 does this: the
    thinking and the answer arrive as one block, answer last).

    Takes everything from the last "Here's / Here is ..." paragraph, else the
    trailing run of markdown-formatted paragraphs. Returns "" if neither is
    found, so the caller can retry."""
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", reasoning or "") if p.strip()]
    answer = ""
    for index in range(len(paragraphs) - 1, -1, -1):
        if _HERE_IS_ANSWER.match(paragraphs[index]):
            answer = "\n\n".join(paragraphs[index:])
            break
    else:
        start = len(paragraphs)
        while start > 0 and _FORMATTED_PARAGRAPH.match(paragraphs[start - 1]):
            start -= 1
        answer = "\n\n".join(paragraphs[start:])
    return answer if len(answer) >= _MIN_RECOVERED_ANSWER_CHARS else ""


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
        recover_answer_from_reasoning: bool = False,
    ) -> str:
        messages = _sanitize_model_messages(messages)
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
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
                    message = (choices[0].get("message") or {}) if choices else {}
                    content = _extract_content(message)
                    if not content and recover_answer_from_reasoning:
                        content = _answer_from_reasoning(message.get("reasoning") or "")
                        if content:
                            logger.info(
                                "Recovered answer from the reasoning field",
                                extra={"model": model, "provider": data.get("provider")},
                            )
                    if content:
                        content = _sanitize_model_output(content)
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
                content = (
                    f"{model} returned an empty response {empty_responses} times in a row. "
                    "The upstream provider is flaky right now — please try again."
                )
                content = _sanitize_model_output(content)
                return content

            logger.warning(
                "Model gateway request failed",
                extra={"model": model, "error": str(last_exc)},
            )
            content = f"Model gateway unavailable for {model}: {last_exc}"
            content = _sanitize_model_output(content)
            return content

        content = await asyncio.to_thread(_post)
        content = _sanitize_model_output(content)
        return content

    async def chat_vision(
        self,
        model: str,
        image_base64: str,
        mime_type: str,
        prompt: str,
        max_tokens: int = 500,
    ) -> str:
        """Send an image to a vision-capable model as an image_url content block."""
        prompt = _sanitize_model_text(prompt)
        image_base64 = redact_pii(image_base64, categories=('ssn', 'year_of_birth', 'birthplace', 'phone', 'email', 'mothers_maiden_name', 'home_address', 'passport_number', 'drivers_license_number', 'taxpayer_id', 'credit_card', 'financial_account_number', 'fingerprints', 'retina_iris_scan', 'voice_signature', 'facial_image', 'medical_records', 'employee_id', 'school_id', 'vehicle_identification_number', 'ip_address', 'mac_address', 'fine_location', 'ethnicity', 'sexual_orientation', 'aws_access_key_id', 'aws_secret_access_key', 'gcp_service_account_key', 'azure_client_secret', 'private_key', 'password', 'api_key', 'oauth_token'))
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
        messages = sanitize_messages(messages)
        messages = redact_pii(messages, categories=('ssn', 'year_of_birth', 'birthplace', 'phone', 'email', 'mothers_maiden_name', 'home_address', 'passport_number', 'drivers_license_number', 'taxpayer_id', 'credit_card', 'financial_account_number', 'fingerprints', 'retina_iris_scan', 'voice_signature', 'facial_image', 'medical_records', 'employee_id', 'school_id', 'vehicle_identification_number', 'ip_address', 'mac_address', 'fine_location', 'ethnicity', 'sexual_orientation', 'aws_access_key_id', 'aws_secret_access_key', 'gcp_service_account_key', 'azure_client_secret', 'private_key', 'password', 'api_key', 'oauth_token'))
        return await self.chat(model=model, messages=messages, temperature=0.0, max_tokens=max_tokens)
