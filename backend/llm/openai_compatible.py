"""
OpenAI-compatible model gateway client.

This keeps the request shape real and makes the selected model visible in each
agent file via the `model=` argument on every call.
"""

import asyncio
import logging
import os
from typing import Any, Optional

import requests
from llm.unifai_guard import sanitize_prompt, find_prompt_attacks, redact_pii, mask_pii, sanitize_messages, find_code_execution, remove_suspicious_content, remove_hidden_prompts, remove_encoded_prompts, remove_leetspeak_prompts, find_command_requests

logger = logging.getLogger(__name__)


def _sanitize_outbound_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    messages = sanitize_messages(messages)
    sanitized_messages: list[dict[str, Any]] = []
    for message in messages:
        sanitized_message = dict(message)
        content = sanitized_message.get("content")
        if isinstance(content, str):
            content = redact_pii(content, categories=('ssn', 'year_of_birth', 'birthplace', 'phone', 'email', 'mothers_maiden_name', 'home_address', 'passport_number', 'drivers_license_number', 'taxpayer_id', 'credit_card', 'financial_account_number', 'fingerprints', 'retina_iris_scan', 'voice_signature', 'facial_image', 'medical_records', 'employee_id', 'school_id', 'vehicle_identification_number', 'ip_address', 'mac_address', 'fine_location', 'ethnicity', 'sexual_orientation', 'aws_access_key_id', 'aws_secret_access_key', 'gcp_service_account_key', 'azure_client_secret', 'private_key', 'password', 'api_key', 'oauth_token'))
            content = sanitize_prompt(content)
            sanitized_message["content"] = content
        elif isinstance(content, list):
            sanitized_parts: list[Any] = []
            for part in content:
                if isinstance(part, dict):
                    sanitized_part = dict(part)
                    if sanitized_part.get("type") == "text" and isinstance(sanitized_part.get("text"), str):
                        text = sanitized_part["text"]
                        text = redact_pii(text, categories=('ssn', 'year_of_birth', 'birthplace', 'phone', 'email', 'mothers_maiden_name', 'home_address', 'passport_number', 'drivers_license_number', 'taxpayer_id', 'credit_card', 'financial_account_number', 'fingerprints', 'retina_iris_scan', 'voice_signature', 'facial_image', 'medical_records', 'employee_id', 'school_id', 'vehicle_identification_number', 'ip_address', 'mac_address', 'fine_location', 'ethnicity', 'sexual_orientation', 'aws_access_key_id', 'aws_secret_access_key', 'gcp_service_account_key', 'azure_client_secret', 'private_key', 'password', 'api_key', 'oauth_token'))
                        text = sanitize_prompt(text)
                        sanitized_part["text"] = text
                    sanitized_parts.append(sanitized_part)
                else:
                    sanitized_parts.append(part)
            sanitized_message["content"] = sanitized_parts
        sanitized_messages.append(sanitized_message)
    return sanitized_messages


def _validate_llm_output(content: str, model: str) -> str:
    findings = find_code_execution(content)
    if findings:
        return f"Model output blocked for {model}: unsafe code execution content detected."
    return content


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
        messages = _sanitize_outbound_messages(messages)
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

        result = await asyncio.to_thread(_post)
        return _validate_llm_output(result, model)

    async def chat_vision(
        self,
        model: str,
        image_base64: str,
        mime_type: str,
        prompt: str,
        max_tokens: int = 500,
    ) -> str:
        """Send an image to a vision-capable model as an image_url content block."""
        prompt = remove_hidden_prompts(prompt)
        prompt = remove_encoded_prompts(prompt)
        prompt = remove_leetspeak_prompts(prompt)
        prompt = redact_pii(prompt, categories=('ssn', 'year_of_birth', 'birthplace', 'phone', 'email', 'mothers_maiden_name', 'home_address', 'passport_number', 'drivers_license_number', 'taxpayer_id', 'credit_card', 'financial_account_number', 'fingerprints', 'retina_iris_scan', 'voice_signature', 'facial_image', 'medical_records', 'employee_id', 'school_id', 'vehicle_identification_number', 'ip_address', 'mac_address', 'fine_location', 'ethnicity', 'sexual_orientation', 'aws_access_key_id', 'aws_secret_access_key', 'gcp_service_account_key', 'azure_client_secret', 'private_key', 'password', 'api_key', 'oauth_token'))
        prompt = sanitize_prompt(prompt)
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
        result = await self.chat(model=model, messages=messages, temperature=0.0, max_tokens=max_tokens)
        return _validate_llm_output(result, model)
