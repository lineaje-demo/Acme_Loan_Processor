"""Small agent framework base class used by the Acme Loan Processor agents."""

import os
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient
from agents.unifai_guard import sanitize_prompt, find_prompt_attacks, redact_pii, mask_pii, sanitize_messages, find_code_execution, remove_suspicious_content, remove_hidden_prompts, remove_encoded_prompts, remove_leetspeak_prompts, find_command_requests


def _apply_message_text_guard(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized_messages = deepcopy(messages)
    for message in sanitized_messages:
        if not isinstance(message, dict):
            continue
        if message.get("role") not in {"user", "tool"}:
            continue
        content = message.get("content")
        if isinstance(content, str):
            content = redact_pii(content, categories=('ssn', 'year_of_birth', 'birthplace', 'phone', 'email', 'mothers_maiden_name', 'home_address', 'passport_number', 'drivers_license_number', 'taxpayer_id', 'credit_card', 'financial_account_number', 'fingerprints', 'retina_iris_scan', 'voice_signature', 'facial_image', 'medical_records', 'employee_id', 'school_id', 'vehicle_identification_number', 'ip_address', 'mac_address', 'fine_location', 'ethnicity', 'sexual_orientation', 'aws_access_key_id', 'aws_secret_access_key', 'gcp_service_account_key', 'azure_client_secret', 'private_key', 'password', 'api_key', 'oauth_token'))
            content = remove_hidden_prompts(content)
            content = remove_encoded_prompts(content)
            content = remove_leetspeak_prompts(content)
            content = sanitize_prompt(content)
            message["content"] = content
        elif isinstance(content, list):
            for part in content:
                if not isinstance(part, dict):
                    continue
                if isinstance(part.get("text"), str):
                    text = part["text"]
                    text = redact_pii(text, categories=('ssn', 'year_of_birth', 'birthplace', 'phone', 'email', 'mothers_maiden_name', 'home_address', 'passport_number', 'drivers_license_number', 'taxpayer_id', 'credit_card', 'financial_account_number', 'fingerprints', 'retina_iris_scan', 'voice_signature', 'facial_image', 'medical_records', 'employee_id', 'school_id', 'vehicle_identification_number', 'ip_address', 'mac_address', 'fine_location', 'ethnicity', 'sexual_orientation', 'aws_access_key_id', 'aws_secret_access_key', 'gcp_service_account_key', 'azure_client_secret', 'private_key', 'password', 'api_key', 'oauth_token'))
                    text = remove_hidden_prompts(text)
                    text = remove_encoded_prompts(text)
                    text = remove_leetspeak_prompts(text)
                    text = sanitize_prompt(text)
                    part["text"] = text
    return sanitized_messages


class AcmeLoanAgentFramework(ABC):
    """Base class that makes agent metadata and model usage obvious."""

    FRAMEWORK_NAME = "AcmeLoanAgentFramework"
    AGENT_ID = ""
    AGENT_NAME = ""
    VERSION = "1.0.0"
    MODEL_NAME = ""
    BEDROCK_MODEL_ID = ""
    BEDROCK_FALLBACK_MODEL_ID = ""
    DESCRIPTION = ""
    MCP_SERVERS: list[str] = []
    GUARDRAILS: dict[str, Any] = {}
    SYSTEM_PROMPT = ""
    IS_ROUTABLE = True
    IS_SCAN_ONLY = False

    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(self):
        # Runtime LLM calls use OpenRouter credentials from .env:
        # OPENROUTER_API_KEY and OPENROUTER_MODEL.
        self.model_client = OpenAICompatibleClient(
            base_url=self.OPENROUTER_BASE_URL,
            api_key=os.getenv("OPENROUTER_API_KEY"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.AGENT_ID,
            "name": self.AGENT_NAME,
            "version": self.VERSION,
            "framework": self.FRAMEWORK_NAME,
            "model": self.MODEL_NAME,
            "provider": "OpenRouter",
            "openrouter_model": os.getenv("OPENROUTER_MODEL"),
            "bedrock_model_id": self.BEDROCK_MODEL_ID,
            "bedrock_fallback_model_id": self.BEDROCK_FALLBACK_MODEL_ID,
            "description": self.DESCRIPTION,
            "mcp_servers": list(self.MCP_SERVERS),
            "guardrails": deepcopy(self.GUARDRAILS),
            "system_prompt": self.SYSTEM_PROMPT,
            "is_routable": self.IS_ROUTABLE,
            "is_scan_only": self.IS_SCAN_ONLY,
        }

    async def call_bedrock_model(
        self,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 350,
    ) -> str:
        """Call OpenRouter using OPENROUTER_API_KEY + OPENROUTER_MODEL.

        Method name is kept for compatibility with existing agents.
        """
        api_key = (os.getenv("OPENROUTER_API_KEY") or "").strip()
        model = (os.getenv("OPENROUTER_MODEL") or "").strip()
        if not api_key:
            return "LLM service not configured. Please set OPENROUTER_API_KEY."
        if not model:
            return "LLM service not configured. Please set OPENROUTER_MODEL."

        messages = _apply_message_text_guard(messages)
        response = await self.model_client.chat(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if isinstance(response, str) and find_code_execution(response):
            return "LLM response blocked due to unsafe code execution content."
        return response

    @abstractmethod
    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """Handle a request for this agent."""
