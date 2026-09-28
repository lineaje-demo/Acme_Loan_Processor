"""Small agent framework base class used by the Acme Loan Processor agents."""

import os
import re
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient

_ai_app_sec_070_patterns: list[tuple[str, str]] = [
    # 1. instruction_override
    (r'(?i)ignore\s+previous\s+instructions', '<prompt_injection_removed: instruction_override>'),
    (r'(?i)forget\s+everything\s+above', '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (r'(?i)you\s+are\s+now\s+DAN', '<prompt_injection_removed: role_hijack>'),
    (r'(?i)act\s+as\s+unrestricted', '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape — fake </system> or </prompt> tags and injected separators
    (r'(?i)</?\s*system\s*>', '<prompt_injection_removed: delimiter_escape>'),
    (r'(?i)</?\s*prompt\s*>', '<prompt_injection_removed: delimiter_escape>'),
    (r'(?i)</?\s*instructions?\s*>', '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload — base64 blobs, hex sequences, ROT13 cues, URL-encoded instructions
    (r'(?i)\bROT13\b.*?(?:ignore|forget|override|jailbreak)', '<prompt_injection_removed: encoded_payload>'),
    (r'(?:[A-Za-z0-9+/]{40,}={0,2})', '<prompt_injection_removed: encoded_payload>'),
    (r'(?i)(?:\\x[0-9a-f]{2}){8,}', '<prompt_injection_removed: encoded_payload>'),
    (r'(?i)(?:%[0-9a-f]{2}){8,}', '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text — HTML comments, zero-width chars, CSS hidden
    (r'<!--.*?-->', '<prompt_injection_removed: hidden_text>'),
    (r'[\u200b\u200c\u200d\u200e\u200f\ufeff]+', '<prompt_injection_removed: hidden_text>'),
    (r'(?i)style\s*=\s*["\']?display\s*:\s*none', '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (r'(?i)\[\s*system\s*\]', '<prompt_injection_removed: fake_system_message>'),
    (r'(?i)\[\s*tool\s*\]', '<prompt_injection_removed: fake_system_message>'),
    (r'(?i)###\s*system', '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt
    (r'(?i)!\[.*?\]\(https?://[^)]+\)', '<prompt_injection_removed: exfiltration_attempt>'),
    (r'(?i)send\s+(?:the\s+)?(?:data|prompt|system\s+prompt|context)\s+to\s+https?://', '<prompt_injection_removed: exfiltration_attempt>'),
    (r'(?i)leak\s+(?:the\s+)?system\s+prompt', '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (r'(?i)in\s+a\s+previous\s+(?:turn|message|conversation).*?(?:you\s+said|you\s+agreed)', '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection
    (r'(?i)(?:the\s+)?(?:file|document|metadata|field)\s+(?:says?|contains?|instructs?)\s+you\s+to', '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection
    (r'(?i)(?:^|\s)(?:eval|exec|os\.system|subprocess\.(?:call|run|Popen))\s*\(', '<prompt_injection_removed: command_injection>'),
    (r'(?i)`[^`]*(?:rm|curl|wget|bash|sh|python|perl|ruby)[^`]*`', '<prompt_injection_removed: command_injection>'),
    # 11. split_payload
    (r'(?i)(?:part\s*1\s*of\s*\d+|continued\s+in\s+next\s+message).*?(?:ignore|override|jailbreak)', '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt
    (r'(?i)\bDAN\b', '<prompt_injection_removed: jailbreak_attempt>'),
    (r'(?i)developer\s+mode', '<prompt_injection_removed: jailbreak_attempt>'),
    (r'(?i)fictional\s+framing', '<prompt_injection_removed: jailbreak_attempt>'),
    (r'(?i)jailbreak', '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize_messages(
    messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return a copy of messages with prompt-injection patterns neutralized."""
    sanitized: list[dict[str, Any]] = []
    for msg in messages:
        msg_copy = dict(msg)
        content = msg_copy.get('content')
        if isinstance(content, str):
            for pattern, marker in _ai_app_sec_070_patterns:
                content = re.sub(pattern, marker, content, flags=re.DOTALL)
            msg_copy['content'] = content
        sanitized.append(msg_copy)
    return sanitized
from lineaje_guardrail import lineaje_guardrail, GuardrailBlockedError

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])


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

        messages = _ai_app_sec_059_guardrail.evaluate(messages)
        messages = _ai_app_sec_070_sanitize_messages(messages)
        return await self.model_client.chat(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    @abstractmethod
    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """Handle a request for this agent."""
