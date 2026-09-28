"""Rate Check Agent class with explicit OpenRouter + DeepSeek invocation."""

import logging
import os
import re
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient

from .framework import AcmeLoanAgentFramework

logger = logging.getLogger(__name__)


class RateCheckAgent(AcmeLoanAgentFramework):
    AGENT_ID = "rate_check_agent"
    AGENT_NAME = "Rate_Check Agent"
    VERSION = "1.0.0"
    OPENROUTER_MODEL = "deepseek/deepseek-r1"
    MODEL_NAME = "deepseek/deepseek-r1"
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Checks lending-rate questions using DeepSeek through OpenRouter."
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Answer rate-check questions with short, practical lending-rate guidance."
    IS_ROUTABLE = False

    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(self):
        super().__init__()
        self.openrouter_client = OpenAICompatibleClient(
            base_url=self.OPENROUTER_BASE_URL,
            api_key=os.getenv("OPENROUTER_API_KEY"),
        )

    def to_dict(self) -> dict[str, Any]:
        metadata = super().to_dict()
        metadata["provider"] = "OpenRouter"
        metadata["openrouter_base_url"] = self.OPENROUTER_BASE_URL
        metadata["openrouter_model"] = self.resolve_model()
        return metadata

    def sanitize_user_message(self, user_message: str) -> tuple[str, bool]:
        sanitized = (user_message or "").strip() or "No rate request provided."
        suspicious_patterns = [
            re.compile(r"<!--.*?-->", re.DOTALL),
            re.compile(r"[A-Za-z0-9+/=]{24,}"),
            re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm|chmod|python\s+-c|exec|eval|subprocess)\b", re.IGNORECASE),
            re.compile(r"\bc[\W_]*u[\W_]*r[\W_]*l\b", re.IGNORECASE),
            re.compile(r"\bc[4@]rl\b|\bw[6g]et\b|\br[mn]\b", re.IGNORECASE),
        ]

        blocked = False
        for pattern in suspicious_patterns:
            if pattern.search(sanitized):
                blocked = True
                sanitized = pattern.sub("<blocked_unsafe_content>", sanitized)

        return sanitized, blocked

    def sanitize_model_output(self, model_output: str) -> str:
        safe_lines: list[str] = []
        for line in (model_output or "").splitlines():
            if re.search(r"\b(?:eval|exec|subprocess|shell\s*=\s*True|os\.system)\b", line, re.IGNORECASE):
                continue
            safe_lines.append(line)
        return "\n".join(safe_lines).strip() or "Rate summary unavailable."

    async def call_agent_model(self, user_message: str) -> str:
        model = self.resolve_model()
        if not os.getenv("OPENROUTER_API_KEY"):
            return "LLM service not configured. Please set OPENROUTER_API_KEY."
        if not model:
            return "LLM service not configured. Please set OPENROUTER_MODEL."

        logger.info(
            "Rate check LLM request",
            extra={
                "agent": self.AGENT_ID,
                "model": model,
                "prompt_length": len(user_message or ""),
            },
        )
        model_output = await self.openrouter_client.chat(
            model=model,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Rate check request:\n{user_message or 'No rate request provided.'}\n\n"
                        "Provide a concise rate check summary."
                    ),
                },
            ],
            temperature=0.2,
            # deepseek-r1 spends completion tokens on a hidden reasoning pass, so a
            # small budget returns empty content. Leave room for reasoning and the answer.
            max_tokens=900,
        )
        logger.info(
            "Rate check LLM response",
            extra={
                "agent": self.AGENT_ID,
                "model": model,
                "response_length": len(model_output or ""),
            },
        )
        return model_output

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        safe_user_message, blocked_unsafe_content = self.sanitize_user_message(user_message)
        prompt_message = safe_user_message
        if blocked_unsafe_content:
            prompt_message = (
                "A rate-check request contained blocked unsafe prompt content. "
                "Use only the remaining safe request details."
            )

        model_output = self.sanitize_model_output(await self.call_agent_model(prompt_message))

        response = (
            f"Rate check request: {safe_user_message}\n\n"
            f"Using model: {self.resolve_model()}\n\n"
            f"Rate summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.resolve_model(),
            "framework": self.FRAMEWORK_NAME,
            "provider": "OpenRouter",
        }


rate_check_agent = RateCheckAgent()
