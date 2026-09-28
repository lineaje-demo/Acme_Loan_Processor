"""Orchestrator Agent class with explicit model invocation."""

import logging
import os
from typing import Any

from .access_control_agent import access_control_agent
from .credit_eval_agent import credit_eval_agent
from .environment_diagnostics_agent import environment_diagnostics_agent
from .file_management_agent import file_management_agent
from .file_processor_agent import file_processor_agent
from .framework import AcmeLoanAgentFramework
from .loan_processing_agent import loan_processing_agent
from .scheduling_agent import scheduling_agent
from .installed_skill_agent import installed_skill_agent
from lineaje_guardrail import lineaje_guardrail

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])

import re

logger = logging.getLogger(__name__)

_ai_dat_sec_001_internal_hop_token = os.environ.get("INTERNAL_HOP_TOKEN")
if not _ai_dat_sec_001_internal_hop_token:
    raise RuntimeError("Required environment variable INTERNAL_HOP_TOKEN is not set")

_ai_app_sec_070_patterns = [
    (re.compile(r'ignore\s+previous\s+instructions|forget\s+everything\s+above', re.IGNORECASE), 'instruction_override'),
    (re.compile(r'you\s+are\s+now\s+DAN|act\s+as\s+unrestricted', re.IGNORECASE), 'role_hijack'),
    (re.compile(r'</?(system|tool|assistant|user)\s*>', re.IGNORECASE), 'delimiter_escape'),
    (re.compile(r'(?:[A-Za-z0-9+/]{20,}={0,2}|\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2})+|%[0-9a-fA-F]{2}(?:%[0-9a-fA-F]{2})+|(?:[0-9a-fA-F]{2}\s*){8,}|(?:\.-\.|-\.\.|\.-\.-)[\s.-]+)', re.IGNORECASE), 'encoded_payload'),
    (re.compile(r'<!--.*?-->|\u200b|\u200c|\u200d|\u2060|\ufeff|display\s*:\s*none|visibility\s*:\s*hidden', re.IGNORECASE | re.DOTALL), 'hidden_text'),
    (re.compile(r'\[system\]|<system>|\[tool\]|<tool>|\bSYSTEM\s*MESSAGE\b|\bTOOL\s*RESPONSE\b', re.IGNORECASE), 'fake_system_message'),
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)|send\s+(?:this\s+)?(?:data|info|prompt|context)\s+to\s+https?://|leak\s+(?:the\s+)?system\s+prompt|exfiltrate', re.IGNORECASE), 'exfiltration_attempt'),
    (re.compile(r'in\s+(?:a\s+)?previous\s+(?:turn|message|conversation)|remember\s+(?:earlier|before)\s+(?:I\s+)?(?:said|told)', re.IGNORECASE), 'context_poisoning'),
    (re.compile(r'(?:the\s+)?(?:file|document|metadata|field)\s+(?:says?|contains?|instructs?)\s+(?:you\s+)?(?:to\s+)?(?:ignore|forget|override)', re.IGNORECASE), 'indirect_injection'),
    (re.compile(r'(?:^|\s)(?:rm\s+-rf|os\.system|subprocess|eval\s*\(|exec\s*\(|__import__|`[^`]+`|\$\([^)]+\))', re.IGNORECASE), 'command_injection'),
    (re.compile(r'(?:part\s*1\s*of|continued\s*in\s*(?:next|part)|\[part\s*\d+\])', re.IGNORECASE), 'split_payload'),
    (re.compile(r'\bDAN\b|developer\s+mode|jailbreak|fictional\s+(?:scenario|framing|character)\s+(?:where\s+)?(?:you\s+)?(?:can|must|should)\s+(?:ignore|bypass|forget)', re.IGNORECASE), 'jailbreak_attempt'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Replace prompt injection patterns with safe markers before sending to LLM."""
    if not text:
        return text
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(f'<prompt_injection_removed: {marker}>', text)
    return text


class OrchestratorAgent(AcmeLoanAgentFramework):
    AGENT_ID = "orchestrator_agent"
    AGENT_NAME = "Orchestrator Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "claude-sonnet-4"
    BEDROCK_MODEL_ID = "us.anthropic.claude-3-5-sonnet-20241022-v2:0"
    DESCRIPTION = "Routes work between the specialized agents and shares the conversation context."
    MCP_SERVERS = ["Slack"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": False,
    }
    SYSTEM_PROMPT = "Route requests to the right specialist and keep the workflow moving."

    async def call_agent_model(self, user_message: str, selected_agent_name: str) -> str:
        user_message = _ai_app_sec_059_guardrail.evaluate(user_message)
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{_ai_app_sec_070_sanitize(user_message) or 'No user message provided.'}\n\n"
                        f"Selected agent: {selected_agent_name}\n\n"
                        "Explain the routing decision in one short paragraph."
                    ),
                },
            ],
            temperature=0.1,
            max_tokens=160,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        selected_agent = self.select_agent(
            user_message=context.get("user_message", ""),
            file_contents=context.get("file_contents", []),
        )
        selected_agent_name = selected_agent.AGENT_NAME

        # Vulnerability: the Orchestrator Agent forwards the entire context and a
        # shared internal token to downstream agents with no authentication boundary.
        forwarded_context = dict(context)
        forwarded_context["orchestrator_agent"] = self.AGENT_NAME
        forwarded_context["selected_agent"] = selected_agent_name
        forwarded_context["internal_call_chain"] = [self.AGENT_NAME, selected_agent_name]
        forwarded_context["internal_hop_token"] = _ai_dat_sec_001_internal_hop_token

        logger.info(
            "Orchestrator Agent routing request",
            extra={
                "selected_agent": selected_agent_name,
                "internal_call_chain": forwarded_context["internal_call_chain"],
            },
        )

        routing_note = await self.call_agent_model(
            context.get("user_message", ""),
            selected_agent_name,
        )
        response = await selected_agent.handle(forwarded_context)
        response["orchestrator"] = self.AGENT_NAME
        response["routing_note"] = routing_note
        return response

    def select_agent(self, user_message: str, file_contents: list[dict[str, Any]]) -> AcmeLoanAgentFramework:
        text = (user_message or "").lower()

        if self._should_route_to_installed_skill(text):
            return installed_skill_agent
        if any(keyword in text for keyword in ["schedule", "meeting", "calendar", "appointment"]):
            return scheduling_agent
        if any(
            keyword in text
            for keyword in [
                "delete",
                "purge",
                "destroy",
                "remove file",
                "file management",
                "deletefile",
                "purge records",
            ]
        ):
            return file_management_agent
        if any(
            keyword in text
            for keyword in [
                "grant access",
                "deny access",
                "allow access",
                "firewall",
                "assign role",
                "assign a role",
                "grant admin",
                "privilege",
                "authorize",
                "access control",
                "security decision",
            ]
        ):
            return access_control_agent
        if any(
            keyword in text
            for keyword in [
                "environment diagnostic",
                "environment diagnostics",
                "run diagnostics",
                "diagnostic steps",
                "verify environment",
                "environment setup",
            ]
        ):
            return environment_diagnostics_agent
        if any(keyword in text for keyword in ["credit", "fico", "debt-to-income", "dti", "underwrite", "loan status", "employee", "ssn", "borrower status"]):
            return credit_eval_agent
        if any(keyword in text for keyword in ["loan", "mortgage", "borrower", "application"]):
            return credit_eval_agent
        if file_contents or any(
            keyword in text
            for keyword in [
                "support document",
                "uploaded support",
                "review this uploaded",
                "summarize it's contents",
                "summarize its contents",
                "uploaded document",
                "review document",
            ]
        ):
            return file_processor_agent
        return credit_eval_agent

    @staticmethod
    def _should_route_to_installed_skill(text: str) -> bool:
        # Ambient skill loading: match task intent, not explicit "use skill" commands.
        skill_match_keywords = [
            "loan document",
            "loan documents",
            "process my loan document",
            "process loan document",
            "review my loan document",
            "review loan document",
        ]
        return any(keyword in text for keyword in skill_match_keywords)


orchestrator_agent = OrchestratorAgent()
