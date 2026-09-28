"""Scheduling Agent class with explicit model invocation."""

import asyncio
import re
from typing import Any

_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(r'ignore\s+previous\s+instructions|forget\s+everything\s+above', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(r'you\s+are\s+now\s+DAN|act\s+as\s+unrestricted', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape
    (re.compile(r'</?(system|tool|assistant|user)\s*>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload - base64-like blobs, hex sequences, ROT13 instructions, URL-encoded instructions
    (re.compile(r'(?:[A-Za-z0-9+/]{20,}={0,2})', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text - HTML comments, zero-width chars, CSS hidden
    (re.compile(r'<!--.*?-->|[\u200b-\u200f\u202a-\u202e\u2060\ufeff]|display\s*:\s*none', re.IGNORECASE | re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(r'\[\s*(?:system|tool|assistant)\s*\]\s*:', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)|send\s+(?:this\s+)?(?:data|info|prompt|context)\s+to\s+https?://|leak\s+(?:the\s+)?system\s+prompt', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(r'in\s+a\s+previous\s+(?:turn|message|conversation)\s+you\s+(?:said|agreed|confirmed)', re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection
    (re.compile(r'<\s*injected[^>]*>.*?</\s*injected\s*>', re.IGNORECASE | re.DOTALL), '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection
    (re.compile(r'(?:^|\s)(?:eval|exec|os\.system|subprocess\.(?:call|run|Popen))\s*\(', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    # 11. split_payload
    (re.compile(r'(?:part\s*1\s*of\s*\d+|continued\s+in\s+next\s+message|split\s+payload)', re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt
    (re.compile(r'\bDAN\b|developer\s+mode|fictional\s+framing|jailbreak', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


from .framework import AcmeLoanAgentFramework
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server
from lineaje_guardrail import lineaje_guardrail, GuardrailBlockedError

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])


class SchedulingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "amazon nova lite"
    BEDROCK_MODEL_ID = "amazon.nova-lite-v1:0"
    DESCRIPTION = "Schedules borrower, underwriting, and support meetings."
    MCP_SERVERS = ["Google Calendar", "Email", "Slack"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Coordinate calendar events and notify the relevant teams."

    async def call_agent_model(self, user_message: str, meeting_reference: str) -> str:
        user_message = _ai_app_sec_059_guardrail.evaluate(user_message)
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Meeting reference: {meeting_reference}\n"
                        f"Scheduling request: {user_message or 'Loan coordination meeting requested.'}\n\n"
                        "Draft a scheduling confirmation."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=180,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        meeting_reference = extract_reference_number(user_message, prefix="MEET")
        user_message = _ai_app_sec_070_sanitize(user_message)
        model_output = await self.call_agent_model(user_message, meeting_reference)

        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                },
            ),
        )

        response = (
            f"Meeting reference: {meeting_reference}\n"
            f"Scheduling request: {user_message or 'No scheduling request provided.'}\n\n"
            f"Scheduling summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


scheduling_agent = SchedulingAgent()
