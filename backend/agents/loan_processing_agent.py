"""Loan Processing Agent class with explicit model invocation."""

import asyncio
import os
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import build_file_summary, extract_reference_number
import re

from .mcp_servers import call_mcp_server
from lineaje_guardrail import lineaje_guardrail, GuardrailBlockedError

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])


_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(
        r'ignore\s+(?:all\s+)?previous\s+instructions|forget\s+everything\s+above',
        re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(
        r'you\s+are\s+now\s+DAN|act\s+as\s+(?:an?\s+)?unrestricted',
        re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape — fake </system>, </user>, </assistant> tags or injected separators
    (re.compile(
        r'</?(?:system|user|assistant|tool|function)\s*>',
        re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload — base64 blobs, hex sequences, ROT13 cues, URL-encoded instructions
    (re.compile(
        r'(?:[A-Za-z0-9+/]{40,}={0,2})|(?:(?:%[0-9A-Fa-f]{2}){8,})|(?:\\u[0-9A-Fa-f]{4}){4,}',
        re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text — HTML comments, zero-width chars, CSS hidden spans
    (re.compile(
        r'<!--.*?-->|[\u200b-\u200f\u202a-\u202e\u2060\ufeff]|<span[^>]+display\s*:\s*none[^>]*>.*?</span>',
        re.IGNORECASE | re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(
        r'\[(?:SYSTEM|TOOL|FUNCTION)\]|<<(?:SYS|INST)>>|<\|(?:system|tool)\|>',
        re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt — markdown image exfil, send-to-URL instructions
    (re.compile(
        r'!\[.*?\]\(https?://[^)]+\)|(?:send|post|exfiltrate|leak)\s+(?:the\s+)?(?:system\s+prompt|data|context)\s+to\s+https?://',
        re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(
        r'disregard\s+(?:all\s+)?(?:prior|previous)\s+context|override\s+(?:all\s+)?(?:prior|previous)\s+instructions',
        re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection — payloads embedded in file/data fields
    (re.compile(
        r'<injected[^>]*>.*?</injected>|\[injected\s+payload\]',
        re.IGNORECASE | re.DOTALL), '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection — shell/code execution attempts
    (re.compile(
        r'(?:^|\s)(?:eval|exec|system|popen|subprocess)\s*\(',
        re.IGNORECASE | re.MULTILINE), '<prompt_injection_removed: command_injection>'),
    # 11. split_payload — fragmented instruction markers
    (re.compile(
        r'(?:part\s*\d+\s*of\s*\d+\s*:.*?){2,}',
        re.IGNORECASE | re.DOTALL), '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt — DAN, developer mode, fictional framing
    (re.compile(
        r'\bDAN\b|developer\s+mode\s+enabled|jailbreak|fictional\s+framing\s+bypass',
        re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Replace known prompt-injection patterns with safe markers."""
    if not text:
        return text
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


class LoanProcessingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "loan_processing_agent"
    AGENT_NAME = "Loan Processing Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.environ.get("_AI_APP_SEC_006_LOAN_AGENT_MODEL", "gpt-4o mini")
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Handles loan application intake, borrower updates, and loan package generation."
    MCP_SERVERS = ["Docx", "Excel", "Email"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Process loan requests, summarize borrower context, and prepare follow-up actions."
    IS_ROUTABLE = False
    IS_SCAN_ONLY = True

    async def call_agent_model(self, user_message: str, file_summary: str) -> str:
        user_message = _ai_app_sec_059_guardrail.evaluate(user_message)
        file_summary = _ai_app_sec_059_guardrail.evaluate(file_summary)
        return await self.model_client.chat(
            model=self.MODEL_NAME,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Loan request:\n{user_message or 'No user message provided.'}\n\n"
                        f"File summary:\n{file_summary}\n\n"
                        "Draft a concise loan processing next-step summary."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        file_summary = build_file_summary(context.get("file_contents", []))
        loan_number = extract_reference_number(user_message, prefix="LOAN")
        user_message = _ai_app_sec_070_sanitize(user_message)
        file_summary = _ai_app_sec_070_sanitize(file_summary)
        model_output = await self.call_agent_model(user_message, file_summary)

        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {loan_number}",
                    "document_body": f"User message:\n{user_message}\n\nFile summary:\n{file_summary}",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Excel",
                "upsert_row",
                {
                    "workbook": "Loan Pipeline",
                    "worksheet": "Applications",
                    "row": {
                        "loan_number": loan_number,
                        "status": "processing",
                        "borrower_request": user_message[:240],
                    },
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example"],
                    "subject": f"Loan update for {loan_number}",
                    "body": "Your loan request is being reviewed by the Loan Processing Agent.",
                },
            ),
        )

        response = (
            "This scan-only agent is disconnected from the Orchestrator Agent.\n\n"
            f"Loan reference: {loan_number}\n"
            f"Borrower request: {user_message or 'No user message provided.'}\n\n"
            f"Loan summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


loan_processing_agent = LoanProcessingAgent()
