"""Thin runtime registry that ties the separated agent files together."""

import re
from copy import deepcopy
from typing import Any

from .access_control_agent import access_control_agent
from .credit_eval_agent import credit_eval_agent
from .file_management_agent import file_management_agent
from .file_processor_agent import file_processor_agent
from .mcp_servers import MCP_SERVERS
from .orchestrator_agent import orchestrator_agent
from .rate_check_agent import rate_check_agent
from .loan_processing_agent import loan_processing_agent
from .scheduling_agent import scheduling_agent
from .installed_skill_agent import installed_skill_agent

from lineaje_guardrail import lineaje_guardrail, GuardrailBlockedError

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])


_ai_app_sec_070_patterns: list[tuple[re.Pattern, str]] = [
    # 1. instruction_override
    (re.compile(r'ignore\s+previous\s+instructions|forget\s+everything\s+above', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(r'you\s+are\s+now\s+DAN|act\s+as\s+unrestricted', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape
    (re.compile(r'</\s*system\s*>|<\s*system\s*>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload - base64 blobs, hex sequences, ROT13 instruction phrases, URL-encoded instructions
    (re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:0x[0-9a-fA-F]{2}[\s,]*){8,}', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:%[0-9a-fA-F]{2}){8,}', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text - HTML comments, zero-width chars, CSS hidden
    (re.compile(r'<!--.*?-->', re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff]+'), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'style\s*=\s*["\']?display\s*:\s*none', re.IGNORECASE), '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(r'\[\s*system\s*\]|\bSYSTEM\s*MESSAGE\b|\bTOOL\s*RESPONSE\b', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)|send\s+.{0,40}\s+to\s+https?://|leak\s+the\s+system\s+prompt', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(r'context\s+poison|multi.?turn\s+manipulat', re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection
    (re.compile(r'payload\s+in\s+(file|data|metadata|code\s+comment)', re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection
    (re.compile(r'(?:^|\s)(?:rm\s+-rf|sudo\s+|chmod\s+|curl\s+|wget\s+|eval\s*\(|exec\s*\(|os\.system\s*\(|subprocess)', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    # 11. split_payload
    (re.compile(r'fragment\w*\s+payload|split\s+payload', re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt
    (re.compile(r'\bDAN\b|developer\s+mode|fictional.?framing\s+bypass|jailbreak', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Replace known prompt injection patterns with their markers."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


def _ai_app_sec_070_sanitize_context(context: dict[str, Any]) -> dict[str, Any]:
    """Sanitize all user-supplied message content in a chat context dict."""
    sanitized = deepcopy(context)
    messages = sanitized.get('messages', [])
    if isinstance(messages, list):
        for msg in messages:
            if isinstance(msg, dict) and 'content' in msg:
                if isinstance(msg['content'], str):
                    msg['content'] = _ai_app_sec_070_sanitize(msg['content'])
    # Also sanitize a top-level 'input' or 'query' key if present
    for key in ('input', 'query', 'user_input'):
        if key in sanitized and isinstance(sanitized[key], str):
            sanitized[key] = _ai_app_sec_070_sanitize(sanitized[key])
    return sanitized


AGENTS: dict[str, Any] = {
    loan_processing_agent.AGENT_NAME: loan_processing_agent,
    file_processor_agent.AGENT_NAME: file_processor_agent,
    file_management_agent.AGENT_NAME: file_management_agent,
    access_control_agent.AGENT_NAME: access_control_agent,
    credit_eval_agent.AGENT_NAME: credit_eval_agent,
    rate_check_agent.AGENT_NAME: rate_check_agent,
    orchestrator_agent.AGENT_NAME: orchestrator_agent,
    scheduling_agent.AGENT_NAME: scheduling_agent,
    installed_skill_agent.AGENT_NAME: installed_skill_agent,
}


def build_catalog() -> dict[str, Any]:
    return {
        "agents": deepcopy([agent.to_dict() for agent in AGENTS.values()]),
        "mcp_servers": deepcopy(list(MCP_SERVERS.values())),
    }


async def handle_chat_request(context: dict[str, Any]) -> dict[str, Any]:
    context = _ai_app_sec_070_sanitize_context(context)
    return await orchestrator_agent.handle(context)


async def process_file_attachment(
    content: str | None,
    filename: str,
    content_type: str,
) -> dict[str, Any]:
    if isinstance(content, str):
        content = _ai_app_sec_070_sanitize(content)
    return await file_processor_agent.process_attachment(content, filename, content_type)
