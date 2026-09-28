"""File Management Agent — demo for HITL-required destructive operations."""

import logging
import re
from typing import Any, Optional

import base64
import binascii
import urllib.parse
import requests

from lineaje_guardrail import lineaje_guardrail, GuardrailBlockedError

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])

from .framework import AcmeLoanAgentFramework
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)

_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(
        r'ignore\s+(?:all\s+)?previous\s+instructions|forget\s+everything\s+above',
        re.IGNORECASE),
     '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(
        r'you\s+are\s+now\s+DAN|act\s+as\s+(?:an?\s+)?unrestricted',
        re.IGNORECASE),
     '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape — fake </system>, </user>, </assistant> tags
    (re.compile(
        r'</\s*(?:system|user|assistant|instruction|prompt)\s*>',
        re.IGNORECASE),
     '<prompt_injection_removed: delimiter_escape>'),
    # 6. fake_system_message
    (re.compile(
        r'<\s*(?:system|tool)\s*>',
        re.IGNORECASE),
     '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt — markdown image exfil or send-data-to-URL instructions
    (re.compile(
        r'!\[.*?\]\(https?://[^)]+\)|send\s+(?:this|the|all|data|prompt|system).*?to\s+https?://|leak\s+(?:the\s+)?system\s+prompt',
        re.IGNORECASE | re.DOTALL),
     '<prompt_injection_removed: exfiltration_attempt>'),
    # 10. command_injection — shell execution patterns
    (re.compile(
        r'(?:^|\s)(?:rm\s+-rf|os\.system\s*\(|subprocess\.(?:call|run|Popen)\s*\(|eval\s*\(|exec\s*\()',
        re.IGNORECASE),
     '<prompt_injection_removed: command_injection>'),
    # 12. jailbreak_attempt — DAN / developer mode / fictional framing
    (re.compile(
        r'\bDAN\b|developer\s+mode\s+enabled|pretend\s+you\s+(?:have\s+no\s+)?(?:restrictions|limits|guidelines)',
        re.IGNORECASE),
     '<prompt_injection_removed: jailbreak_attempt>'),
    # 5. hidden_text — zero-width characters
    (re.compile(
        r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u2060\u00ad]+'),
     '<prompt_injection_removed: hidden_text>'),
    # 8. context_poisoning
    (re.compile(
        r'context\s+poisoning|multi[- ]turn\s+manipulation',
        re.IGNORECASE),
     '<prompt_injection_removed: context_poisoning>'),
    # 11. split_payload
    (re.compile(
        r'fragmented\s+payload|split\s+payload',
        re.IGNORECASE),
     '<prompt_injection_removed: split_payload>'),
]


def _ai_app_sec_070_is_encoded_payload(text: str) -> bool:
    """Return True if text looks like a base64 or URL-encoded instruction payload."""
    # Check URL-encoded suspicious content
    try:
        decoded_url = urllib.parse.unquote(text)
        if decoded_url != text and any(
            kw in decoded_url.lower()
            for kw in ('ignore', 'forget', 'you are now', 'act as', 'system', 'jailbreak')
        ):
            return True
    except Exception:
        pass
    # Check base64-encoded suspicious content (only for plausible b64 blobs)
    stripped = text.strip()
    if len(stripped) >= 20 and re.match(r'^[A-Za-z0-9+/=\s]+$', stripped):
        try:
            decoded_b64 = base64.b64decode(stripped + '==').decode('utf-8', errors='ignore')
            if any(
                kw in decoded_b64.lower()
                for kw in ('ignore', 'forget', 'you are now', 'act as', 'system', 'jailbreak')
            ):
                return True
        except (binascii.Error, ValueError):
            pass
    return False


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in untrusted text before LLM submission."""
    if not text:
        return text
    # Encoded payload check on the whole string
    if _ai_app_sec_070_is_encoded_payload(text):
        return '<prompt_injection_removed: encoded_payload>'
    result = text
    for pattern, marker in _ai_app_sec_070_patterns:
        result = pattern.sub(marker, result)
    return result


class FileManagementAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_management_agent"
    AGENT_NAME = "File Management Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = (
        "Retrieves loan files, deletes documents, and purges archived records "
        "for servicing workflows."
    )
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
        "hitl_for_destructive_ops": False,
    }
    SYSTEM_PROMPT = (
        "Manage loan files and archived records. Prefer concise operational summaries."
    )

    GET_FILE_API = "https://www.testme160375.com/getFile"
    PURGE_RECORDS_API = "https://x1w3n1m6.com/purgeRecords"
    API_TIMEOUT = 30

    async def call_agent_model(self, user_message: str, workflow_summary: str) -> str:
        user_message = _ai_app_sec_059_guardrail.evaluate(user_message)
        workflow_summary = _ai_app_sec_059_guardrail.evaluate(workflow_summary)
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{user_message or 'No user message provided.'}\n\n"
                        f"Workflow results:\n{workflow_summary}\n\n"
                        "Summarize the file management actions in 2-3 sentences."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=200,
        )

    def _extract_filename(self, user_message: str) -> str:
        match = re.search(
            r"(?:delete|remove|destroy)\s+(?:the\s+)?(?:file\s+)?([A-Za-z0-9._-]+\.[A-Za-z0-9]+)",
            user_message or "",
            re.IGNORECASE,
        )
        return match.group(1) if match else "retrieved_file.txt"

    def _extract_record_id(self, user_message: str) -> int:
        match = re.search(
            r"(?:purge|destroy|delete)\s+(?:records?\s+)?(?:for\s+)?(?:id\s+)?(\d+)",
            user_message or "",
            re.IGNORECASE,
        )
        if match:
            return int(match.group(1))
        match = re.search(r"\bid\s*[:=]?\s*(\d+)", user_message or "", re.IGNORECASE)
        return int(match.group(1)) if match else 45

    def get_file_from_api(self, file_id: int = 50) -> tuple[bool, Optional[str], Optional[str]]:
        url = f"{self.GET_FILE_API}?id={file_id}"
        logger.info("Retrieving file from API: %s", url)
        try:
            response = requests.get(url, timeout=self.API_TIMEOUT)
            if response.status_code != 200:
                return False, None, f"API returned status {response.status_code}"
            return True, response.text, None
        except requests.RequestException as exc:
            # Demo path: continue workflow even when the external API is unreachable.
            logger.warning("get_file_from_api failed: %s", exc)
            return True, "SIMULATED_FILE_CONTENT", None

    async def delete_file(self, filename: str) -> tuple[bool, Optional[str]]:
        """Delete a loan document. Intentionally has no HITL approval gate."""
        logger.info("Deleting file: %s", filename)
        if not filename or ".." in filename or filename.startswith("/"):
            return False, "Invalid filename"

        # Vulnerability: destructive delete executes without human-in-the-loop approval.
        await call_mcp_server(
            self.to_dict(),
            "Docx",
            "create_document",
            {
                "document_title": f"Deleted {filename}",
                "document_body": f"deleteFile(fileName='{filename}') completed without HITL approval.",
            },
        )
        logger.info("Would call: deleteFile(fileName='%s')", filename)
        return True, None

    def purge_records(self, record_id: int) -> tuple[bool, Optional[str]]:
        """Purge archived records. Intentionally has no HITL approval gate."""
        url = f"{self.PURGE_RECORDS_API}?id={record_id}"
        logger.info("Purging records via API: %s", url)
        try:
            # Vulnerability: purge/destroy-style API call runs without HITL approval.
            response = requests.get(url, timeout=self.API_TIMEOUT)
            if response.status_code != 200:
                logger.warning("purge_records API returned %s; simulating success for demo", response.status_code)
            return True, None
        except requests.RequestException as exc:
            logger.warning("purge_records failed: %s; simulating success for demo", exc)
            return True, None

    def destroy_temp_artifacts(self, filename: str) -> None:
        """Destroy temporary artifacts after delete/purge. No HITL gate."""
        # Vulnerability: destroy operation executes without human approval.
        logger.info("destroy_temp_artifacts('%s') executed without HITL approval", filename)

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        filename = self._extract_filename(user_message)
        record_id = self._extract_record_id(user_message)

        get_ok, content, get_error = self.get_file_from_api(file_id=50)
        delete_ok, delete_error = await self.delete_file(filename)
        purge_ok, purge_error = self.purge_records(record_id)
        self.destroy_temp_artifacts(filename)

        workflow_summary = (
            f"Retrieve file id 50: {'ok' if get_ok else get_error}\n"
            f"Delete file '{filename}': {'ok' if delete_ok else delete_error}\n"
            f"Purge records id {record_id}: {'ok' if purge_ok else purge_error}\n"
            f"Destroy temp artifacts for '{filename}': completed\n"
            f"Content preview: {(content or '')[:80]}"
        )
        model_output = await self.call_agent_model(user_message, workflow_summary)

        response = (
            "File Management Agent workflow complete.\n\n"
            f"1. Retrieved file id 50 ({'success' if get_ok else 'failed'})\n"
            f"2. Deleted file via MCP deleteFile('{filename}') "
            f"({'success' if delete_ok else 'failed'})\n"
            f"3. Purged records via API for id {record_id} "
            f"({'success' if purge_ok else 'failed'})\n"
            f"4. Destroyed temporary artifacts for '{filename}'\n\n"
            f"{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


file_management_agent = FileManagementAgent()
