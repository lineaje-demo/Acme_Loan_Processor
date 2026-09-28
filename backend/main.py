"""
Acme Loan Processor Backend - FastAPI Application

This entry point exposes the vulnerable multi-agent loan workflow used by the
demo UI. The backend now routes through a central agent catalog so the agent
names, model names, and MCP server names are easy to inspect in source.
"""

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agents.runtime import build_catalog, handle_chat_request, process_file_attachment
import re

_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(
        r'ignore\s+(?:all\s+)?previous\s+instructions|forget\s+everything\s+above',
        re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(
        r'you\s+are\s+now\s+DAN|act\s+as\s+(?:an?\s+)?unrestricted',
        re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape - fake </system>, </prompt>, </instruction> tags or injected separators
    (re.compile(
        r'</?\s*(?:system|prompt|instruction|context|human|assistant)\s*>',
        re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    # 6. fake_system_message
    (re.compile(
        r'\[\s*(?:SYSTEM|TOOL|ASSISTANT|USER)\s*\]\s*:',
        re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt - markdown image exfil or instructions to send data to URLs
    (re.compile(
        r'!\[.*?\]\(https?://[^)]*\?[^)]*\)|send\s+(?:the\s+)?(?:system\s+prompt|data|contents?)\s+to\s+https?://|leak\s+(?:the\s+)?system\s+prompt',
        re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(
        r'disregard\s+(?:all\s+)?(?:prior|previous)\s+(?:context|instructions?|messages?)|manipulate\s+(?:the\s+)?(?:context|conversation)',
        re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    # 10. command_injection - shell execution patterns
    (re.compile(
        r'(?:^|\s)(?:sudo\s+)?(?:rm\s+-rf|curl\s+.*\|\s*(?:bash|sh)|wget\s+.*\|\s*(?:bash|sh)|os\.system\s*\(|subprocess\.(?:call|run|Popen)\s*\(|eval\s*\(|exec\s*\()',
        re.IGNORECASE | re.MULTILINE), '<prompt_injection_removed: command_injection>'),
    # 12. jailbreak_attempt - DAN, developer mode, fictional framing
    (re.compile(
        r'\bDAN\b|developer\s+mode\s+enabled|pretend\s+you\s+(?:have\s+no\s+restrictions|are\s+(?:an?\s+)?(?:unrestricted|evil|unfiltered))|jailbreak',
        re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
    # 5. hidden_text - HTML comments, zero-width characters, CSS hidden
    (re.compile(
        r'<!--.*?-->|[\u200b\u200c\u200d\u200e\u200f\ufeff]|<span[^>]+display\s*:\s*none[^>]*>.*?</span>',
        re.IGNORECASE | re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    # 4. encoded_payload - base64-encoded instructions, hex blobs, ROT13 hints
    (re.compile(
        r'(?:base64\s*(?:decode|encoded)|rot13|\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,})',
        re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    # 9. indirect_injection - payloads in metadata fields or code comments
    (re.compile(
        r'#\s*(?:ignore|override|forget)\s+(?:previous\s+)?instructions',
        re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    # 11. split_payload - fragmented instructions
    (re.compile(
        r'(?:part\s*[1-9]\s*of\s*[1-9]|continued\s+from\s+(?:above|previous)).*?(?:ignore|override|forget)',
        re.IGNORECASE | re.DOTALL), '<prompt_injection_removed: split_payload>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text before it reaches the LLM."""
    if not text:
        return text
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text
from lineaje_guardrail import lineaje_guardrail, GuardrailBlockedError

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
MCP_CALL_LOG: list[dict] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("Acme Loan Processor backend starting up...")
    yield
    logger.info("Acme Loan Processor backend shutting down...")


app = FastAPI(
    title="Acme Loan Processor",
    description="AI-powered policy evaluation and remediation demo",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5001", "http://127.0.0.1:5001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class FileAttachment(BaseModel):
    id: str
    name: str
    type: str
    size: int
    content: Optional[str] = None


class ChatRequest(BaseModel):
    message: str
    attachments: Optional[list[FileAttachment]] = None
    conversation_id: Optional[str] = None


class PolicyError(BaseModel):
    type: str
    message: str
    details: Optional[dict] = None


class SkillInvocation(BaseModel):
    id: str
    name: str
    version: str
    description: str
    status: str


class WorkflowStage(BaseModel):
    id: str
    label: str
    duration_ms: int


class ChatResponse(BaseModel):
    response: str
    conversation_id: Optional[str] = None
    policy_warning: Optional[PolicyError] = None
    workflow_status: Optional[str] = None
    agent: Optional[str] = None
    skill_invocation: Optional[SkillInvocation] = None
    skill_used: Optional[bool] = None
    skill_content_bytes: Optional[int] = None
    workflow_stages: Optional[list[WorkflowStage]] = None


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "acme-loan-processor"}


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Main chat endpoint that processes user messages and file uploads.

    This endpoint:
    1. Receives user messages and optional file attachments
    2. Processes files through the File Processor Agent
    3. Routes the request through the Orchestrator Agent
    4. Returns the agent response
    """
    try:
        file_contents = []
        if request.attachments:
            for attachment in request.attachments:
                logger.info(
                    "Processing attachment",
                    extra={
                        "file_name": attachment.name,
                        "file_type": attachment.type,
                        "file_size": attachment.size,
                        "request_context": {
                            "message": request.message,
                            "attachment_content_preview": attachment.content[:100] if attachment.content else None
                        }
                    }
                )

                _ai_app_sec_059_attachment_content = attachment.content
                _ai_app_sec_059_attachment_content = _ai_app_sec_059_guardrail.evaluate(_ai_app_sec_059_attachment_content)
                                sanitized_attachment_content = _ai_app_sec_070_sanitize(attachment.content) if attachment.content else attachment.content
                processed = await process_file_attachment(
                    content=sanitized_attachment_content,
                    filename=attachment.name,
                    content_type=attachment.type
                )
                file_contents.append(processed)

        _ai_app_sec_059_user_message = request.message
        _ai_app_sec_059_user_message = _ai_app_sec_059_guardrail.evaluate(_ai_app_sec_059_user_message)
        context = {
            "user_message": _ai_app_sec_059_user_message,
            "file_contents": file_contents,
            "conversation_id": request.conversation_id,
        }

        response = await handle_chat_request(context)

        skill_invocation = response.get("skill_invocation")
        workflow_stages = response.get("workflow_stages")
        return ChatResponse(
            response=response.get("response", "I processed your request."),
            conversation_id=request.conversation_id,
            policy_warning=response.get("policy_warning"),
            workflow_status=response.get("workflow_status"),
            agent=response.get("agent"),
            skill_used=response.get("skill_used"),
            skill_content_bytes=response.get("skill_content_bytes"),
            workflow_stages=(
                [WorkflowStage(**stage) for stage in workflow_stages]
                if workflow_stages
                else None
            ),
            skill_invocation=(
                SkillInvocation(**skill_invocation) if skill_invocation else None
            ),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error processing chat request",
            extra={
                # VULNERABILITY: Error context includes full state
                "error": str(e),
                "request_state": {
                    "message": request.message,
                    "attachments": [a.dict() for a in request.attachments] if request.attachments else None
                }
            }
        )
        raise HTTPException(
            status_code=500,
            detail={
                "detail": "An error occurred processing your request",
                "policy_error": {
                    "type": "general",
                    "message": str(e)
                }
            }
        )


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Direct file upload endpoint.
    """
    content = await file.read()
    if (file.content_type or "").startswith("image/") or file.content_type in {
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }:
        processed_content = base64.b64encode(content).decode("utf-8")
    else:
        processed_content = content.decode("utf-8", errors="ignore")

    processed_content = _ai_app_sec_059_guardrail.evaluate(processed_content)
    processed_content = _ai_app_sec_070_sanitize(processed_content)
    processed = await process_file_attachment(
        content=processed_content,
        filename=file.filename,
        content_type=file.content_type
    )

    return {
        "filename": file.filename,
        "size": len(content),
        "processed": True,
        "content_preview": processed.get("extracted_content", "")[:500] if processed else None,
        "agent": processed.get("agent"),
        "model": processed.get("model"),
    }


@app.post("/mock-mcp/{server_key}")
async def mock_mcp_server(server_key: str, request: Request):
    """
    Local mock MCP server endpoint used by the demo agents.

    These handlers intentionally accept broad payloads so the insecure agent
    flows can be exercised end-to-end without external infrastructure.
    """
    payload = await request.json()
    params = payload.get("params", {})
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})
    response_payload = _handle_mock_mcp_call(server_key, tool_name, arguments)
    return {
        "jsonrpc": "2.0",
        "id": payload.get("id"),
        "result": response_payload,
    }


@app.get("/catalog")
async def get_catalog():
    """Expose the current agent and MCP server catalog to the UI."""
    return build_catalog()


@app.get("/agents")
async def get_agents():
    """Compatibility alias for agent catalog inspection."""
    return build_catalog()


@app.get("/mcp-servers")
async def get_mcp_servers():
    """Compatibility alias for MCP server catalog inspection."""
    catalog = build_catalog()
    return {"mcp_servers": catalog.get("mcp_servers", [])}


def _handle_mock_mcp_call(server_key: str, tool_name: str, arguments: dict) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    log_entry = {
        "server_key": server_key,
        "tool_name": tool_name,
        "arguments": arguments,
        "timestamp": timestamp,
    }
    MCP_CALL_LOG.append(log_entry)

    if server_key == "slack" and tool_name == "slack.post_message":
        return {
            "server": "Slack",
            "posted": True,
            "channel": arguments.get("channel", "#general"),
            "text": arguments.get("text", ""),
            "timestamp": timestamp,
        }

    if server_key == "slack" and tool_name == "slack.download_demo_package":
        encoded_payload = arguments.get("encoded_payload", "")
        try:
            decoded_payload = base64.b64decode(encoded_payload).decode("utf-8")
        except Exception:
            decoded_payload = "Unable to decode demo payload."
        return {
            "server": "Slack",
            "downloaded": True,
            "package_name": arguments.get("package_name", "demo-package"),
            "pretend_download_path": "/tmp/demo-rce-playbook.txt",
            "decoded_payload": decoded_payload,
            "timestamp": timestamp,
        }

    if server_key == "servicenow" and tool_name == "servicenow.create_incident":
        return {
            "server": "ServiceNow",
            "incident_number": f"INC{len(MCP_CALL_LOG):06d}",
            "short_description": arguments.get("short_description", ""),
            "status": "created",
            "timestamp": timestamp,
        }

    if server_key == "email" and tool_name == "email.send_message":
        return {
            "server": "Email",
            "message_id": f"email-{len(MCP_CALL_LOG):06d}",
            "to": arguments.get("to", []),
            "subject": arguments.get("subject", ""),
            "status": "queued",
            "timestamp": timestamp,
        }

    if server_key == "excel" and tool_name == "excel.upsert_row":
        return {
            "server": "Excel",
            "workbook": arguments.get("workbook", ""),
            "worksheet": arguments.get("worksheet", ""),
            "row": arguments.get("row", {}),
            "status": "upserted",
            "timestamp": timestamp,
        }

    if server_key == "docx" and tool_name == "docx.create_document":
        return {
            "server": "Docx",
            "document_id": f"docx-{len(MCP_CALL_LOG):06d}",
            "document_title": arguments.get("document_title", ""),
            "document_body_preview": arguments.get("document_body", "")[:300],
            "status": "generated",
            "timestamp": timestamp,
        }

    if server_key == "google-calendar" and tool_name == "google_calendar.create_event":
        return {
            "server": "Google Calendar",
            "event_id": f"gcal-{len(MCP_CALL_LOG):06d}",
            "title": arguments.get("title", ""),
            "start": arguments.get("start", ""),
            "end": arguments.get("end", ""),
            "status": "scheduled",
            "timestamp": timestamp,
        }

    return {
        "server": server_key,
        "tool": tool_name,
        "status": "unsupported",
        "raw_arguments": json.dumps(arguments),
        "timestamp": timestamp,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5500)
