"""File Processor Agent class with explicit model invocation."""

import base64
import io
import json
import logging
import re
from typing import Any, Optional

try:
    from docx import Document
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    Document = None

from file_parsers.html_parser import HTMLParser
from file_parsers.image_parser import ImageParser
from file_parsers.pdf_parser import PDFParser

from lineaje_guardrail import lineaje_guardrail, GuardrailBlockedError
from .framework import AcmeLoanAgentFramework
from .helpers import build_file_summary
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)

# Zero-tolerance PII patterns for DAT-SEC-023
_ai_dat_sec_023_patterns = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED-SSN]'),
    # Taxpayer Identification Number (EIN style)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED-TIN]'),
    # Credit Card Number (Visa, MC, Amex, Discover)
    (re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b'), '[REDACTED-CC]'),
    # Passport Number (generic: letter(s) + digits)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED-PASSPORT]'),
    # Driver License Number (common US formats)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[REDACTED-DL]'),
    # Financial Account Number (8-17 digits)
    (re.compile(r'\b\d{8,17}\b'), '[REDACTED-ACCOUNT]'),
    # IP Address (IPv4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED-IP]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED-MAC]'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED-VIN]'),
    # Email
    (re.compile(r'\b[\w.+\-]+@[\w.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED-EMAIL]'),
    # Personal Phone Number
    (re.compile(r'\b(?:\+?1[\-.\s]?)?(?:\(?\d{3}\)?[\-.\s]?){2}\d{4}\b'), '[REDACTED-PHONE]'),
    # Year of Birth (standalone 4-digit year 1900-2099 near birth keywords)
    (re.compile(r'(?i)(?:born|birth|dob|date of birth)[^\n]{0,30}\b(19|20)\d{2}\b'), '[REDACTED-YOB]'),
    # Home Address (street address pattern)
    (re.compile(r'\b\d{1,5}\s+[A-Za-z0-9 .]{3,40}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[REDACTED-ADDRESS]'),
    # Mother's Maiden Name keyword
    (re.compile(r"(?i)mother'?s?\s+maiden\s+name[^\n]{0,60}"), '[REDACTED-MAIDEN-NAME]'),
    # Birthplace keyword
    (re.compile(r'(?i)(?:birthplace|place of birth)[^\n]{0,60}'), '[REDACTED-BIRTHPLACE]'),
    # Employee ID
    (re.compile(r'(?i)(?:employee\s*id|emp\s*id)[^\n]{0,30}'), '[REDACTED-EMPLOYEE-ID]'),
    # School ID
    (re.compile(r'(?i)(?:school\s*id|student\s*id)[^\n]{0,30}'), '[REDACTED-SCHOOL-ID]'),
    # Medical Records keyword
    (re.compile(r'(?i)(?:medical\s*record|diagnosis|prescription|patient\s*id)[^\n]{0,60}'), '[REDACTED-MEDICAL]'),
    # Ethnicity keyword
    (re.compile(r'(?i)(?:ethnicity|ethnic\s*origin|race)[^\n]{0,40}'), '[REDACTED-ETHNICITY]'),
    # Sexual Orientation keyword
    (re.compile(r'(?i)(?:sexual\s*orientation|gender\s*identity)[^\n]{0,40}'), '[REDACTED-SEXUAL-ORIENTATION]'),
    # Fingerprints keyword
    (re.compile(r'(?i)fingerprint[^\n]{0,40}'), '[REDACTED-FINGERPRINT]'),
    # Retina/Iris Scan keyword
    (re.compile(r'(?i)(?:retina|iris)\s*scan[^\n]{0,40}'), '[REDACTED-BIOMETRIC]'),
    # Voice signature keyword
    (re.compile(r'(?i)voice\s*signature[^\n]{0,40}'), '[REDACTED-VOICE-SIG]'),
    # Facial image keyword
    (re.compile(r'(?i)facial\s*(?:image|recognition|scan)[^\n]{0,40}'), '[REDACTED-FACIAL]'),
    # Fine Location (GPS coordinates)
    (re.compile(r'\b[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?)\s*,\s*[-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|\d{1,2})(?:\.\d+)?)\b'), '[REDACTED-LOCATION]'),
]


def _ai_dat_sec_023_redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from the given text."""
    if not text:
        return text
    for pattern, replacement in _ai_dat_sec_023_patterns:
        text = pattern.sub(replacement, text)
    return text

_ai_dat_sec_012_PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[SSN REDACTED]'),
    # Taxpayer Identification Number (EIN style)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[TIN REDACTED]'),
    # Credit Card Number
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[CC REDACTED]'),
    # Email
    (re.compile(r'\b[\w.+\-]+@[\w.\-]+\.[A-Za-z]{2,}\b'), '[EMAIL REDACTED]'),
    # Personal Phone Number
    (re.compile(r'\b(?:\+?1[\-.\s]?)?(?:\(?\d{3}\)?[\-.\s]?){2}\d{4}\b'), '[PHONE REDACTED]'),
    # IP Address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[IP REDACTED]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[MAC REDACTED]'),
    # Passport Number (generic alphanumeric 6-9 chars preceded by keyword)
    (re.compile(r'(?i)(?:passport\s*(?:no\.?|number|#)?\s*:?\s*)([A-Z0-9]{6,9})\b'), '[PASSPORT REDACTED]'),
    # Driver License Number (preceded by keyword)
    (re.compile(r"(?i)(?:driver'?s?\s*licen[sc]e\s*(?:no\.?|number|#)?\s*:?\s*)([A-Z0-9\-]{5,15})\b"), '[DL REDACTED]'),
    # Financial Account / Account Number (preceded by keyword)
    (re.compile(r'(?i)(?:account\s*(?:no\.?|number|#)?\s*:?\s*)(\d{6,20})\b'), '[ACCOUNT REDACTED]'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[VIN REDACTED]'),
    # Year of Birth (preceded by keyword)
    (re.compile(r'(?i)(?:year\s+of\s+birth|birth\s*year)\s*:?\s*(\d{4})\b'), '[YOB REDACTED]'),
    # Date of Birth (full date)
    (re.compile(r'(?i)(?:dob|date\s+of\s+birth)\s*:?\s*(\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4})'), '[DOB REDACTED]'),
    # Home Address (street address pattern)
    (re.compile(r'\b\d{1,5}\s+[A-Za-z0-9\s]{3,40}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\.?\b', re.IGNORECASE), '[ADDRESS REDACTED]'),
    # Employee ID / School ID (preceded by keyword)
    (re.compile(r'(?i)(?:employee\s*id|school\s*id|emp\s*id)\s*:?\s*([A-Z0-9\-]{3,20})\b'), '[ID REDACTED]'),
]


def _ai_dat_sec_012_mask_pii(text: str) -> str:
    """Mask zero-tolerance PII categories before displaying text on the UI."""
    for pattern, replacement in _ai_dat_sec_012_PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text

_ai_app_sec_070_patterns = [
    (
        re.compile(
            r"(?i)(ignore\s+(?:all\s+)?previous\s+instructions|forget\s+everything\s+above)",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: instruction_override>",
    ),
    (
        re.compile(
            r"(?i)(you\s+are\s+now\s+DAN|act\s+as\s+(?:an?\s+)?unrestricted)",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: role_hijack>",
    ),
    (
        re.compile(
            r"(?i)</?\s*(?:system|tool|assistant|user)\s*>",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: delimiter_escape>",
    ),
    (
        re.compile(
            r"(?i)(?:(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)",
        ),
        "<prompt_injection_removed: encoded_payload>",
    ),
    (
        re.compile(
            r"(?i)(?:&#x200[0-9A-Fa-f];|&#8203;|\u200b|\u200c|\u200d|\ufeff|<!--.*?-->)",
            re.DOTALL,
        ),
        "<prompt_injection_removed: hidden_text>",
    ),
    (
        re.compile(
            r"(?i)(\[system\]|\[tool\]|<system>|system\s*message\s*:|tool\s*response\s*:)",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: fake_system_message>",
    ),
    (
        re.compile(
            r"(?i)(send\s+(?:this|the|all|data|info|contents?)\s+to\s+https?://|leak\s+(?:the\s+)?system\s+prompt|!\[.*?\]\(https?://[^)]+\))",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: exfiltration_attempt>",
    ),
    (
        re.compile(
            r"(?i)(in\s+(?:a\s+)?previous\s+(?:turn|message|conversation)|remember\s+(?:that\s+)?(?:you|we)\s+(?:agreed|said|decided))",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: context_poisoning>",
    ),
    (
        re.compile(
            r"(?i)(payload\s*:|injected\s+(?:instruction|command)|<!--\s*inject)",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: indirect_injection>",
    ),
    (
        re.compile(
            r"(?i)(`{1,3}\s*(?:bash|sh|python|cmd|powershell)[^`]*`{1,3}|\$\((?:[^)]+)\)|os\.system\s*\(|subprocess\.(?:call|run|Popen)\s*\(|eval\s*\(|exec\s*\()",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: command_injection>",
    ),
    (
        re.compile(
            r"(?i)(part\s*[1-9]\s+of\s*[1-9]|continued\s+in\s+(?:next|part)|split\s+(?:across|over)\s+(?:multiple|several)\s+(?:messages|parts))",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: split_payload>",
    ),
    (
        re.compile(
            r"(?i)(DAN\s+mode|developer\s+mode\s+enabled|jailbreak|fictional\s+(?:framing|scenario)\s+to\s+bypass|pretend\s+(?:you\s+have\s+no\s+restrictions|there\s+are\s+no\s+rules))",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: jailbreak_attempt>",
    ),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Replace known prompt-injection patterns in file-derived text with safe markers."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])


class FileProcessorAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_processor_agent"
    AGENT_NAME = "File Processor Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = "Extracts text from uploaded files and returns the raw contents to downstream agents."
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": False,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Extract document text and hand the raw contents to the next agent."

    def __init__(self):
        super().__init__()
        self.pdf_parser = PDFParser()
        self.html_parser = HTMLParser()
        self.image_parser = ImageParser()

    async def call_agent_model(self, file_summary: str) -> str:
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Extracted file contents:\n{file_summary}\n\n"
                        "Give a short processing note without masking any content."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=220,
        )

    async def process_attachment(
        self,
        content: Optional[str],
        filename: str,
        content_type: str,
    ) -> dict[str, Any]:
        """
        Extracted text is redacted for PII before being returned.
        """
        file_type = self.get_file_type(content_type, filename)
        if not content:
            extracted_content = f"Empty file: {filename}"
        elif file_type == "pdf":
            extracted_content = await self._process_pdf(content)
        elif file_type == "html":
            extracted_content = await self._process_html(content)
        elif file_type == "image":
            extracted_content = await self._process_image(content, content_type)
        elif file_type == "json":
            extracted_content = await self._process_json(content)
        elif file_type == "word":
            extracted_content = await self._process_word(content)
        else:
            extracted_content = content

        return {
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "filename": filename,
            "content_type": content_type,
            "file_type": file_type,
            "extracted_content": _ai_dat_sec_023_redact_pii(extracted_content),
            "guardrails": dict(self.GUARDRAILS),
        }

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        file_contents = context.get("file_contents", [])
        file_summary = build_file_summary(file_contents, include_raw_text=True)
        pii_exposure_summary = self.build_pii_exposure_summary(file_contents)
        file_summary = _ai_app_sec_059_guardrail.evaluate(file_summary)
        file_summary = _ai_app_sec_070_sanitize(file_summary)
        model_output = await self.call_agent_model(file_summary)
        mcp_activity = [
            await call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": "Extracted File Contents",
                    "document_body": file_summary,
                },
            )
        ] if file_contents else []

        if pii_exposure_summary:
            response = (
                "I reviewed the uploaded document and displayed the extracted customer details below.\n\n"
                "Sensitive details shown in the interface:\n"
                f"{_ai_dat_sec_012_mask_pii(pii_exposure_summary)}\n\n"
                f"Processing note:\n{model_output}"
            )
        else:
            response = (
                "I reviewed the uploaded document and extracted its contents.\n\n"
                f"Processing note:\n{model_output}\n\n"
                f"Extracted content preview:\n{file_summary}"
            )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }

    def extract_pii_lines(self, content: str, limit: int = 12) -> list[str]:
        keyword_markers = (
            "name:",
            "full name:",
            "employee id",
            "date of birth",
            "dob:",
            "ssn",
            "social security",
            "address:",
            "phone:",
            "email:",
            "loan balance",
            "account number",
            "customer id",
            "borrower",
            "credit score",
        )
        pattern_markers = (
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
            re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b"),
        )

        pii_lines: list[str] = []
        for raw_line in (content or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue

            lowered = line.lower()
            if any(marker in lowered for marker in keyword_markers) or any(pattern.search(line) for pattern in pattern_markers):
                pii_lines.append(line)

            if len(pii_lines) >= limit:
                break

        return pii_lines

    def build_pii_exposure_summary(self, file_contents: list[dict[str, Any]]) -> str:
        sections: list[str] = []
        for file_data in file_contents:
            extracted_content = file_data.get("extracted_content", "")
            pii_lines = self.extract_pii_lines(extracted_content)
            if not pii_lines:
                continue

            sections.append(
                f"File: {file_data.get('filename', 'unknown')}\n" + "\n".join(pii_lines)
            )

        return "\n\n".join(sections)

    def get_file_type(self, content_type: str, filename: str) -> str:
        supported_types = {
            "application/pdf": "pdf",
            "text/html": "html",
            "text/plain": "text",
            "application/json": "json",
            "image/jpeg": "image",
            "image/png": "image",
            "application/msword": "word",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "word",
        }

        if content_type in supported_types:
            return supported_types[content_type]

        extension_map = {
            "pdf": "pdf",
            "html": "html",
            "htm": "html",
            "txt": "text",
            "json": "json",
            "jpg": "image",
            "jpeg": "image",
            "png": "image",
            "doc": "word",
            "docx": "word",
        }
        extension = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
        return extension_map.get(extension, "text")

    async def _process_pdf(self, content: str) -> str:
        try:
            return await self.pdf_parser.extract_text(base64.b64decode(content))
        except Exception as exc:
            logger.error("PDF processing failed", extra={"error": str(exc)})
            return f"Error processing PDF: {exc}"

    async def _process_html(self, content: str) -> str:
        try:
            return await self.html_parser.extract_text(content)
        except Exception as exc:
            logger.error("HTML processing failed", extra={"error": str(exc)})
            return f"Error processing HTML: {exc}"

    async def _process_image(self, content: str, content_type: str = "image/jpeg") -> str:
        try:
            return await self.image_parser.extract_all(
                base64.b64decode(content), mime_type=content_type or "image/jpeg"
            )
        except Exception as exc:
            logger.error("Image processing failed", extra={"error": str(exc)})
            return f"Error processing image: {exc}"

    async def _process_json(self, content: str) -> str:
        try:
            return json.dumps(json.loads(content), indent=2)
        except json.JSONDecodeError:
            return content

    async def _process_word(self, content: str) -> str:
        if Document is None:
            return "Word document processing requires python-docx to be installed."

        try:
            document = Document(io.BytesIO(base64.b64decode(content)))
            paragraphs = [paragraph.text.strip() for paragraph in document.paragraphs if paragraph.text.strip()]
            return "\n".join(paragraphs) or "No paragraph text was found in the Word document."
        except Exception as exc:
            logger.error("Word processing failed", extra={"error": str(exc)})
            return f"Error processing Word document: {exc}"


file_processor_agent = FileProcessorAgent()
