"""Shared helper functions for the Acme Loan Processor agents."""

import base64
import re
from typing import Any
from uuid import uuid4


_ai_dat_sec_023_patterns = [
    # Social Security Number
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b'), '[REDACTED SSN]'),
    # Taxpayer Identification Number (EIN format)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED TIN]'),
    # Credit Card Number (Visa, MC, Amex, Discover)
    (re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[- ]?\d{4}[- ]?\d{4}[- ]?\d{3,4}\b'), '[REDACTED CREDIT CARD]'),
    # Financial Account Number (generic 8-17 digit)
    (re.compile(r'\b(?:account\s*(?:number|#|no\.?)?\s*:?\s*)?\d{8,17}\b', re.IGNORECASE), '[REDACTED ACCOUNT NUMBER]'),
    # Passport Number (US format)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED PASSPORT]'),
    # Driver's License Number (common US formats)
    (re.compile(r"\b(?:driver'?s?\s+license\s*(?:number|#|no\.?)?\s*:?\s*)[A-Z0-9]{5,15}\b", re.IGNORECASE), '[REDACTED DL]'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED VIN]'),
    # IP Address (v4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED IP]'),
    # IP Address (v6)
    (re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'), '[REDACTED IPv6]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b'), '[REDACTED MAC]'),
    # Email Address
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED EMAIL]'),
    # Personal Phone Number
    (re.compile(r'\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b'), '[REDACTED PHONE]'),
    # Year of Birth (context-sensitive)
    (re.compile(r'\b(?:born|birth\s*year|year\s*of\s*birth|dob|date\s*of\s*birth)\s*:?\s*(?:19|20)\d{2}\b', re.IGNORECASE), '[REDACTED BIRTH YEAR]'),
    # Home Address (street address pattern)
    (re.compile(r'\b\d{1,5}\s+[A-Za-z0-9\s]{3,30}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\.?\b', re.IGNORECASE), '[REDACTED ADDRESS]'),
    # Employee ID
    (re.compile(r'\b(?:employee\s*(?:id|#|no\.?)|emp\s*id)\s*:?\s*[A-Z0-9]{4,12}\b', re.IGNORECASE), '[REDACTED EMPLOYEE ID]'),
    # School ID
    (re.compile(r'\b(?:student\s*(?:id|#|no\.?)|school\s*id)\s*:?\s*[A-Z0-9]{4,12}\b', re.IGNORECASE), '[REDACTED SCHOOL ID]'),
    # Mother's Maiden Name
    (re.compile(r"\b(?:mother'?s?\s+maiden\s+name)\s*:?\s*[A-Za-z\-']{2,30}\b", re.IGNORECASE), '[REDACTED MAIDEN NAME]'),
    # Birthplace
    (re.compile(r'\b(?:birthplace|place\s*of\s*birth|born\s*in)\s*:?\s*[A-Za-z\s,]{2,50}\b', re.IGNORECASE), '[REDACTED BIRTHPLACE]'),
    # Ethnicity
    (re.compile(r'\b(?:ethnicity|ethnic\s*origin|race)\s*:?\s*[A-Za-z\s]{2,30}\b', re.IGNORECASE), '[REDACTED ETHNICITY]'),
    # Sexual Orientation
    (re.compile(r'\b(?:sexual\s*orientation|sexuality)\s*:?\s*[A-Za-z\s]{2,30}\b', re.IGNORECASE), '[REDACTED SEXUAL ORIENTATION]'),
    # Medical Records
    (re.compile(r'\b(?:medical\s*record(?:\s*number)?|mrn|diagnosis|prescription|patient\s*id)\s*:?\s*[A-Za-z0-9\s\-]{2,30}\b', re.IGNORECASE), '[REDACTED MEDICAL INFO]'),
]


def _ai_dat_sec_023_redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from the given text."""
    for pattern, replacement in _ai_dat_sec_023_patterns:
        text = pattern.sub(replacement, text)
    return text


def build_file_summary(
    file_contents: list[dict[str, Any]],
    include_raw_text: bool = False,
) -> str:
    if not file_contents:
        return "No files were attached."

    sections = []
    for file_data in file_contents:
        extracted_content = _ai_dat_sec_023_redact_pii(file_data.get("extracted_content", ""))
        if not include_raw_text and len(extracted_content) > 600:
            extracted_content = extracted_content[:600] + "..."

        sections.append(
            f"Filename: {file_data.get('filename', 'unknown')}\n"
            f"Content Type: {file_data.get('content_type', 'unknown')}\n"
            f"Extracted Content:\n{extracted_content}"
        )

    return "\n\n".join(sections)


def extract_reference_number(message: str, prefix: str) -> str:
    match = re.search(r"\b([A-Z]{2,}-\d{2,}|\d{4,})\b", message or "")
    if match:
        return str(match.group(1))
    return f"{prefix}-{str(uuid4())[:8].upper()}"


def decode_base64_segments(content: str) -> list[str]:
    decoded_segments: list[str] = []
    for candidate in extract_base64_candidates(content):
        if len(candidate) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
        except Exception:
            continue
        if decoded.strip():
            decoded_segments.append(decoded.strip())
    return decoded_segments


def extract_base64_candidates(content: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9+/=]{24,}", content or "")
