"""
HTML Parser

Extracts text content from HTML files.

SECURITY NOTES (for Unifai demo):
- Extracts text including from hidden elements
- CSS-hidden content is extracted
- Script content may be included
- No XSS sanitization
"""

import logging
import re
from typing import Optional

# PII patterns for zero-tolerance categories
_ai_dat_sec_023_patterns = [
    # Social Security Number
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), '[REDACTED-SSN]'),
    # Taxpayer Identification Number (EIN format)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED-TIN]'),
    # Credit Card Number (Visa, MC, Amex, Discover)
    (re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b'), '[REDACTED-CCN]'),
    # Email address
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED-EMAIL]'),
    # Personal Phone Number (US formats)
    (re.compile(r'\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'), '[REDACTED-PHONE]'),
    # IP Address (IPv4)
    (re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'), '[REDACTED-IP]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED-MAC]'),
    # Passport Number (generic alphanumeric 6-9 chars preceded by keyword)
    (re.compile(r'(?i)\bpassport\s*(?:number|no\.?|#)?\s*[:\-]?\s*([A-Z0-9]{6,9})\b'), '[REDACTED-PASSPORT]'),
    # Drivers License (preceded by keyword)
    (re.compile(r"(?i)\bdriver'?s?\s+licen[sc]e\s*(?:number|no\.?|#)?\s*[:\-]?\s*([A-Z0-9]{5,15})\b"), '[REDACTED-DL]'),
    # Financial Account Number (preceded by keyword)
    (re.compile(r'(?i)\b(?:account|acct)\s*(?:number|no\.?|#)?\s*[:\-]?\s*(\d{6,17})\b'), '[REDACTED-ACCOUNT]'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED-VIN]'),
    # Year of Birth (preceded by keyword)
    (re.compile(r'(?i)\b(?:born|birth\s*year|year\s*of\s*birth|dob|date\s*of\s*birth)\s*[:\-]?\s*(\d{4}|\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b'), '[REDACTED-DOB]'),
    # Home Address (street address pattern)
    (re.compile(r'\b\d{1,5}\s+[A-Za-z0-9\s]{3,30}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\.?\b'), '[REDACTED-ADDRESS]'),
    # Employee ID (preceded by keyword)
    (re.compile(r'(?i)\bemployee\s*(?:id|no\.?|number|#)\s*[:\-]?\s*([A-Z0-9]{3,12})\b'), '[REDACTED-EMPID]'),
    # School ID (preceded by keyword)
    (re.compile(r'(?i)\bstudent\s*(?:id|no\.?|number|#)\s*[:\-]?\s*([A-Z0-9]{3,12})\b'), '[REDACTED-SCHOOLID]'),
    # Ethnicity keywords
    (re.compile(r'(?i)\bethnicity\s*[:\-]?\s*[A-Za-z\s]{2,30}\b'), '[REDACTED-ETHNICITY]'),
    # Sexual Orientation keywords
    (re.compile(r'(?i)\bsexual\s+orientation\s*[:\-]?\s*[A-Za-z\s]{2,30}\b'), '[REDACTED-ORIENTATION]'),
    # Medical Record Number (preceded by keyword)
    (re.compile(r'(?i)\b(?:medical\s*record|mrn|patient\s*id)\s*(?:number|no\.?|#)?\s*[:\-]?\s*([A-Z0-9]{4,15})\b'), '[REDACTED-MEDICAL]'),
]


def _ai_dat_sec_023_redact_pii(text: str) -> str:
    """Scan text for zero-tolerance PII categories and redact any matches."""
    for pattern, replacement in _ai_dat_sec_023_patterns:
        text = pattern.sub(replacement, text)
    return text

logger = logging.getLogger(__name__)


class HTMLParser:
    """
    Parses HTML files and extracts text content.

    VULNERABILITY: Extracts hidden content without flagging.
    - display:none elements are extracted
    - visibility:hidden elements are extracted
    - Off-screen positioned elements are extracted
    - White text on white background is extracted
    """

    def __init__(self):
        pass

    async def extract_text(self, html_content: str) -> str:
        """
        Extract all text from HTML content.

        VULNERABILITY: All text extracted including hidden content.
        get_text() extracts text from hidden elements.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements (but not hidden divs!)
            for element in soup(['script', 'style']):
                element.decompose()

            # VULNERABILITY: get_text() extracts from hidden elements too
            # This includes:
            # - Elements with display:none
            # - Elements with visibility:hidden
            # - Off-screen positioned elements
            # - White text on white background
            text = soup.get_text(separator='\n', strip=True)
            text = _ai_dat_sec_023_redact_pii(text)

            logger.info(
                "HTML text extraction complete",
                extra={
                    "text_length": len(text),
                    # VULNERABILITY: Content preview in logs
                    "preview": text[:100]
                }
            )

            return text

        except Exception as e:
            logger.error(f"HTML extraction error: {e}")
            return f"Error extracting HTML: {str(e)}"

    async def extract_visible_only(self, html_content: str) -> str:
        """
        Extract only visible text (not implemented properly).

        VULNERABILITY: Still extracts hidden content.
        Would need CSS parsing to properly filter.
        """
        # VULNERABILITY: This method doesn't actually filter hidden content
        # It would need to parse inline styles and CSS classes
        return await self.extract_text(html_content)

    async def extract_metadata(self, html_content: str) -> dict:
        """
        Extract HTML metadata (title, meta tags).

        VULNERABILITY: Metadata extracted without scanning.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')
            metadata = {}

            # Title
            title = soup.find('title')
            if title:
                metadata['title'] = title.get_text()

            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    metadata[name] = content

            return metadata

        except Exception as e:
            logger.error(f"HTML metadata extraction error: {e}")
            return {}

    async def extract_all(self, html_content: str) -> dict:
        """
        Extract all content from HTML.

        VULNERABILITY: All content extracted without security analysis.
        """
        text = await self.extract_text(html_content)
        metadata = await self.extract_metadata(html_content)

        text = _ai_dat_sec_023_redact_pii(text)
        return {
            "text": text,
            "metadata": metadata,
            "warnings": []
        }
