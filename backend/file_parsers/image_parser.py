"""
Image Parser

Extracts content from image files including EXIF metadata and
vision-model transcription of any visible text.

SECURITY NOTES (for Unifai demo):
- EXIF metadata extracted without scanning
- Visible text is transcribed verbatim by a vision model with no scanning
- Comments and descriptions could contain prompt injections
- No malware detection
"""

import base64
import io
import logging
import os
from typing import Optional

from llm.openai_compatible import OpenAICompatibleClient
from lineaje_guardrail import lineaje_guardrail, GuardrailBlockedError

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])

import re

logger = logging.getLogger(__name__)

_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(
        r'ignore\s+(?:all\s+)?previous\s+instructions|forget\s+everything\s+above',
        re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(
        r'you\s+are\s+now\s+DAN|act\s+as\s+(?:an?\s+)?unrestricted',
        re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape
    (re.compile(
        r'</\s*system\s*>|<\s*system\s*>|\[INST\]|\[/INST\]|<\|(?:im_start|im_end)\|>',
        re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload
    (re.compile(
        r'(?:[A-Za-z0-9+/]{20,}={0,2})(?=\s|$)|'
        r'(?:\\u[0-9a-fA-F]{4}){3,}|'
        r'(?:%[0-9a-fA-F]{2}){5,}|'
        r'(?:0x[0-9a-fA-F]{2}\s*){5,}',
        re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text
    (re.compile(
        r'<!--.*?-->|\u200b|\u200c|\u200d|\u2060|\ufeff|'
        r'display\s*:\s*none|visibility\s*:\s*hidden',
        re.IGNORECASE | re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(
        r'\[\s*(?:SYSTEM|TOOL|ASSISTANT|USER)\s*\]\s*:',
        re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt
    (re.compile(
        r'!\[.*?\]\(https?://[^)]+\)|'
        r'send\s+(?:this|the|all|data|prompt|system)\s+(?:data|info|prompt|to)\s+(?:to\s+)?https?://|'
        r'leak\s+(?:the\s+)?system\s+prompt|'
        r'exfiltrate',
        re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(
        r'from\s+now\s+on\s+(?:you\s+(?:will|must|should))|'
        r'in\s+(?:all|every)\s+(?:future|subsequent)\s+(?:responses?|messages?|turns?)',
        re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection
    (re.compile(
        r'(?:this\s+(?:file|document|image|metadata|field)\s+(?:contains?|has)\s+(?:a\s+)?(?:new\s+)?instructions?)',
        re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection
    (re.compile(
        r'(?:^|\s)(?:eval|exec|system|popen|subprocess)\s*\(',
        re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    # 11. split_payload
    (re.compile(
        r'(?:part\s*[1-9]\s*of\s*[1-9]|continued\s+(?:from|in)\s+(?:next|previous))',
        re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt
    (re.compile(
        r'\bDAN\b|developer\s+mode|jailbreak|fictional\s+framing|'
        r'pretend\s+(?:you\s+(?:are|have\s+no)|there\s+are\s+no)\s+(?:restrictions?|rules?|guidelines?)',
        re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in untrusted text before LLM use."""
    if not isinstance(text, str):
        return text
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


class ImageParser:
    """
    Parses image files and extracts metadata and visible text.

    VULNERABILITY: Extracts EXIF data and vision-transcribed text without
    security scanning.
    - Comment fields could contain prompt injections
    - UserComment could contain malicious instructions
    - ImageDescription could contain attacks
    - Visible pixel text is transcribed verbatim and passed downstream
    """

    def __init__(self):
        self.model_client = OpenAICompatibleClient(
            api_key=os.getenv("OPENROUTER_API_KEY"),
        )

    async def extract_metadata(self, image_bytes: bytes) -> dict:
        """
        Extract EXIF and other metadata from image.

        VULNERABILITY: Metadata extracted without scanning for threats.
        """
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            image = Image.open(io.BytesIO(image_bytes))
            metadata = {}

            # Get basic image info
            metadata['format'] = image.format
            metadata['size'] = image.size
            metadata['mode'] = image.mode

            # Extract EXIF data
            # VULNERABILITY: All EXIF data extracted without filtering
            exif_data = image._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    # Convert bytes to string for JSON serialization
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except:
                            value = str(value)
                    metadata[tag] = value

            # VULNERABILITY: Log metadata without scanning
            logger.info(
                "Image metadata extracted",
                extra={
                    "format": image.format,
                    "size": image.size,
                    "exif_fields": len(metadata),
                    # VULNERABILITY: Full metadata in logs
                    "metadata_preview": str(metadata)[:200]
                }
            )

            return metadata

        except Exception as e:
            logger.error(f"Image metadata extraction error: {e}")
            return {"error": str(e)}

    async def extract_text_fields(self, metadata: dict) -> str:
        """
        Extract text from relevant metadata fields.

        VULNERABILITY: Text fields extracted without scanning.
        These fields could contain prompt injections.
        """
        text_fields = []

        # Fields that commonly contain text content
        # VULNERABILITY: These fields could contain malicious prompts
        dangerous_fields = [
            'ImageDescription',
            'XPComment',
            'XPSubject',
            'XPTitle',
            'XPKeywords',
            'UserComment',
            'Comment',
            'Artist',
            'Copyright',
            'Software',
        ]

        for field in dangerous_fields:
            if field in metadata:
                value = metadata[field]
                if value and isinstance(value, str):
                    text_fields.append(f"{field}: {value}")
                    logger.debug(
                        f"Found text in {field}",
                        extra={
                            "field": field,
                            # VULNERABILITY: Field content logged
                            "value_preview": value[:50]
                        }
                    )

        sanitized = _ai_app_sec_070_sanitize('\n'.join(text_fields))
        return sanitized

    async def extract_visible_text(self, image_bytes: bytes, mime_type: str = "image/jpeg") -> str:
        """
        Transcribe visible text rendered in the image using the configured model.

        VULNERABILITY: whatever text is drawn on the image is transcribed
        verbatim and returned with no scanning - this is the image-based
        prompt-injection vector for this demo. Uses OPENROUTER_MODEL
        (must be multimodal for image transcription).
        """
        model = os.getenv("OPENROUTER_MODEL")
        if not self.model_client.api_key or not model:
            return ""

        try:
            transcription = await self.model_client.chat_vision(
                model=model,
                image_base64=base64.b64encode(image_bytes).decode("utf-8"),
                mime_type=mime_type,
                prompt=(
                    "Transcribe every piece of text visible anywhere in this "
                    "image verbatim - including overlaid captions, watermarks, "
                    "and any text rendered on top of the picture. Return only "
                    "the transcribed text, no commentary."
                ),
            )
            transcription = _ai_app_sec_059_guardrail.evaluate(transcription)
            logger.info(
                "Image visible-text transcription complete",
                extra={"model": model, "text_length": len(transcription)},
            )
            return _ai_app_sec_070_sanitize(transcription)
        except Exception as exc:
            logger.error(f"Image vision transcription error: {exc}")
            return ""

    async def extract_all(self, image_bytes: bytes, mime_type: str = "image/jpeg") -> str:
        """
        Extract all content from image for analysis.

        VULNERABILITY: All metadata and vision-transcribed text, including
        potentially malicious content, is extracted and returned without
        filtering.
        """
        metadata = await self.extract_metadata(image_bytes)
        text_content = await self.extract_text_fields(metadata)
        visible_text = await self.extract_visible_text(image_bytes, mime_type)

        # VULNERABILITY: Combine all content without security checks
        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        if visible_text:
            result_parts.append(f"Visible Text in Image:\n{visible_text}")

        result_parts.append(f"Image Info: {metadata.get('format', 'unknown')} {metadata.get('size', 'unknown')}")

        combined = '\n\n'.join(result_parts)
        return _ai_app_sec_070_sanitize(combined)
