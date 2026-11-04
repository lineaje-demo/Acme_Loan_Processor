"""
HTML Parser

Extracts text content from HTML files.

SECURITY NOTES (for Unifai demo):
- Extracts text including from hidden elements
- CSS-hidden content is extracted
- Script content may be included
- No XSS sanitization
"""
# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py (missing / broken: a pass-through client)."""
    import sys, importlib.util as u, pathlib
    n = "_lineaje_gr_stub_client"
    if n in sys.modules: return sys.modules[n]
    try:
        h = pathlib.Path(__file__).resolve().parent
        s = u.spec_from_file_location(n, next(p for p in (d / "gr_stub_client.py" for d in [h, *h.parents][:8]) if p.is_file()))
        m = sys.modules[n] = u.module_from_spec(s); s.loader.exec_module(m); return m
    except Exception:
        sys.modules.pop(n, None); return __import__('types').SimpleNamespace(STUB_API=999999, GuardrailUnavailableError=type('GuardrailUnavailableError', (PermissionError,), {}), SiteDescriptor=lambda *a, **k: None, new_interaction_id=lambda *a, **k: None, enforce=lambda _s, _p, *a, **k: _p, enforce_request=lambda _s, _p, *a, **k: _p, enforce_reply=lambda _s, _p, *a, **k: _p)


import logging
from typing import Optional

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

            _lineaje_payload = "HTML text extraction complete"
            # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in HTMLParser.extract_text).
            #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:7c87fcc1cf42b48751e7d8d1e2cc30e673866634fb1d8c2df64d1c79bd0d20b3'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7c87fcc1cf42b48751e7d8d1e2cc30e673866634fb1d8c2df64d1c79bd0d20b3', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'backend/file_parsers/html_parser.py', 'line': 57, 'function': 'HTMLParser.extract_text'}, 'file': 'backend/file_parsers/html_parser.py', 'line': 57, 'function': 'extract_text', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.info(
                _lineaje_payload,
                extra={
                    "text_length": len(text),
                    # VULNERABILITY: Content preview in logs
                    "preview": text[:100]
                }
            )

            # LINEAJE: runtime guardrail checks `text` as it flows from the agent to the user interface, before it leaves the application (in HTMLParser.extract_text).
            #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `text` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:c0823b13e69b2090df5f929bd273778e8bee23a78d14da234733272bde594795'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:c0823b13e69b2090df5f929bd273778e8bee23a78d14da234733272bde594795', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'backend/file_parsers/html_parser.py', 'line': 66, 'function': 'HTMLParser.extract_text'}, 'file': 'backend/file_parsers/html_parser.py', 'line': 66, 'function': 'extract_text', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                text = _gr_client.enforce(_gr_site, text, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return text

        except Exception as e:
            _lineaje_payload = f"HTML extraction error: {e}"
            # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in HTMLParser.extract_text).
            #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:6db350d10da664d1f974c2b94c04346f1571ac6550c498fc100cd74e3d0a6661'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:6db350d10da664d1f974c2b94c04346f1571ac6550c498fc100cd74e3d0a6661', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'backend/file_parsers/html_parser.py', 'line': 69, 'function': 'HTMLParser.extract_text'}, 'file': 'backend/file_parsers/html_parser.py', 'line': 69, 'function': 'extract_text', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.error(_lineaje_payload)
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

            # LINEAJE: runtime guardrail checks `metadata` as it flows from the agent to the user interface, before it leaves the application (in HTMLParser.extract_metadata).
            #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `metadata` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:ebe87fb1c2cfd9fdf6cc0e2942a3fbb71755334a05640055d0bd47a4348af314'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ebe87fb1c2cfd9fdf6cc0e2942a3fbb71755334a05640055d0bd47a4348af314', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'backend/file_parsers/html_parser.py', 'line': 107, 'function': 'HTMLParser.extract_metadata'}, 'file': 'backend/file_parsers/html_parser.py', 'line': 107, 'function': 'extract_metadata', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                metadata = _gr_client.enforce(_gr_site, metadata, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return metadata

        except Exception as e:
            _lineaje_payload = f"HTML metadata extraction error: {e}"
            # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in HTMLParser.extract_metadata).
            #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:f54624af7029737d1a4e1d778dd054579ad42137994e80696b854ce8b6b06975'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:f54624af7029737d1a4e1d778dd054579ad42137994e80696b854ce8b6b06975', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'backend/file_parsers/html_parser.py', 'line': 110, 'function': 'HTMLParser.extract_metadata'}, 'file': 'backend/file_parsers/html_parser.py', 'line': 110, 'function': 'extract_metadata', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.error(_lineaje_payload)
            return {}

    async def extract_all(self, html_content: str) -> dict:
        """
        Extract all content from HTML.

        VULNERABILITY: All content extracted without security analysis.
        """
        text = await self.extract_text(html_content)
        metadata = await self.extract_metadata(html_content)

        return {
            "text": text,
            "metadata": metadata,
            "warnings": []  # VULNERABILITY: No warnings generated
        }
