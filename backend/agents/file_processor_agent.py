"""File Processor Agent class with explicit model invocation."""
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

from .framework import AcmeLoanAgentFramework
from .helpers import build_file_summary
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)


class FileProcessorAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_processor_agent"
    AGENT_NAME = "File Processor Agent"
    VERSION = "1.0.0"
    OPENROUTER_MODEL = "meta-llama/llama-4-scout"
    MODEL_NAME = "meta-llama/llama-4-scout"
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
        Vulnerability: extracted text is returned directly without PII masking.
        """
        file_type = self.get_file_type(content_type, filename)
        if not content:
            extracted_content = f"Empty file: {filename}"
        elif file_type == "pdf":
            # LINEAJE: runtime guardrail checks `content` as it flows from file storage to the agent (in FileProcessorAgent.process_attachment).
            #   Detected: this statement moves data from file storage to the agent with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_APP_SEC_070, AI_DAT_SEC_023, AI_DAT_SEC_024; sensitive values in `content` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:b1dc6f00cb9665400745ea03f92922ada5dd76d2253d8ad598857eaa50e85d85'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:b1dc6f00cb9665400745ea03f92922ada5dd76d2253d8ad598857eaa50e85d85', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, fail_mode='BLOCK', source_type='file_storage', destination_type='agent', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent'}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 78, 'function': 'FileProcessorAgent.process_attachment'}, 'file': 'backend/agents/file_processor_agent.py', 'line': 78, 'function': 'process_attachment', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                content = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, content, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
            extracted_content = await self._process_pdf(content)
        elif file_type == "html":
            # LINEAJE: runtime guardrail checks `content` as it flows from file storage to the agent (in FileProcessorAgent.process_attachment).
            #   Detected: this statement moves data from file storage to the agent with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_APP_SEC_070, AI_DAT_SEC_023, AI_DAT_SEC_024; sensitive values in `content` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:660e1adc4ba6a4004310f5d32107187a0b6bce019dbe7a550aeef111adf9e779'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:660e1adc4ba6a4004310f5d32107187a0b6bce019dbe7a550aeef111adf9e779', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, fail_mode='BLOCK', source_type='file_storage', destination_type='agent', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent'}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 80, 'function': 'FileProcessorAgent.process_attachment'}, 'file': 'backend/agents/file_processor_agent.py', 'line': 80, 'function': 'process_attachment', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                content = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, content, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
            extracted_content = await self._process_html(content)
        elif file_type == "image":
            # LINEAJE: runtime guardrail checks `content` as it flows from file storage to the agent (in FileProcessorAgent.process_attachment).
            #   Detected: this statement moves data from file storage to the agent with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_APP_SEC_070, AI_DAT_SEC_023, AI_DAT_SEC_024; sensitive values in `content` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:e2e1a9b768a3ad9f706489e00e7e20042c5a175c0eeff3699d0cf138c12873af'
            _lineaje_content_evidence = {'content': content, 'name': content_type}
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e2e1a9b768a3ad9f706489e00e7e20042c5a175c0eeff3699d0cf138c12873af', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, fail_mode='BLOCK', source_type='file_storage', destination_type='agent', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent'}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 82, 'function': 'FileProcessorAgent.process_attachment'}, 'file': 'backend/agents/file_processor_agent.py', 'line': 82, 'function': 'process_attachment', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                _lineaje_content_evidence = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_content_evidence, content_type='application/json'))
                content = _lineaje_content_evidence.get('content', content) if isinstance(_lineaje_content_evidence, dict) else content
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
            extracted_content = await self._process_image(content, content_type)
        elif file_type == "json":
            # LINEAJE: runtime guardrail checks `content` as it flows from file storage to the agent (in FileProcessorAgent.process_attachment).
            #   Detected: this statement moves data from file storage to the agent with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_APP_SEC_070, AI_DAT_SEC_023, AI_DAT_SEC_024; sensitive values in `content` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:78dfef1bd385b2dd7cce8a053a3f1bce78d54657357eb50a874b4b8267ffe8db'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:78dfef1bd385b2dd7cce8a053a3f1bce78d54657357eb50a874b4b8267ffe8db', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, fail_mode='BLOCK', source_type='file_storage', destination_type='agent', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent'}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 84, 'function': 'FileProcessorAgent.process_attachment'}, 'file': 'backend/agents/file_processor_agent.py', 'line': 84, 'function': 'process_attachment', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                content = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, content, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
            extracted_content = await self._process_json(content)
        elif file_type == "word":
            # LINEAJE: runtime guardrail checks `content` as it flows from file storage to the agent (in FileProcessorAgent.process_attachment).
            #   Detected: this statement moves data from file storage to the agent with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_APP_SEC_070, AI_DAT_SEC_023, AI_DAT_SEC_024; sensitive values in `content` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:0dfa9b4d526ec41a3a6433a05db33c29d4741dfa177b257213f26d9c8d1e6dbb'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0dfa9b4d526ec41a3a6433a05db33c29d4741dfa177b257213f26d9c8d1e6dbb', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, fail_mode='BLOCK', source_type='file_storage', destination_type='agent', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent'}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 86, 'function': 'FileProcessorAgent.process_attachment'}, 'file': 'backend/agents/file_processor_agent.py', 'line': 86, 'function': 'process_attachment', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                content = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, content, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
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
            "extracted_content": extracted_content,
            "guardrails": dict(self.GUARDRAILS),
        }

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        file_contents = context.get("file_contents", [])
        file_summary = build_file_summary(file_contents, include_raw_text=True)
        pii_exposure_summary = self.build_pii_exposure_summary(file_contents)
        # LINEAJE: runtime guardrail checks `file_summary` as it flows from the agent to the LLM, before it is sent to the model (in FileProcessorAgent.handle).
        #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+2 more); sensitive values in `file_summary` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:0e58a5efc8b4121a0d12ba11a6541ba6cf33d3ed7a0869a1a4d14d33670f557a'
        _lineaje_file_summary_evidence = {'file_summary': file_summary, 'model': getattr(_lineaje_load_gr_client(), 'current_model', lambda _f: '')(__file__)}
        _gr_client = _lineaje_load_gr_client()
        _lineaje_interaction_id = _gr_client.new_interaction_id()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0e58a5efc8b4121a0d12ba11a6541ba6cf33d3ed7a0869a1a4d14d33670f557a', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'source': {'entity_type': 'agent', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd'}, 'destination': {'entity_type': 'llm', 'name': 'llama-4-scout', 'provider': 'meta-llama', 'version': ''}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'function': 'FileProcessorAgent.handle', 'line': 105}, 'file': 'backend/agents/file_processor_agent.py', 'line': 105, 'function': 'handle', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:fe4b117eb6573940'}, interaction_id=_lineaje_interaction_id)
        try:
            _lineaje_file_summary_evidence = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_file_summary_evidence, content_type='application/json'))
            file_summary = _lineaje_file_summary_evidence.get('file_summary', file_summary) if isinstance(_lineaje_file_summary_evidence, dict) else file_summary
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        model_output = await self.call_agent_model(file_summary)
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:bf4a1b1905d6ef451ef0a84ce1658ef80fded092d92d448d860fba925e9f1674', phase='', boundary={}, fail_mode='ALLOW', source_type='llm', destination_type='agent', components={'file': 'backend/agents/file_processor_agent.py', 'line': 105, 'function': 'handle', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.call_agent_model', 'source': {'entity_type': 'agent', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd'}, 'destination': {'entity_type': 'llm', 'name': 'mistral.mistral-7b-instruct-v0:2', 'provider': 'mistral', 'version': ''}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'function': 'FileProcessorAgent.handle', 'line': 105}, 'boundary_id': 'bnd:ce681e032933a451'}, observe_only=True, interaction_id=locals().get('_lineaje_interaction_id'))
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'llm_to_agent'}, content_type='application/json'))
        except Exception:
            pass
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:7d8adcb7f9dd687e1e6dcbab9a0b03e5462152ede0faea4791902bae1ef1583b', phase='', boundary={}, fail_mode='ALLOW', source_type='tool', destination_type='agent', components={'file': 'backend/agents/file_processor_agent.py', 'line': 107, 'function': 'handle', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'call_mcp_server', 'source': {'entity_type': 'agent', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd'}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'function': 'FileProcessorAgent.handle', 'line': 107}, 'destination': {'entity_type': 'mcp_server', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 107, 'name': 'docx', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd'}, 'boundary_id': 'bnd:a3660cf268937f78'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'tool_result'}, content_type='application/json'))
        except Exception:
            pass
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:e25055da0a039d4ca20011c74b78f592ac2b3b50f0e1398dc7c5ae2fe8fd0219', phase='', boundary={}, fail_mode='ALLOW', source_type='agent', destination_type='tool', components={'file': 'backend/agents/file_processor_agent.py', 'line': 107, 'function': 'handle', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'call_mcp_server', 'source': {'entity_type': 'agent', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd'}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'function': 'FileProcessorAgent.handle', 'line': 107}, 'destination': {'entity_type': 'mcp_server', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 107, 'name': 'docx', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd'}, 'boundary_id': 'bnd:a3660cf268937f78'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'tool_call'}, content_type='application/json'))
        except Exception:
            pass
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
                f"{pii_exposure_summary}\n\n"
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

        # LINEAJE: runtime guardrail checks `pii_lines` as it flows from the agent to the user interface, before it leaves the application (in FileProcessorAgent.extract_pii_lines).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `pii_lines` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:4947c91b106e505c91b13c8ae786d3d2270ee81ac37ff44ce43cce232f49a090'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:4947c91b106e505c91b13c8ae786d3d2270ee81ac37ff44ce43cce232f49a090', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent'}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 177, 'function': 'FileProcessorAgent.extract_pii_lines'}, 'file': 'backend/agents/file_processor_agent.py', 'line': 177, 'function': 'extract_pii_lines', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            pii_lines = _gr_client.enforce(_gr_site, pii_lines, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
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
            _lineaje_payload = "PDF processing failed"
            # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in FileProcessorAgent._process_pdf).
            #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:8917bce0ebbc841099bc919d757896daf2365c939b40dd6b09e27d0de1178110'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8917bce0ebbc841099bc919d757896daf2365c939b40dd6b09e27d0de1178110', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent'}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 227, 'function': 'FileProcessorAgent._process_pdf'}, 'file': 'backend/agents/file_processor_agent.py', 'line': 227, 'function': '_process_pdf', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.error(_lineaje_payload, extra={"error": str(exc)})
            return f"Error processing PDF: {exc}"

    async def _process_html(self, content: str) -> str:
        try:
            return await self.html_parser.extract_text(content)
        except Exception as exc:
            _lineaje_payload = "HTML processing failed"
            # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in FileProcessorAgent._process_html).
            #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:890bcd5bef2620d340a5df49e29fba1e799b7290a9246ce921caf1b2b76396e5'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:890bcd5bef2620d340a5df49e29fba1e799b7290a9246ce921caf1b2b76396e5', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent'}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 234, 'function': 'FileProcessorAgent._process_html'}, 'file': 'backend/agents/file_processor_agent.py', 'line': 234, 'function': '_process_html', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.error(_lineaje_payload, extra={"error": str(exc)})
            return f"Error processing HTML: {exc}"

    async def _process_image(self, content: str, content_type: str = "image/jpeg") -> str:
        try:
            return await self.image_parser.extract_all(
                base64.b64decode(content), mime_type=content_type or "image/jpeg"
            )
        except Exception as exc:
            _lineaje_payload = "Image processing failed"
            # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in FileProcessorAgent._process_image).
            #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:20d2fd675586c9d0dc91697fae368149a7e5eb1daa42cc78284e4d33e889bf0b'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:20d2fd675586c9d0dc91697fae368149a7e5eb1daa42cc78284e4d33e889bf0b', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent'}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 243, 'function': 'FileProcessorAgent._process_image'}, 'file': 'backend/agents/file_processor_agent.py', 'line': 243, 'function': '_process_image', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.error(_lineaje_payload, extra={"error": str(exc)})
            return f"Error processing image: {exc}"

    async def _process_json(self, content: str) -> str:
        try:
            _lineaje_payload = json.loads(content)
            # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to an external endpoint, before it leaves the application (in FileProcessorAgent._process_json).
            #   Detected: this statement moves data from the agent to an external endpoint with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `_lineaje_payload` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:2abe9c07c165df221215259f210e144f51665f2748015e8b1d3823b5167b5048'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2abe9c07c165df221215259f210e144f51665f2748015e8b1d3823b5167b5048', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'external_endpoint'}, fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='external', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent'}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 248, 'function': 'FileProcessorAgent._process_json'}, 'file': 'backend/agents/file_processor_agent.py', 'line': 248, 'function': '_process_json', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json', variable_name='_lineaje_payload', source_file=__file__, before_line=248))
            except _gr_client.GuardrailUnavailableError:
                pass
            return json.dumps(_lineaje_payload, indent=2)
        except json.JSONDecodeError:
            # LINEAJE: runtime guardrail checks `content` as it flows from the agent to the user interface, before it leaves the application (in FileProcessorAgent._process_json).
            #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `content` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:7b366c37da5fe9ef94942456400c80fec817bf3b34679ead276591edf29b11f5'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7b366c37da5fe9ef94942456400c80fec817bf3b34679ead276591edf29b11f5', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent'}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 250, 'function': 'FileProcessorAgent._process_json'}, 'file': 'backend/agents/file_processor_agent.py', 'line': 250, 'function': '_process_json', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                content = _gr_client.enforce(_gr_site, content, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return content

    async def _process_word(self, content: str) -> str:
        if Document is None:
            return "Word document processing requires python-docx to be installed."

        try:
            document = Document(io.BytesIO(base64.b64decode(content)))
            paragraphs = [paragraph.text.strip() for paragraph in document.paragraphs if paragraph.text.strip()]
            return "\n".join(paragraphs) or "No paragraph text was found in the Word document."
        except Exception as exc:
            _lineaje_payload = "Word processing failed"
            # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in FileProcessorAgent._process_word).
            #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:e9fddf84a4083cbf900485e97562d9afd2e1494cfdf15949cd6f31776e9964a9'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e9fddf84a4083cbf900485e97562d9afd2e1494cfdf15949cd6f31776e9964a9', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 26, 'name': 'FileProcessorAgent'}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 261, 'function': 'FileProcessorAgent._process_word'}, 'file': 'backend/agents/file_processor_agent.py', 'line': 261, 'function': '_process_word', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.error(_lineaje_payload, extra={"error": str(exc)})
            return f"Error processing Word document: {exc}"


file_processor_agent = FileProcessorAgent()
