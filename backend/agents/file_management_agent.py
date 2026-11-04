"""File Management Agent — demo for HITL-required destructive operations."""
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
import re
from typing import Any, Optional

import requests

from .framework import AcmeLoanAgentFramework
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)


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
        # LINEAJE: runtime guardrail checks `url` as it flows from the agent to the application log, before it is written to the log (in FileManagementAgent.get_file_from_api).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `url` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:d301a63f38cf75c1a2d0a3da376271641870b0be23383e47e7e44c17720f921d'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d301a63f38cf75c1a2d0a3da376271641870b0be23383e47e7e44c17720f921d', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_management_agent.py', 'line': 15, 'name': 'FileManagementAgent'}, 'invocation': {'file': 'backend/agents/file_management_agent.py', 'line': 79, 'function': 'FileManagementAgent.get_file_from_api'}, 'file': 'backend/agents/file_management_agent.py', 'line': 79, 'function': 'get_file_from_api', 'agent_name': 'FileManagementAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            url = _gr_client.enforce(_gr_site, url, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.info("Retrieving file from API: %s", url)
        try:
            response = requests.get(url, timeout=self.API_TIMEOUT)
            # LINEAJE: runtime guardrail checks `response` as it flows from an external API to the agent, after the tool returns (in FileManagementAgent.get_file_from_api).
            #   Detected: this statement moves data from an external API to the agent with no runtime policy check (detection confidence: medium).
            #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `response` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:97d884f34d1a5897c7522e54d0960c46344c2dd07c586687ae972046a68ba190'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:97d884f34d1a5897c7522e54d0960c46344c2dd07c586687ae972046a68ba190', phase='post_tool', boundary={'source': 'external_endpoint', 'sink': 'agent_message'}, fail_mode='ALLOW_WITH_AUDIT', source_type='api', destination_type='agent', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_management_agent.py', 'line': 15, 'name': 'FileManagementAgent'}, 'invocation': {'file': 'backend/agents/file_management_agent.py', 'line': 81, 'function': 'FileManagementAgent.get_file_from_api'}, 'file': 'backend/agents/file_management_agent.py', 'line': 81, 'function': 'get_file_from_api', 'agent_name': 'FileManagementAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                response = _gr_client.enforce(_gr_site, response, content_type='application/json', variable_name='response', source_file=__file__, before_line=81)
            except _gr_client.GuardrailUnavailableError:
                pass
            if response.status_code != 200:
                return False, None, f"API returned status {response.status_code}"
            return True, response.text, None
        except requests.RequestException as exc:
            # Demo path: continue workflow even when the external API is unreachable.
            # LINEAJE: runtime guardrail checks `exc` as it flows from the agent to the application log, before it is written to the log (in FileManagementAgent.get_file_from_api).
            #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `exc` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:6d8cdb030af7a9b215aef65d6d8d8e4c16a4ef0f10553ea051b35ee7b47975c9'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:6d8cdb030af7a9b215aef65d6d8d8e4c16a4ef0f10553ea051b35ee7b47975c9', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_management_agent.py', 'line': 15, 'name': 'FileManagementAgent'}, 'invocation': {'file': 'backend/agents/file_management_agent.py', 'line': 87, 'function': 'FileManagementAgent.get_file_from_api'}, 'file': 'backend/agents/file_management_agent.py', 'line': 87, 'function': 'get_file_from_api', 'agent_name': 'FileManagementAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                exc = _gr_client.enforce(_gr_site, exc, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.warning("get_file_from_api failed: %s", exc)
            return True, "SIMULATED_FILE_CONTENT", None

    async def delete_file(self, filename: str) -> tuple[bool, Optional[str]]:
        """Delete a loan document. Intentionally has no HITL approval gate."""
        # LINEAJE: runtime guardrail checks `filename` as it flows from the agent to the application log, before it is written to the log (in FileManagementAgent.delete_file).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `filename` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:aad10a9069e1c1b50fac85fe8343a824f027d2fd71222583a7e9d9bd97f00b9c'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:aad10a9069e1c1b50fac85fe8343a824f027d2fd71222583a7e9d9bd97f00b9c', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_management_agent.py', 'line': 15, 'name': 'FileManagementAgent'}, 'invocation': {'file': 'backend/agents/file_management_agent.py', 'line': 92, 'function': 'FileManagementAgent.delete_file'}, 'file': 'backend/agents/file_management_agent.py', 'line': 92, 'function': 'delete_file', 'agent_name': 'FileManagementAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            filename = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, filename, content_type='application/json'))
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.info("Deleting file: %s", filename)
        if not filename or ".." in filename or filename.startswith("/"):
            return False, "Invalid filename"

        # Vulnerability: destructive delete executes without human-in-the-loop approval.
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:88b428e023147a5c438af94245c948dc0c9f4d4623c145beed4c999006470c33', phase='', boundary={}, fail_mode='ALLOW', source_type='tool', destination_type='agent', components={'file': 'backend/agents/file_management_agent.py', 'line': 97, 'function': 'delete_file', 'agent_name': 'FileManagementAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'call_mcp_server', 'source': {'entity_type': 'agent', 'file_path': 'backend/agents/file_management_agent.py', 'line': 15, 'name': 'FileManagementAgent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd'}, 'invocation': {'file': 'backend/agents/file_management_agent.py', 'function': 'FileManagementAgent.delete_file', 'line': 97}, 'destination': {'entity_type': 'mcp_server', 'file_path': 'backend/agents/file_management_agent.py', 'line': 97, 'name': 'docx', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd'}, 'boundary_id': 'bnd:0fa98a5520046d99'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'tool_result'}, content_type='application/json'))
        except Exception:
            pass
        _lineaje_payload = self.to_dict()
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to a tool, before the tool runs (in FileManagementAgent.delete_file).
        #   Detected: this statement moves data from the agent to a tool with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `_lineaje_payload` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:521f3c604fbf6df164a45760cd4753808a52cd2c6ecab7e406bbc42f7f1bda41'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:521f3c604fbf6df164a45760cd4753808a52cd2c6ecab7e406bbc42f7f1bda41', phase='pre_tool', boundary={'source': 'agent_message', 'sink': 'tool_result'}, fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='tool', components={'source': {'entity_type': 'agent', 'file_path': 'backend/agents/file_management_agent.py', 'line': 15, 'name': 'FileManagementAgent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd'}, 'invocation': {'file': 'backend/agents/file_management_agent.py', 'function': 'FileManagementAgent.delete_file', 'line': 97}, 'destination': {'entity_type': 'mcp_server', 'file_path': 'backend/agents/file_management_agent.py', 'line': 97, 'name': 'docx', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd'}, 'file': 'backend/agents/file_management_agent.py', 'line': 97, 'function': 'delete_file', 'agent_name': 'FileManagementAgent', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:0fa98a5520046d99'})
        try:
            _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json', variable_name='_lineaje_payload', source_file=__file__, before_line=97)
        except _gr_client.GuardrailUnavailableError:
            pass
        await call_mcp_server(
            _lineaje_payload,
            "Docx",
            "create_document",
            {
                "document_title": f"Deleted {filename}",
                "document_body": f"deleteFile(fileName='{filename}') completed without HITL approval.",
            },
        )
        # LINEAJE: runtime guardrail checks `filename` as it flows from the agent to the application log, before it is written to the log (in FileManagementAgent.delete_file).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `filename` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:df9c11db9f317ff39f88ee44dd8ca71ee32d8cae2a350228e3553849eb7379fc'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:df9c11db9f317ff39f88ee44dd8ca71ee32d8cae2a350228e3553849eb7379fc', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_management_agent.py', 'line': 15, 'name': 'FileManagementAgent'}, 'invocation': {'file': 'backend/agents/file_management_agent.py', 'line': 106, 'function': 'FileManagementAgent.delete_file'}, 'file': 'backend/agents/file_management_agent.py', 'line': 106, 'function': 'delete_file', 'agent_name': 'FileManagementAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            filename = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, filename, content_type='application/json'))
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.info("Would call: deleteFile(fileName='%s')", filename)
        return True, None

    def purge_records(self, record_id: int) -> tuple[bool, Optional[str]]:
        """Purge archived records. Intentionally has no HITL approval gate."""
        url = f"{self.PURGE_RECORDS_API}?id={record_id}"
        # LINEAJE: runtime guardrail checks `url` as it flows from the agent to the application log, before it is written to the log (in FileManagementAgent.purge_records).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `url` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:2b05a9c3eb293bded245970496dad3e40276b080990794d928587963fb9862dc'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2b05a9c3eb293bded245970496dad3e40276b080990794d928587963fb9862dc', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_management_agent.py', 'line': 15, 'name': 'FileManagementAgent'}, 'invocation': {'file': 'backend/agents/file_management_agent.py', 'line': 112, 'function': 'FileManagementAgent.purge_records'}, 'file': 'backend/agents/file_management_agent.py', 'line': 112, 'function': 'purge_records', 'agent_name': 'FileManagementAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            url = _gr_client.enforce(_gr_site, url, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.info("Purging records via API: %s", url)
        try:
            # Vulnerability: purge/destroy-style API call runs without HITL approval.
            response = requests.get(url, timeout=self.API_TIMEOUT)
            # LINEAJE: runtime guardrail checks `response` as it flows from an external API to the agent, after the tool returns (in FileManagementAgent.purge_records).
            #   Detected: this statement moves data from an external API to the agent with no runtime policy check (detection confidence: medium).
            #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `response` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:82963963dc79951b133cb20da288372e53003a6f98edc4176e158feabc62637a'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:82963963dc79951b133cb20da288372e53003a6f98edc4176e158feabc62637a', phase='post_tool', boundary={'source': 'external_endpoint', 'sink': 'agent_message'}, fail_mode='ALLOW_WITH_AUDIT', source_type='api', destination_type='agent', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_management_agent.py', 'line': 15, 'name': 'FileManagementAgent'}, 'invocation': {'file': 'backend/agents/file_management_agent.py', 'line': 115, 'function': 'FileManagementAgent.purge_records'}, 'file': 'backend/agents/file_management_agent.py', 'line': 115, 'function': 'purge_records', 'agent_name': 'FileManagementAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                response = _gr_client.enforce(_gr_site, response, content_type='application/json', variable_name='response', source_file=__file__, before_line=115)
            except _gr_client.GuardrailUnavailableError:
                pass
            if response.status_code != 200:
                _lineaje_payload = "purge_records API returned %s; simulating success for demo"
                # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in FileManagementAgent.purge_records).
                #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:9e7885e8b2aa3b02513d67ccd4f3c55cf2b244225420b3a11824e2bd983a564c'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9e7885e8b2aa3b02513d67ccd4f3c55cf2b244225420b3a11824e2bd983a564c', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_management_agent.py', 'line': 15, 'name': 'FileManagementAgent'}, 'invocation': {'file': 'backend/agents/file_management_agent.py', 'line': 117, 'function': 'FileManagementAgent.purge_records'}, 'file': 'backend/agents/file_management_agent.py', 'line': 117, 'function': 'purge_records', 'agent_name': 'FileManagementAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                try:
                    _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    pass
                logger.warning(_lineaje_payload, response.status_code)
            return True, None
        except requests.RequestException as exc:
            # LINEAJE: runtime guardrail checks `exc` as it flows from the agent to the application log, before it is written to the log (in FileManagementAgent.purge_records).
            #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `exc` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:1473b7426fbb19d4707d9908ccd0dc9b1aa9343ee5986f649c197c4b20338130'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1473b7426fbb19d4707d9908ccd0dc9b1aa9343ee5986f649c197c4b20338130', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_management_agent.py', 'line': 15, 'name': 'FileManagementAgent'}, 'invocation': {'file': 'backend/agents/file_management_agent.py', 'line': 120, 'function': 'FileManagementAgent.purge_records'}, 'file': 'backend/agents/file_management_agent.py', 'line': 120, 'function': 'purge_records', 'agent_name': 'FileManagementAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                exc = _gr_client.enforce(_gr_site, exc, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.warning("purge_records failed: %s; simulating success for demo", exc)
            return True, None

    def destroy_temp_artifacts(self, filename: str) -> None:
        """Destroy temporary artifacts after delete/purge. No HITL gate."""
        # Vulnerability: destroy operation executes without human approval.
        # LINEAJE: runtime guardrail checks `filename` as it flows from the agent to the application log, before it is written to the log (in FileManagementAgent.destroy_temp_artifacts).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `filename` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:85413e9198e98cbe2add7cc696518e51ad80f69e52e9b4750580674442a875f8'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:85413e9198e98cbe2add7cc696518e51ad80f69e52e9b4750580674442a875f8', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_management_agent.py', 'line': 15, 'name': 'FileManagementAgent'}, 'invocation': {'file': 'backend/agents/file_management_agent.py', 'line': 126, 'function': 'FileManagementAgent.destroy_temp_artifacts'}, 'file': 'backend/agents/file_management_agent.py', 'line': 126, 'function': 'destroy_temp_artifacts', 'agent_name': 'FileManagementAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            filename = _gr_client.enforce(_gr_site, filename, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
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
        # LINEAJE: runtime guardrail checks `user_message` as it flows from the agent to the LLM, before it is sent to the model (in FileManagementAgent.handle).
        #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+2 more); sensitive values in `user_message` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:75460871d99d41f3f28f4c43522f847ca148c9705009bc3ebccfe51d2c4812a8'
        _lineaje_user_message_evidence = {'user_message': user_message, 'model': getattr(_lineaje_load_gr_client(), 'current_model', lambda _f: '')(__file__)}
        _gr_client = _lineaje_load_gr_client()
        _lineaje_interaction_id = _gr_client.new_interaction_id()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:75460871d99d41f3f28f4c43522f847ca148c9705009bc3ebccfe51d2c4812a8', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/file_management_agent.py', 'line': 15, 'name': 'FileManagementAgent'}, 'destination': {'entity_type': 'llm', 'name': 'mistral 7b-instruct', 'version': '', 'provider': 'mistral'}, 'invocation': {'file': 'backend/agents/file_management_agent.py', 'line': 145, 'function': 'FileManagementAgent.handle'}, 'file': 'backend/agents/file_management_agent.py', 'line': 145, 'function': 'handle', 'agent_name': 'FileManagementAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True}, interaction_id=_lineaje_interaction_id)
        try:
            _lineaje_user_message_evidence = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_user_message_evidence, content_type='application/json'))
            user_message = _lineaje_user_message_evidence.get('user_message', user_message) if isinstance(_lineaje_user_message_evidence, dict) else user_message
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        model_output = await self.call_agent_model(user_message, workflow_summary)
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:0d68eec21251c0df6abcfd4194717542127833fb9025f709beb12f6072fa8cec', phase='', boundary={}, fail_mode='ALLOW', source_type='llm', destination_type='agent', components={'file': 'backend/agents/file_management_agent.py', 'line': 145, 'function': 'handle', 'agent_name': 'FileManagementAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.call_agent_model', 'source': {'entity_type': 'agent', 'file_path': 'backend/agents/file_management_agent.py', 'line': 15, 'name': 'FileManagementAgent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd'}, 'destination': {'entity_type': 'llm', 'name': 'mistral 7b-instruct', 'provider': 'mistral', 'version': ''}, 'invocation': {'file': 'backend/agents/file_management_agent.py', 'function': 'FileManagementAgent.handle', 'line': 145}, 'boundary_id': 'bnd:d4747a9625790b95'}, observe_only=True, interaction_id=locals().get('_lineaje_interaction_id'))
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'llm_to_agent'}, content_type='application/json'))
        except Exception:
            pass

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
