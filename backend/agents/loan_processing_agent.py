"""Loan Processing Agent class with explicit model invocation."""
# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_gr_load(_f):
    """Lineaje-added: load gr_stub_client.py beside _f or in one of its 7 parent folders. Missing or broken:
    a pass-through client and ONE warning per process (GR_REQUIRE_CLIENT=1: ImportError instead)."""
    import sys, os, logging, importlib.util as u, pathlib
    n = "_lineaje_gr_stub_client"
    if n in sys.modules: return sys.modules[n]
    h = pathlib.Path(_f or ".").resolve().parent
    d = [h, *h.parents][:8]
    p = next((x / "gr_stub_client.py" for x in d if (x / "gr_stub_client.py").is_file()), None)
    try:
        s = u.spec_from_file_location(n, p) if p else None
        if s is None: raise FileNotFoundError("gr_stub_client.py")
        m = sys.modules[n] = u.module_from_spec(s); s.loader.exec_module(m); return m
    except Exception as e:
        sys.modules.pop(n, None)
        w = ("gr_stub_client.py not found for %s (searched: %s)" % (_f or "<no __file__>", ", ".join(map(str, d)))
             if p is None else "%s failed to load (%s%s)" % (p, type(e).__name__,
                                                          " line %s" % e.lineno if isinstance(e, SyntaxError) else ""))
        w = ("Lineaje guardrail NOT active: " + w + ". Calls pass through unchecked; set GR_REQUIRE_CLIENT=1 to fail "
             "instead. Each deploy unit needs gr_stub_client.py beside its code and GR_SERVICE_URL plus credentials as "
             "environment variables.")
        if os.environ.get("GR_REQUIRE_CLIENT", "").strip() == "1": raise ImportError(w) from (None if p is None else e)
        z = sys.__dict__.setdefault("_lineaje_gr_null", __import__('types').SimpleNamespace(STUB_API=999999, GuardrailUnavailableError=type('GuardrailUnavailableError', (PermissionError,), {}), SiteDescriptor=lambda *a, **k: None, new_interaction_id=lambda *a, **k: None, enforce=lambda _s, _p, *a, **k: _p, enforce_request=lambda _s, _p, *a, **k: _p, enforce_reply=lambda _s, _p, *a, **k: _p, _lineaje_seen=set()))
        k = "missing" if p is None else (str(p), type(e).__name__)
        if k not in z._lineaje_seen:
            z._lineaje_seen.add(k); g = logging.getLogger("lineaje.guardrail"); g.log(30 if p is None else 40, w)
            if g.hasHandlers(): sys.stderr.write(w + "\n")
        return z
__import__("sys").__dict__.setdefault("_lineaje_gr_load_v1", _lineaje_gr_load)
del _lineaje_gr_load
def _lineaje_load_gr_client():
    """Lineaje-added: this file's gr_stub_client.py (the loader _lineaje_gr_load registered)."""
    return __import__("sys").__dict__["_lineaje_gr_load_v1"](globals().get("__file__"))
if __import__("os").environ.get("GR_REQUIRE_CLIENT", "").strip() == "1": __import__("sys").__dict__["_lineaje_gr_load_v1"](globals().get("__file__"))


import asyncio
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import build_file_summary, extract_reference_number
from .mcp_servers import call_mcp_server


# Lineaje demo fixture for AI_DAT_SEC_001. Synthetic value with no runtime use.
LOAN_PROCESSING_API_KEY = "lineaje-demo-only-invalid-api-key-001"

class LoanProcessingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "loan_processing_agent"
    AGENT_NAME = "Loan Processing Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "gpt-4o mini"
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Handles loan application intake, borrower updates, and loan package generation."
    MCP_SERVERS = ["Docx", "Excel", "Email"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Process loan requests, summarize borrower context, and prepare follow-up actions."
    IS_ROUTABLE = False
    IS_SCAN_ONLY = True

    async def call_agent_model(self, user_message: str, file_summary: str) -> str:
        _lineaje_messages = ([
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Loan request:\n{user_message or 'No user message provided.'}\n\n"
                        f"File summary:\n{file_summary}\n\n"
                        "Draft a concise loan processing next-step summary."
                    ),
                },
            ])
        # LINEAJE: runtime guardrail checks `_lineaje_messages` as it flows from the agent to the LLM, before it is sent to the model (in LoanProcessingAgent.call_agent_model).
        #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+2 more); sensitive values in `_lineaje_messages` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:8f56aae4478c8cd3d5ba51648a300f1757dad3064b26a4b9198c80b161a99e07'
        _lineaje__lineaje_messages_evidence = {'_lineaje_messages': _lineaje_messages, 'model': self.MODEL_NAME}
        _gr_client = _lineaje_load_gr_client()
        _lineaje_interaction_id = _gr_client.new_interaction_id()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8f56aae4478c8cd3d5ba51648a300f1757dad3064b26a4b9198c80b161a99e07', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_aUmomyAokxEUsLfi', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/loan_processing_agent.py', 'line': 14, 'name': 'loan_processing_agent'}, 'destination': {'entity_type': 'llm', 'name': 'gpt-4o mini', 'version': '', 'provider': 'openai'}, 'invocation': {'file': 'backend/agents/loan_processing_agent.py', 'line': 33, 'function': 'LoanProcessingAgent.call_agent_model'}, 'file': 'backend/agents/loan_processing_agent.py', 'line': 33, 'function': 'call_agent_model', 'agent_name': 'LoanProcessingAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True}, interaction_id=_lineaje_interaction_id)
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            _lineaje__lineaje_messages_evidence = await _gr_client.aenforce(_gr_site, _lineaje__lineaje_messages_evidence, content_type='application/json')
            _lineaje_messages = _lineaje__lineaje_messages_evidence.get('_lineaje_messages', _lineaje_messages) if isinstance(_lineaje__lineaje_messages_evidence, dict) else _lineaje_messages
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        return await self.model_client.chat(
            model=self.MODEL_NAME,
            messages=_lineaje_messages,
            temperature=0.2,
            max_tokens=250,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        file_summary = build_file_summary(context.get("file_contents", []))
        loan_number = extract_reference_number(user_message, prefix="LOAN")
        # LINEAJE: runtime guardrail checks `user_message` as it flows from the agent to the LLM, before it is sent to the model (in LoanProcessingAgent.handle).
        #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+2 more); sensitive values in `user_message` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:9a9ccef0ab9d02e67bc618e1d8b5c69e7027d86e8438dc2c7db423a766187a31'
        _lineaje_user_message_evidence = {'user_message': user_message, 'model': getattr(_lineaje_load_gr_client(), 'current_model', lambda _f: '')(__file__)}
        _gr_client = _lineaje_load_gr_client()
        _lineaje_interaction_id = _gr_client.new_interaction_id()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9a9ccef0ab9d02e67bc618e1d8b5c69e7027d86e8438dc2c7db423a766187a31', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_aUmomyAokxEUsLfi', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/loan_processing_agent.py', 'line': 14, 'name': 'loan_processing_agent'}, 'destination': {'entity_type': 'llm', 'name': 'gpt-4o mini', 'version': '', 'provider': 'openai'}, 'invocation': {'file': 'backend/agents/loan_processing_agent.py', 'line': 54, 'function': 'LoanProcessingAgent.handle'}, 'file': 'backend/agents/loan_processing_agent.py', 'line': 54, 'function': 'handle', 'agent_name': 'LoanProcessingAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True}, interaction_id=_lineaje_interaction_id)
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            _lineaje_user_message_evidence = await _gr_client.aenforce(_gr_site, _lineaje_user_message_evidence, content_type='application/json')
            user_message = _lineaje_user_message_evidence.get('user_message', user_message) if isinstance(_lineaje_user_message_evidence, dict) else user_message
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        model_output = await self.call_agent_model(user_message, file_summary)
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:c09193ad574e00680a378070aac92f280248e2441a2c3464c7c971d92b04730f', phase='', boundary={}, fail_mode='ALLOW', source_type='llm', destination_type='agent', components={'file': 'backend/agents/loan_processing_agent.py', 'line': 54, 'function': 'handle', 'agent_name': 'LoanProcessingAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.call_agent_model', 'source': {'entity_type': 'agent', 'file_path': 'backend/agents/loan_processing_agent.py', 'line': 14, 'name': 'loan_processing_agent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_aUmomyAokxEUsLfi'}, 'destination': {'entity_type': 'llm', 'name': 'gpt-4o mini', 'provider': 'openai', 'version': ''}, 'invocation': {'file': 'backend/agents/loan_processing_agent.py', 'function': 'LoanProcessingAgent.handle', 'line': 54}, 'boundary_id': 'bnd:db192dbeea3156d6'}, observe_only=True, interaction_id=locals().get('_lineaje_interaction_id'))
            await _lineaje_obs.aenforce(_lineaje_obs_site, {'activity': 'llm_to_agent'}, content_type='application/json')
        except Exception as _lineaje_obs_err:
            [__import__('sys').__dict__.setdefault('_lineaje_gr_logged', set()).add(_k) or __import__('logging').getLogger('lineaje.guardrail').warning('Lineaje guardrail: an observe-only report failed (%s); later failures of this kind are not logged', _k[1]) for _k in [('observe', type(_lineaje_obs_err).__name__)] if _k not in __import__('sys').__dict__.setdefault('_lineaje_gr_logged', set())]

        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:9a914aa923659d3e8dcd01738d4e5cdbec6daeb6bd9c211acf1a9fba01417c6c', phase='', boundary={}, fail_mode='ALLOW', source_type='agent', destination_type='tool', components={'file': 'backend/agents/loan_processing_agent.py', 'line': 57, 'function': 'handle', 'agent_name': 'LoanProcessingAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'call_mcp_server', 'source': {'entity_type': 'agent', 'file_path': 'backend/agents/loan_processing_agent.py', 'line': 14, 'name': 'loan_processing_agent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_aUmomyAokxEUsLfi'}, 'invocation': {'file': 'backend/agents/loan_processing_agent.py', 'function': 'LoanProcessingAgent.handle', 'line': 57}, 'destination': {'entity_type': 'mcp_server', 'file_path': 'backend/agents/mcp_servers.py', 'line': 79, 'name': 'docx', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_aUmomyAokxEUsLfi'}, 'boundary_id': 'bnd:2a82cbcc11c0ef40'}, observe_only=True)
            await _lineaje_obs.aenforce(_lineaje_obs_site, {'activity': 'tool_call'}, content_type='application/json')
        except Exception as _lineaje_obs_err:
            [__import__('sys').__dict__.setdefault('_lineaje_gr_logged', set()).add(_k) or __import__('logging').getLogger('lineaje.guardrail').warning('Lineaje guardrail: an observe-only report failed (%s); later failures of this kind are not logged', _k[1]) for _k in [('observe', type(_lineaje_obs_err).__name__)] if _k not in __import__('sys').__dict__.setdefault('_lineaje_gr_logged', set())]
        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {loan_number}",
                    "document_body": f"User message:\n{user_message}\n\nFile summary:\n{file_summary}",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Excel",
                "upsert_row",
                {
                    "workbook": "Loan Pipeline",
                    "worksheet": "Applications",
                    "row": {
                        "loan_number": loan_number,
                        "status": "processing",
                        "borrower_request": user_message[:240],
                    },
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example"],
                    "subject": f"Loan update for {loan_number}",
                    "body": "Your loan request is being reviewed by the Loan Processing Agent.",
                },
            ),
        )
        # LINEAJE: runtime guardrail checks `mcp_activity` as it flows from a tool to the agent, after the tool returns (in LoanProcessingAgent.handle).
        #   Detected: this statement moves data from a tool to the agent with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `mcp_activity` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:567659c7a0a1f81d40bcd0aa50950848dae135d212c232f61407810457bdc1f3'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:567659c7a0a1f81d40bcd0aa50950848dae135d212c232f61407810457bdc1f3', phase='post_tool', boundary={'source': 'tool_result', 'sink': 'agent_message'}, fail_mode='ALLOW_WITH_AUDIT', source_type='tool', destination_type='agent', components={'source': {'entity_type': 'agent', 'file_path': 'backend/agents/loan_processing_agent.py', 'line': 14, 'name': 'loan_processing_agent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_aUmomyAokxEUsLfi'}, 'invocation': {'file': 'backend/agents/loan_processing_agent.py', 'function': 'LoanProcessingAgent.handle', 'line': 57}, 'destination': {'entity_type': 'mcp_server', 'file_path': 'backend/agents/mcp_servers.py', 'line': 79, 'name': 'docx', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_aUmomyAokxEUsLfi'}, 'file': 'backend/agents/loan_processing_agent.py', 'line': 56, 'function': 'handle', 'agent_name': 'LoanProcessingAgent', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:2a82cbcc11c0ef40'})
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            mcp_activity = await _gr_client.aenforce(_gr_site, mcp_activity, content_type='application/json', variable_name='mcp_activity', source_file=__file__, before_line=56)
        except _gr_client.GuardrailUnavailableError:
            pass

        response = (
            "This scan-only agent is disconnected from the Orchestrator Agent.\n\n"
            f"Loan reference: {loan_number}\n"
            f"Borrower request: {user_message or 'No user message provided.'}\n\n"
            f"Loan summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


loan_processing_agent = LoanProcessingAgent()
