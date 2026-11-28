"""Scheduling Agent class with explicit model invocation."""
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
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server


class SchedulingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "amazon nova lite"
    BEDROCK_MODEL_ID = "amazon.nova-lite-v1:0"
    DESCRIPTION = "Schedules borrower, underwriting, and support meetings."
    MCP_SERVERS = ["Google Calendar", "Email", "Slack"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Coordinate calendar events and notify the relevant teams."

    async def call_agent_model(self, user_message: str, meeting_reference: str) -> str:
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Meeting reference: {meeting_reference}\n"
                        f"Scheduling request: {user_message or 'Loan coordination meeting requested.'}\n\n"
                        "Draft a scheduling confirmation."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=180,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        meeting_reference = extract_reference_number(user_message, prefix="MEET")
        # LINEAJE: runtime guardrail checks `user_message` as it flows from the agent to the LLM, before it is sent to the model (in SchedulingAgent.handle).
        #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+2 more); sensitive values in `user_message` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:ffe1354837ce0346bb61aa5011bbf7b31273aaf3703463eb21d4ffebb0fb0958'
        _lineaje_user_message_evidence = {'user_message': user_message, 'model': getattr(_lineaje_load_gr_client(), 'current_model', lambda _f: '')(__file__)}
        _gr_client = _lineaje_load_gr_client()
        _lineaje_interaction_id = _gr_client.new_interaction_id()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ffe1354837ce0346bb61aa5011bbf7b31273aaf3703463eb21d4ffebb0fb0958', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'source': {'entity_type': 'agent', 'file_path': 'backend/agents/scheduling_agent.py', 'line': 13, 'name': 'Scheduling Agent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_elgreoHPPlPJqb7M'}, 'destination': {'entity_type': 'llm', 'name': 'amazon nova lite', 'provider': '', 'version': ''}, 'invocation': {'file': 'backend/agents/scheduling_agent.py', 'function': 'SchedulingAgent.handle', 'line': 47}, 'file': 'backend/agents/scheduling_agent.py', 'line': 47, 'function': 'handle', 'agent_name': 'SchedulingAgent', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:5fe2e3b32c231bc1'}, interaction_id=_lineaje_interaction_id)
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
        model_output = await self.call_agent_model(user_message, meeting_reference)
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:840e435e7b66d9d9c29716ff9e66924e4802de22b192c510fe2ac99c53335b84', phase='', boundary={}, fail_mode='ALLOW', source_type='llm', destination_type='agent', components={'file': 'backend/agents/scheduling_agent.py', 'line': 47, 'function': 'handle', 'agent_name': 'SchedulingAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.call_agent_model', 'source': {'entity_type': 'agent', 'file_path': 'backend/agents/scheduling_agent.py', 'line': 13, 'name': 'Scheduling Agent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_elgreoHPPlPJqb7M'}, 'destination': {'entity_type': 'llm', 'name': 'amazon nova lite', 'provider': '', 'version': ''}, 'invocation': {'file': 'backend/agents/scheduling_agent.py', 'function': 'SchedulingAgent.handle', 'line': 47}, 'boundary_id': 'bnd:5fe2e3b32c231bc1'}, observe_only=True, interaction_id=locals().get('_lineaje_interaction_id'))
            await _lineaje_obs.aenforce(_lineaje_obs_site, {'activity': 'llm_to_agent'}, content_type='application/json')
        except Exception as _lineaje_obs_err:
            [__import__('sys').__dict__.setdefault('_lineaje_gr_logged', set()).add(_k) or __import__('logging').getLogger('lineaje.guardrail').warning('Lineaje guardrail: an observe-only report failed (%s); later failures of this kind are not logged', _k[1]) for _k in [('observe', type(_lineaje_obs_err).__name__)] if _k not in __import__('sys').__dict__.setdefault('_lineaje_gr_logged', set())]

        _lineaje_payload = (call_mcp_server(
                self.to_dict(),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                },
            ))
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to a tool, before the tool runs (in SchedulingAgent.handle).
        #   Detected: this statement moves data from the agent to a tool with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `_lineaje_payload` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:9a071a3a21923977f3a2559eb4b5271d4fd0af6826eaf348f7fbc82baabe7285'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9a071a3a21923977f3a2559eb4b5271d4fd0af6826eaf348f7fbc82baabe7285', phase='pre_tool', boundary={'source': 'agent_message', 'sink': 'tool_result'}, fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='tool', components={'source': {'entity_type': 'agent', 'file_path': 'backend/agents/scheduling_agent.py', 'line': 23, 'name': 'amazon.nova-lite-v1:0', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_elgreoHPPlPJqb7M'}, 'invocation': {'file': 'backend/agents/scheduling_agent.py', 'function': 'SchedulingAgent.handle', 'line': 49}, 'destination': {'entity_type': 'mcp_server', 'file_path': 'backend/agents/scheduling_agent.py', 'line': 71, 'name': 'slack', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_elgreoHPPlPJqb7M'}, 'file': 'backend/agents/scheduling_agent.py', 'line': 49, 'function': 'handle', 'agent_name': 'SchedulingAgent', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:17f72bb7dd352a82'})
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            _lineaje_payload = await _gr_client.aenforce(_gr_site, _lineaje_payload, content_type='application/json', variable_name='_lineaje_payload', source_file=__file__, before_line=49)
        except _gr_client.GuardrailUnavailableError:
            pass
        mcp_activity = await asyncio.gather(
            _lineaje_payload,
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                },
            ),
        )
        # LINEAJE: runtime guardrail checks `mcp_activity` as it flows from a tool to the agent, after the tool returns (in SchedulingAgent.handle).
        #   Detected: this statement moves data from a tool to the agent with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `mcp_activity` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:f25d857d00787ae16e48643fa8427d88cd8eed7ead2ceb4f1898fe2508527568'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:f25d857d00787ae16e48643fa8427d88cd8eed7ead2ceb4f1898fe2508527568', phase='post_tool', boundary={'source': 'tool_result', 'sink': 'agent_message'}, fail_mode='ALLOW_WITH_AUDIT', source_type='tool', destination_type='agent', components={'source': {'entity_type': 'agent', 'file_path': 'backend/agents/scheduling_agent.py', 'line': 23, 'name': 'amazon.nova-lite-v1:0', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_elgreoHPPlPJqb7M'}, 'invocation': {'file': 'backend/agents/scheduling_agent.py', 'function': 'SchedulingAgent.handle', 'line': 49}, 'destination': {'entity_type': 'mcp_server', 'file_path': 'backend/agents/scheduling_agent.py', 'line': 71, 'name': 'slack', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_elgreoHPPlPJqb7M'}, 'file': 'backend/agents/scheduling_agent.py', 'line': 49, 'function': 'handle', 'agent_name': 'SchedulingAgent', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:17f72bb7dd352a82'})
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            mcp_activity = await _gr_client.aenforce(_gr_site, mcp_activity, content_type='application/json', variable_name='mcp_activity', source_file=__file__, before_line=49)
        except _gr_client.GuardrailUnavailableError:
            pass

        response = (
            f"Meeting reference: {meeting_reference}\n"
            f"Scheduling request: {user_message or 'No scheduling request provided.'}\n\n"
            f"Scheduling summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


scheduling_agent = SchedulingAgent()
