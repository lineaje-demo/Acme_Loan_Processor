"""Thin runtime registry that ties the separated agent files together."""
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


from copy import deepcopy
from typing import Any

from .access_control_agent import access_control_agent
from .credit_eval_agent import credit_eval_agent
from .file_management_agent import file_management_agent
from .file_processor_agent import file_processor_agent
from .mcp_servers import MCP_SERVERS
from .orchestrator_agent import orchestrator_agent
from .rate_check_agent import rate_check_agent
from .loan_processing_agent import loan_processing_agent
from .scheduling_agent import scheduling_agent
from .installed_skill_agent import installed_skill_agent


AGENTS: dict[str, Any] = {
    loan_processing_agent.AGENT_NAME: loan_processing_agent,
    file_processor_agent.AGENT_NAME: file_processor_agent,
    file_management_agent.AGENT_NAME: file_management_agent,
    access_control_agent.AGENT_NAME: access_control_agent,
    credit_eval_agent.AGENT_NAME: credit_eval_agent,
    rate_check_agent.AGENT_NAME: rate_check_agent,
    orchestrator_agent.AGENT_NAME: orchestrator_agent,
    scheduling_agent.AGENT_NAME: scheduling_agent,
    installed_skill_agent.AGENT_NAME: installed_skill_agent,
}


def build_catalog() -> dict[str, Any]:
    return {
        "agents": deepcopy([agent.to_dict() for agent in AGENTS.values()]),
        "mcp_servers": deepcopy(list(MCP_SERVERS.values())),
    }


async def handle_chat_request(context: dict[str, Any]) -> dict[str, Any]:
    return await orchestrator_agent.handle(context)


async def process_file_attachment(
    content: str | None,
    filename: str,
    content_type: str,
) -> dict[str, Any]:
    # LINEAJE: runtime guardrail checks `content` as it flows from file storage to the agent (in process_file_attachment).
    #   Detected: this statement moves data from file storage to the agent with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_APP_SEC_070, AI_DAT_SEC_023, AI_DAT_SEC_024; sensitive values in `content` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:7fbf351abad2dec2f1c8a6f531e0151db0a93a6d39c11a3d633575a47bb51135'
    _lineaje_content_evidence = {'content': content, 'name': filename, 'content_type': content_type}
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7fbf351abad2dec2f1c8a6f531e0151db0a93a6d39c11a3d633575a47bb51135', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, fail_mode='BLOCK', source_type='file_storage', destination_type='agent', components={'invocation': {'file': 'backend/agents/runtime.py', 'line': 47, 'function': 'process_file_attachment'}, 'file': 'backend/agents/runtime.py', 'line': 47, 'function': 'process_file_attachment', 'agent_name': 'process_file_attachment', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
            __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
            raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
        _lineaje_content_evidence = await _gr_client.aenforce(_gr_site, _lineaje_content_evidence, content_type='application/json')
        content = _lineaje_content_evidence.get('content', content) if isinstance(_lineaje_content_evidence, dict) else content
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        raise
    return await file_processor_agent.process_attachment(content, filename, content_type)
