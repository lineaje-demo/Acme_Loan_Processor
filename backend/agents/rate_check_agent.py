"""Rate Check Agent class with explicit OpenRouter + DeepSeek invocation."""
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


import logging
import os
import re
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient

from .framework import AcmeLoanAgentFramework

logger = logging.getLogger(__name__)


class RateCheckAgent(AcmeLoanAgentFramework):
    AGENT_ID = "rate_check_agent"
    AGENT_NAME = "Rate_Check Agent"
    VERSION = "1.0.0"
    # Vulnerability: this agent runs on DeepSeek, which is NOT on the
    # organization's approved LLM list (AI_APP_SEC_006).
    OPENROUTER_MODEL = "deepseek/deepseek-r1"
    MODEL_NAME = "deepseek/deepseek-r1"
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Checks lending-rate questions using DeepSeek through OpenRouter."
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Answer rate-check questions with short, practical lending-rate guidance."
    IS_ROUTABLE = True

    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(self):
        super().__init__()
        self.openrouter_client = OpenAICompatibleClient(
            base_url=self.OPENROUTER_BASE_URL,
            api_key=os.getenv("OPENROUTER_API_KEY"),
        )

    def to_dict(self) -> dict[str, Any]:
        metadata = super().to_dict()
        metadata["provider"] = "OpenRouter"
        metadata["openrouter_base_url"] = self.OPENROUTER_BASE_URL
        metadata["openrouter_model"] = self.resolve_model()
        # LINEAJE: runtime guardrail checks `metadata` as it flows from the agent to the user interface, before it leaves the application (in RateCheckAgent.to_dict).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `metadata` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:0df19c3582f994fd226b63d4b3c50449cc5e39c6b94467c9dc70cc89cfdf4dcd'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0df19c3582f994fd226b63d4b3c50449cc5e39c6b94467c9dc70cc89cfdf4dcd', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_aUmomyAokxEUsLfi', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/rate_check_agent.py', 'line': 15, 'name': 'rate_check_agent'}, 'invocation': {'file': 'backend/agents/rate_check_agent.py', 'line': 49, 'function': 'RateCheckAgent.to_dict'}, 'file': 'backend/agents/rate_check_agent.py', 'line': 49, 'function': 'to_dict', 'agent_name': 'RateCheckAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            metadata = _gr_client.enforce(_gr_site, metadata, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return metadata

    def sanitize_user_message(self, user_message: str) -> tuple[str, bool]:
        sanitized = (user_message or "").strip() or "No rate request provided."
        suspicious_patterns = [
            re.compile(r"<!--.*?-->", re.DOTALL),
            re.compile(r"[A-Za-z0-9+/=]{24,}"),
            re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm|chmod|python\s+-c|exec|eval|subprocess)\b", re.IGNORECASE),
            re.compile(r"\bc[\W_]*u[\W_]*r[\W_]*l\b", re.IGNORECASE),
            re.compile(r"\bc[4@]rl\b|\bw[6g]et\b|\br[mn]\b", re.IGNORECASE),
        ]

        blocked = False
        for pattern in suspicious_patterns:
            if pattern.search(sanitized):
                blocked = True
                sanitized = pattern.sub("<blocked_unsafe_content>", sanitized)

        return sanitized, blocked

    def sanitize_model_output(self, model_output: str) -> str:
        safe_lines: list[str] = []
        for line in (model_output or "").splitlines():
            if re.search(r"\b(?:eval|exec|subprocess|shell\s*=\s*True|os\.system)\b", line, re.IGNORECASE):
                continue
            safe_lines.append(line)
        return "\n".join(safe_lines).strip() or "Rate summary unavailable."

    async def call_agent_model(self, user_message: str) -> str:
        model = self.resolve_model()
        if not os.getenv("OPENROUTER_API_KEY"):
            return "LLM service not configured. Please set OPENROUTER_API_KEY."
        if not model:
            return "LLM service not configured. Please set OPENROUTER_MODEL."

        _lineaje_payload = "Rate check LLM request"
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in RateCheckAgent.call_agent_model).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:1c5ab84b3fc1af40ad31a390eda6314849d3834d077e69f40bbf40f23c96917a'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1c5ab84b3fc1af40ad31a390eda6314849d3834d077e69f40bbf40f23c96917a', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_aUmomyAokxEUsLfi', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/rate_check_agent.py', 'line': 15, 'name': 'rate_check_agent'}, 'invocation': {'file': 'backend/agents/rate_check_agent.py', 'line': 84, 'function': 'RateCheckAgent.call_agent_model'}, 'file': 'backend/agents/rate_check_agent.py', 'line': 84, 'function': 'call_agent_model', 'agent_name': 'RateCheckAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            _lineaje_payload = await _gr_client.aenforce(_gr_site, _lineaje_payload, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.info(
            _lineaje_payload,
            extra={
                "agent": self.AGENT_ID,
                "model": model,
                "prompt_length": len(user_message or ""),
            },
        )
        model_output = await self.openrouter_client.chat(
            model=model,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Rate check request:\n{user_message or 'No rate request provided.'}\n\n"
                        "Provide a concise rate check summary."
                    ),
                },
            ],
            temperature=0.2,
            # deepseek-r1 spends completion tokens on a hidden reasoning pass (still
            # counted even when excluded from the reply), so leave room for both.
            max_tokens=1500,
            # deepseek-r1 via Novita often returns the answer at the end of
            # `reasoning` with `content` empty; recover it from there.
            recover_answer_from_reasoning=True,
        )
        _lineaje_payload = "Rate check LLM response"
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in RateCheckAgent.call_agent_model).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:0cb9e2b33fbd67836f82b560578a5c2f4052b3d2c840e150c54d990051d41287'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0cb9e2b33fbd67836f82b560578a5c2f4052b3d2c840e150c54d990051d41287', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_aUmomyAokxEUsLfi', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/rate_check_agent.py', 'line': 15, 'name': 'rate_check_agent'}, 'invocation': {'file': 'backend/agents/rate_check_agent.py', 'line': 112, 'function': 'RateCheckAgent.call_agent_model'}, 'file': 'backend/agents/rate_check_agent.py', 'line': 112, 'function': 'call_agent_model', 'agent_name': 'RateCheckAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            _lineaje_payload = await _gr_client.aenforce(_gr_site, _lineaje_payload, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.info(
            _lineaje_payload,
            extra={
                "agent": self.AGENT_ID,
                "model": model,
                "response_length": len(model_output or ""),
            },
        )
        # LINEAJE: runtime guardrail checks `model_output` as it flows from the agent to the user interface, before it leaves the application (in RateCheckAgent.call_agent_model).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `model_output` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:896092e51e52bd5287264ae5a196b0ac5a928f9aa60eb5890cbd5fb0b8f81ce0'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:896092e51e52bd5287264ae5a196b0ac5a928f9aa60eb5890cbd5fb0b8f81ce0', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_aUmomyAokxEUsLfi', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/rate_check_agent.py', 'line': 15, 'name': 'rate_check_agent'}, 'invocation': {'file': 'backend/agents/rate_check_agent.py', 'line': 120, 'function': 'RateCheckAgent.call_agent_model'}, 'file': 'backend/agents/rate_check_agent.py', 'line': 120, 'function': 'call_agent_model', 'agent_name': 'RateCheckAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            model_output = await _gr_client.aenforce(_gr_site, model_output, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return model_output

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        safe_user_message, blocked_unsafe_content = self.sanitize_user_message(user_message)
        prompt_message = safe_user_message
        if blocked_unsafe_content:
            prompt_message = (
                "A rate-check request contained blocked unsafe prompt content. "
                "Use only the remaining safe request details."
            )

        # LINEAJE: runtime guardrail checks `prompt_message` as it flows from the agent to the LLM, before it is sent to the model (in RateCheckAgent.handle).
        #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+2 more); sensitive values in `prompt_message` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:30aaea03eb1d3a35bc49aaf6d4a5ef84377dbc654bf1cc6c96b229b82c46d071'
        _lineaje_prompt_message_evidence = {'prompt_message': prompt_message, 'model': getattr(_lineaje_load_gr_client(), 'current_model', lambda _f: '')(__file__)}
        _gr_client = _lineaje_load_gr_client()
        _lineaje_interaction_id = _gr_client.new_interaction_id()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:30aaea03eb1d3a35bc49aaf6d4a5ef84377dbc654bf1cc6c96b229b82c46d071', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_aUmomyAokxEUsLfi', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/rate_check_agent.py', 'line': 15, 'name': 'rate_check_agent'}, 'destination': {'entity_type': 'llm', 'name': 'deepseek-r1', 'version': '', 'provider': 'deepseek'}, 'invocation': {'file': 'backend/agents/rate_check_agent.py', 'line': 132, 'function': 'RateCheckAgent.handle'}, 'file': 'backend/agents/rate_check_agent.py', 'line': 132, 'function': 'handle', 'agent_name': 'RateCheckAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True}, interaction_id=_lineaje_interaction_id)
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            _lineaje_prompt_message_evidence = await _gr_client.aenforce(_gr_site, _lineaje_prompt_message_evidence, content_type='application/json')
            prompt_message = _lineaje_prompt_message_evidence.get('prompt_message', prompt_message) if isinstance(_lineaje_prompt_message_evidence, dict) else prompt_message
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        model_output = self.sanitize_model_output(await self.call_agent_model(prompt_message))
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:edfb9365daf1039787bedb07cdbf6a24ab3ee7dbf14348f4a6af479a42babece', phase='', boundary={}, fail_mode='ALLOW', source_type='llm', destination_type='agent', components={'file': 'backend/agents/rate_check_agent.py', 'line': 132, 'function': 'handle', 'agent_name': 'RateCheckAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.sanitize_model_output', 'source': {'entity_type': 'agent', 'file_path': 'backend/agents/rate_check_agent.py', 'line': 15, 'name': 'rate_check_agent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_aUmomyAokxEUsLfi'}, 'destination': {'entity_type': 'llm', 'name': 'deepseek-r1', 'provider': 'deepseek', 'version': ''}, 'invocation': {'file': 'backend/agents/rate_check_agent.py', 'function': 'RateCheckAgent.handle', 'line': 132}, 'boundary_id': 'bnd:e65b1c988a3cdba3'}, observe_only=True, interaction_id=locals().get('_lineaje_interaction_id'))
            await _lineaje_obs.aenforce(_lineaje_obs_site, {'activity': 'llm_to_agent'}, content_type='application/json')
        except Exception as _lineaje_obs_err:
            [__import__('sys').__dict__.setdefault('_lineaje_gr_logged', set()).add(_k) or __import__('logging').getLogger('lineaje.guardrail').warning('Lineaje guardrail: an observe-only report failed (%s); later failures of this kind are not logged', _k[1]) for _k in [('observe', type(_lineaje_obs_err).__name__)] if _k not in __import__('sys').__dict__.setdefault('_lineaje_gr_logged', set())]

        response = (
            f"Using model: {self.resolve_model()}\n\n"
            f"Rate check request: {safe_user_message}\n\n"
            f"Rate summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.resolve_model(),
            "framework": self.FRAMEWORK_NAME,
            "provider": "OpenRouter",
        }


rate_check_agent = RateCheckAgent()
