"""Credit Eval Agent class with explicit model invocation."""
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
import re
from typing import Any

from .framework import AcmeLoanAgentFramework
from .mock_database import (
    SEED_SOURCE_DOCUMENT,
    format_unmasked_borrower_record,
    search_borrower_records,
)

logger = logging.getLogger(__name__)


class CreditEvalAgent(AcmeLoanAgentFramework):
    AGENT_ID = "credit_eval_agent"
    AGENT_NAME = "Credit Eval Agent"
    VERSION = "1.0.0"
    OPENROUTER_MODEL = "meta-llama/llama-4-scout"
    MODEL_NAME = "meta-llama/llama-4-scout"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = "Evaluates creditworthiness, loan status, and borrower notes for loan decisions."
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": False,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Review credit details, debt ratios, repayment risk indicators, and loan status."

    def sanitize_prompt_content(self, text: str) -> tuple[str, bool]:
        sanitized = text or ""
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
        return "\n".join(safe_lines).strip() or "Underwriting note unavailable."

    async def call_agent_model(self, combined_context: str) -> str:
        _lineaje_payload = "Credit eval LLM request"
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in CreditEvalAgent.call_agent_model).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:c3f4d3e61931bf32dc58dffde5826cc0374a4e179178924fcc78ffb8b2c2720e'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:c3f4d3e61931bf32dc58dffde5826cc0374a4e179178924fcc78ffb8b2c2720e', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_rOCYtKUfcvTLYShc', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/credit_eval_agent.py', 'line': 17, 'name': 'credit_eval_agent'}, 'invocation': {'file': 'backend/agents/credit_eval_agent.py', 'line': 61, 'function': 'CreditEvalAgent.call_agent_model'}, 'file': 'backend/agents/credit_eval_agent.py', 'line': 61, 'function': 'call_agent_model', 'agent_name': 'CreditEvalAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
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
                "model": self.BEDROCK_MODEL_ID,
                "prompt_length": len(combined_context or ""),
                "contains_pii": True,
            },
        )
        _lineaje_messages = ([
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Credit evaluation context:\n{combined_context or 'No credit context supplied.'}\n\n"
                        "Provide a short underwriting note."
                    ),
                },
            ])
        # LINEAJE: runtime guardrail checks `_lineaje_messages` as it flows from the agent to the LLM, before it is sent to the model (in CreditEvalAgent.call_agent_model).
        #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+2 more); sensitive values in `_lineaje_messages` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:4cc590c618c9cfb77b8fba28047293983a1dab76920227ab5e066b31cad0a402'
        _gr_client = _lineaje_load_gr_client()
        _lineaje_interaction_id = _gr_client.new_interaction_id()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:4cc590c618c9cfb77b8fba28047293983a1dab76920227ab5e066b31cad0a402', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'source': {'entity_type': 'agent', 'file_path': 'backend/agents/credit_eval_agent.py', 'line': 17, 'name': 'credit_eval_agent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_rOCYtKUfcvTLYShc'}, 'destination': {'entity_type': 'llm', 'name': 'mistral.mistral-7b-instruct-v0:2', 'provider': 'mistral', 'version': ''}, 'invocation': {'file': 'backend/agents/credit_eval_agent.py', 'function': 'CreditEvalAgent.call_agent_model', 'line': 70}, 'file': 'backend/agents/credit_eval_agent.py', 'line': 70, 'function': 'call_agent_model', 'agent_name': 'CreditEvalAgent', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:c777c4b0f5d4929f'}, interaction_id=_lineaje_interaction_id)
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            _lineaje_messages = await _gr_client.aenforce(_gr_site, _lineaje_messages, content_type='application/json', variable_name='_lineaje_messages', source_file=__file__, before_line=70)
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        model_output = await self.call_bedrock_model(
            messages=_lineaje_messages,
            temperature=0.2,
            max_tokens=250,
        )
        # LINEAJE: runtime guardrail checks `model_output` as it flows from the LLM to the agent, after the model replies (in CreditEvalAgent.call_agent_model).
        #   Detected: this statement moves data from the LLM to the agent with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_011, AI_DAT_SEC_025, AI_DAT_SEC_027, AI_DAT_SEC_029; sensitive values in `model_output` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:06538eeb20f959c01be2e05f4f8f0e36ffd03190d71c3a5628bcb0c8272c8582'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:06538eeb20f959c01be2e05f4f8f0e36ffd03190d71c3a5628bcb0c8272c8582', phase='post_model', boundary={'source': 'model', 'sink': 'agent_message'}, fail_mode='BLOCK', source_type='llm', destination_type='agent', components={'source': {'entity_type': 'agent', 'file_path': 'backend/agents/credit_eval_agent.py', 'line': 17, 'name': 'credit_eval_agent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_rOCYtKUfcvTLYShc'}, 'destination': {'entity_type': 'llm', 'name': 'mistral.mistral-7b-instruct-v0:2', 'provider': 'mistral', 'version': ''}, 'invocation': {'file': 'backend/agents/credit_eval_agent.py', 'function': 'CreditEvalAgent.call_agent_model', 'line': 70}, 'file': 'backend/agents/credit_eval_agent.py', 'line': 70, 'function': 'call_agent_model', 'agent_name': 'CreditEvalAgent', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:c777c4b0f5d4929f'}, interaction_id=locals().get('_lineaje_interaction_id'))
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            model_output = await _gr_client.aenforce(_gr_site, model_output, content_type='application/json', variable_name='model_output', source_file=__file__, before_line=70)
        except _gr_client.GuardrailUnavailableError:
            pass
        _lineaje_payload = "Credit eval LLM response"
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in CreditEvalAgent.call_agent_model).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:1dd406088094564d4e72f9acf6be87b3e87b1eeea36271e0c76e11b147121ff2'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1dd406088094564d4e72f9acf6be87b3e87b1eeea36271e0c76e11b147121ff2', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_rOCYtKUfcvTLYShc', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/credit_eval_agent.py', 'line': 17, 'name': 'credit_eval_agent'}, 'invocation': {'file': 'backend/agents/credit_eval_agent.py', 'line': 84, 'function': 'CreditEvalAgent.call_agent_model'}, 'file': 'backend/agents/credit_eval_agent.py', 'line': 84, 'function': 'call_agent_model', 'agent_name': 'CreditEvalAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
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
                "model": self.BEDROCK_MODEL_ID,
                "response_length": len(model_output or ""),
            },
        )
        # LINEAJE: runtime guardrail checks `model_output` as it flows from the agent to the user interface, before it leaves the application (in CreditEvalAgent.call_agent_model).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `model_output` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:a9b3b6a8a5b51cc1a08909ba41ef94c00ddbe783c10586f36ba8fa5d2fcd7ecf'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a9b3b6a8a5b51cc1a08909ba41ef94c00ddbe783c10586f36ba8fa5d2fcd7ecf', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_rOCYtKUfcvTLYShc', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/credit_eval_agent.py', 'line': 17, 'name': 'credit_eval_agent'}, 'invocation': {'file': 'backend/agents/credit_eval_agent.py', 'line': 92, 'function': 'CreditEvalAgent.call_agent_model'}, 'file': 'backend/agents/credit_eval_agent.py', 'line': 92, 'function': 'call_agent_model', 'agent_name': 'CreditEvalAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
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
        borrower_records = search_borrower_records(user_message)
        borrower_record = borrower_records[0]
        borrower_record_text = format_unmasked_borrower_record(borrower_record)
        combined_context = (
            f"Seed source document: {SEED_SOURCE_DOCUMENT}\n\n"
            f"Borrower record:\n{borrower_record_text}\n\n"
            f"User request:\n{user_message}"
        ).strip()
        safe_combined_context, blocked_unsafe_content = self.sanitize_prompt_content(combined_context)
        if blocked_unsafe_content:
            safe_combined_context += "\n\nUnsafe prompt content was removed before model evaluation."
        # LINEAJE: runtime guardrail checks `safe_combined_context` as it flows from the agent to the LLM, before it is sent to the model (in CreditEvalAgent.handle).
        #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+2 more); sensitive values in `safe_combined_context` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:6144ef2d6029f487947e23c6ea756ed80b820c06e3e6eaffb1e7062dd32d566a'
        _lineaje_safe_combined_context_evidence = {'safe_combined_context': safe_combined_context, 'model': getattr(_lineaje_load_gr_client(), 'current_model', lambda _f: '')(__file__)}
        _gr_client = _lineaje_load_gr_client()
        _lineaje_interaction_id = _gr_client.new_interaction_id()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:6144ef2d6029f487947e23c6ea756ed80b820c06e3e6eaffb1e7062dd32d566a', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'source': {'entity_type': 'agent', 'file_path': 'backend/agents/credit_eval_agent.py', 'line': 17, 'name': 'credit_eval_agent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_rOCYtKUfcvTLYShc'}, 'destination': {'entity_type': 'llm', 'name': 'llama-4-scout', 'provider': 'meta-llama', 'version': ''}, 'invocation': {'file': 'backend/agents/credit_eval_agent.py', 'function': 'CreditEvalAgent.handle', 'line': 107}, 'file': 'backend/agents/credit_eval_agent.py', 'line': 107, 'function': 'handle', 'agent_name': 'CreditEvalAgent', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:580affc36bce35ca'}, interaction_id=_lineaje_interaction_id)
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            _lineaje_safe_combined_context_evidence = await _gr_client.aenforce(_gr_site, _lineaje_safe_combined_context_evidence, content_type='application/json')
            safe_combined_context = _lineaje_safe_combined_context_evidence.get('safe_combined_context', safe_combined_context) if isinstance(_lineaje_safe_combined_context_evidence, dict) else safe_combined_context
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        model_output = self.sanitize_model_output(await self.call_agent_model(safe_combined_context))
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:47752653b1f75c9b3cc38a35f1c3f62620d3ba6bda7c5b4a1360652e151c0934', phase='', boundary={}, fail_mode='ALLOW', source_type='llm', destination_type='agent', components={'file': 'backend/agents/credit_eval_agent.py', 'line': 107, 'function': 'handle', 'agent_name': 'CreditEvalAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.sanitize_model_output', 'source': {'entity_type': 'agent', 'file_path': 'backend/agents/credit_eval_agent.py', 'line': 17, 'name': 'credit_eval_agent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_rOCYtKUfcvTLYShc'}, 'destination': {'entity_type': 'llm', 'name': 'llama-4-scout', 'provider': 'meta-llama', 'version': ''}, 'invocation': {'file': 'backend/agents/credit_eval_agent.py', 'function': 'CreditEvalAgent.handle', 'line': 107}, 'boundary_id': 'bnd:580affc36bce35ca'}, observe_only=True, interaction_id=locals().get('_lineaje_interaction_id'))
            await _lineaje_obs.aenforce(_lineaje_obs_site, {'activity': 'llm_to_agent'}, content_type='application/json')
        except Exception as _lineaje_obs_err:
            [__import__('sys').__dict__.setdefault('_lineaje_gr_logged', set()).add(_k) or __import__('logging').getLogger('lineaje.guardrail').warning('Lineaje guardrail: an observe-only report failed (%s); later failures of this kind are not logged', _k[1]) for _k in [('observe', type(_lineaje_obs_err).__name__)] if _k not in __import__('sys').__dict__.setdefault('_lineaje_gr_logged', set())]

        # Vulnerability: these raw PII fields are intentionally returned to the UI
        # instead of being masked before display.
        response = (
            f"Borrower snapshot for {borrower_record['name']}\n"
            f"Loan status: {borrower_record['loan_status']}\n"
            f"Loan type: {borrower_record['loan_type']}\n"
            f"Credit score: {borrower_record['credit_score']}\n"
            f"Loan balance: ${borrower_record['loan_balance']:,}\n\n"
            "Borrower details shown in UI:\n"
            f"DOB: {borrower_record['date_of_birth']}\n"
            f"SSN: {borrower_record['ssn']}\n"
            f"Address: {borrower_record['address']}\n\n"
            f"Underwriting note:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


credit_eval_agent = CreditEvalAgent()
