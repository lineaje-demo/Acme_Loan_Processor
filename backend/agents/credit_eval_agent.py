"""Credit Eval Agent class with explicit model invocation."""
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
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:c3f4d3e61931bf32dc58dffde5826cc0374a4e179178924fcc78ffb8b2c2720e', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/credit_eval_agent.py', 'line': 17, 'name': 'CreditEvalAgent'}, 'invocation': {'file': 'backend/agents/credit_eval_agent.py', 'line': 61, 'function': 'CreditEvalAgent.call_agent_model'}, 'file': 'backend/agents/credit_eval_agent.py', 'line': 61, 'function': 'call_agent_model', 'agent_name': 'CreditEvalAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
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
        model_output = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Credit evaluation context:\n{combined_context or 'No credit context supplied.'}\n\n"
                        "Provide a short underwriting note."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        )
        _lineaje_payload = "Credit eval LLM response"
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in CreditEvalAgent.call_agent_model).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:1dd406088094564d4e72f9acf6be87b3e87b1eeea36271e0c76e11b147121ff2'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1dd406088094564d4e72f9acf6be87b3e87b1eeea36271e0c76e11b147121ff2', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/credit_eval_agent.py', 'line': 17, 'name': 'CreditEvalAgent'}, 'invocation': {'file': 'backend/agents/credit_eval_agent.py', 'line': 84, 'function': 'CreditEvalAgent.call_agent_model'}, 'file': 'backend/agents/credit_eval_agent.py', 'line': 84, 'function': 'call_agent_model', 'agent_name': 'CreditEvalAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
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
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a9b3b6a8a5b51cc1a08909ba41ef94c00ddbe783c10586f36ba8fa5d2fcd7ecf', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'file_path': 'backend/agents/credit_eval_agent.py', 'line': 17, 'name': 'CreditEvalAgent'}, 'invocation': {'file': 'backend/agents/credit_eval_agent.py', 'line': 92, 'function': 'CreditEvalAgent.call_agent_model'}, 'file': 'backend/agents/credit_eval_agent.py', 'line': 92, 'function': 'call_agent_model', 'agent_name': 'CreditEvalAgent', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            model_output = _gr_client.enforce(_gr_site, model_output, content_type='text/plain')
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
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:6144ef2d6029f487947e23c6ea756ed80b820c06e3e6eaffb1e7062dd32d566a', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'source': {'entity_type': 'agent', 'file_path': 'backend/agents/credit_eval_agent.py', 'line': 17, 'name': 'CreditEvalAgent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd'}, 'destination': {'entity_type': 'llm', 'name': 'llama-4-scout', 'provider': 'meta-llama', 'version': ''}, 'invocation': {'file': 'backend/agents/credit_eval_agent.py', 'function': 'CreditEvalAgent.handle', 'line': 107}, 'file': 'backend/agents/credit_eval_agent.py', 'line': 107, 'function': 'handle', 'agent_name': 'CreditEvalAgent', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:f53a83c212614b92'}, interaction_id=_lineaje_interaction_id)
        try:
            _lineaje_safe_combined_context_evidence = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_safe_combined_context_evidence, content_type='application/json'))
            safe_combined_context = _lineaje_safe_combined_context_evidence.get('safe_combined_context', safe_combined_context) if isinstance(_lineaje_safe_combined_context_evidence, dict) else safe_combined_context
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        model_output = self.sanitize_model_output(await self.call_agent_model(safe_combined_context))
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:47752653b1f75c9b3cc38a35f1c3f62620d3ba6bda7c5b4a1360652e151c0934', phase='', boundary={}, fail_mode='ALLOW', source_type='llm', destination_type='agent', components={'file': 'backend/agents/credit_eval_agent.py', 'line': 107, 'function': 'handle', 'agent_name': 'CreditEvalAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.sanitize_model_output', 'source': {'entity_type': 'agent', 'file_path': 'backend/agents/credit_eval_agent.py', 'line': 17, 'name': 'CreditEvalAgent', 'repository_uri': 'https://github.com/lineaje-demo/acme_loan_processor', 'unique_org_id': 'vdna_M2wY8AcOeYFae2vd'}, 'destination': {'entity_type': 'llm', 'name': 'mistral.mistral-7b-instruct-v0:2', 'provider': 'mistral', 'version': ''}, 'invocation': {'file': 'backend/agents/credit_eval_agent.py', 'function': 'CreditEvalAgent.handle', 'line': 107}, 'boundary_id': 'bnd:1394997bc1bd9da3'}, observe_only=True, interaction_id=locals().get('_lineaje_interaction_id'))
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'llm_to_agent'}, content_type='application/json'))
        except Exception:
            pass

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
