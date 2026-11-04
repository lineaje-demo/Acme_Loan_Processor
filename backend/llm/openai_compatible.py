"""
OpenAI-compatible model gateway client.

This keeps the request shape real and makes the selected model visible in each
agent file via the `model=` argument on every call.
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


import asyncio
import logging
import os
import re
import time
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

# Retry transient upstream failures (5xx / gateway timeouts / connection
# resets / empty completions). meta-llama/llama-4-scout on OpenRouter
# occasionally returns a 504 Gateway Timeout, and deepseek/deepseek-r1 (only
# served by Novita) sometimes finishes with an empty `content`.
_MAX_ATTEMPTS = 4
_RETRY_BACKOFF_SEC = 1.5
# Reasoning models such as deepseek-r1 take 15-30s per call.
_REQUEST_TIMEOUT_SEC = 90


def _extract_content(message: dict[str, Any]) -> str:
    """Return the assistant text from a chat-completions message, accepting
    either a plain string or a list of content parts."""
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = [
            part.get("text", "") if isinstance(part, dict) else str(part)
            for part in content
        ]
        return "".join(parts).strip()
    return ""


_HERE_IS_ANSWER = re.compile(r"here(?:'s| is| are)\b", re.IGNORECASE)
_FORMATTED_PARAGRAPH = re.compile(r"(?:\*\*|#{1,6}\s|[-*]\s|\d+\.\s)")
_MIN_RECOVERED_ANSWER_CHARS = 40


def _answer_from_reasoning(reasoning: str) -> str:
    """Recover the final answer when a reasoning model returns it inside
    `reasoning` instead of `content` (Novita's deepseek-r1 does this: the
    thinking and the answer arrive as one block, answer last).

    Takes everything from the last "Here's / Here is ..." paragraph, else the
    trailing run of markdown-formatted paragraphs. Returns "" if neither is
    found, so the caller can retry."""
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", reasoning or "") if p.strip()]
    answer = ""
    for index in range(len(paragraphs) - 1, -1, -1):
        if _HERE_IS_ANSWER.match(paragraphs[index]):
            answer = "\n\n".join(paragraphs[index:])
            break
    else:
        start = len(paragraphs)
        while start > 0 and _FORMATTED_PARAGRAPH.match(paragraphs[start - 1]):
            start -= 1
        answer = "\n\n".join(paragraphs[start:])
    return answer if len(answer) >= _MIN_RECOVERED_ANSWER_CHARS else ""


class OpenAICompatibleClient:
    """Minimal async wrapper around a chat-completions style API."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        # Use OpenRouter credentials from the environment.
        self.base_url = (
            base_url
            or os.getenv("OPENROUTER_BASE_URL")
            or "https://openrouter.ai/api/v1"
        ).rstrip("/")
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")

    async def chat(
        self,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 400,
        recover_answer_from_reasoning: bool = False,
    ) -> str:
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        def _post() -> str:
            last_exc: Optional[Exception] = None
            empty_responses = 0
            for attempt in range(1, _MAX_ATTEMPTS + 1):
                try:
                    _lineaje_json = payload
                    # LINEAJE: runtime guardrail checks `_lineaje_json` as it flows from the agent to the LLM, before it is sent to the model (in OpenAICompatibleClient._post).
                    #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: medium).
                    #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+2 more); sensitive values in `_lineaje_json` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                    #   Do not remove without review. site_id='site:sha256:c6dbb7ec338ef23de28b011d24a29577cb560971803db0cd0dacb6694589d019'
                    _gr_client = _lineaje_load_gr_client()
                    _lineaje_interaction_id = _gr_client.new_interaction_id()
                    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:c6dbb7ec338ef23de28b011d24a29577cb560971803db0cd0dacb6694589d019', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'invocation': {'file': 'backend/llm/openai_compatible.py', 'function': 'OpenAICompatibleClient.chat._post', 'line': 111}, 'file': 'backend/llm/openai_compatible.py', 'line': 111, 'function': '_post', 'agent_name': 'OpenAICompatibleClient', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:b65a5c12a82989c3'}, interaction_id=_lineaje_interaction_id)
                    try:
                        if getattr(_gr_client, 'STUB_API', 0) < 3:
                            __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates enforce_request (STUB_API 3): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                            raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no enforce_request")
                        _lineaje_json = _gr_client.enforce_request(_gr_site, _lineaje_json, content_type='application/json', evidence={'model': (getattr(_lineaje_load_gr_client(), 'header_model', None) or (lambda h: None))(headers), 'model_source': 'header'})
                    except _gr_client.GuardrailUnavailableError:
                        pass
                    except PermissionError:
                        raise
                    response = requests.post(
                        f"{self.base_url}/chat/completions",
                        json=_lineaje_json,
                        headers=headers,
                        timeout=_REQUEST_TIMEOUT_SEC,
                    )
                    # LINEAJE: runtime guardrail checks `response` as it flows from the LLM to the agent, after the model replies (in OpenAICompatibleClient._post).
                    #   Detected: this statement moves data from the LLM to the agent with no runtime policy check (detection confidence: medium).
                    #   Decision: the Guardrail evaluates AI_DAT_SEC_011, AI_DAT_SEC_025, AI_DAT_SEC_027, AI_DAT_SEC_029; sensitive values in `response` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                    #   Do not remove without review. site_id='site:sha256:9d3d7ff8b6931555bc184da87e71c1a0984e8e02536cfb110b2f0ff365189446'
                    _gr_client = _lineaje_load_gr_client()
                    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9d3d7ff8b6931555bc184da87e71c1a0984e8e02536cfb110b2f0ff365189446', phase='post_model', boundary={'source': 'model', 'sink': 'agent_message'}, fail_mode='BLOCK', source_type='llm', destination_type='agent', components={'invocation': {'file': 'backend/llm/openai_compatible.py', 'function': 'OpenAICompatibleClient.chat._post', 'line': 111}, 'file': 'backend/llm/openai_compatible.py', 'line': 111, 'function': '_post', 'agent_name': 'OpenAICompatibleClient', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:b65a5c12a82989c3'}, interaction_id=locals().get('_lineaje_interaction_id'))
                    try:
                        if not hasattr(_gr_client, 'enforce_reply'):
                            __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates enforce_reply (STUB_API 2): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                            raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no enforce_reply")
                        response = _gr_client.enforce_reply(_gr_site, response, content_type='application/json')
                    except _gr_client.GuardrailUnavailableError:
                        pass
                    response.raise_for_status()
                    data = response.json()
                    choices = data.get("choices") or []
                    message = (choices[0].get("message") or {}) if choices else {}
                    content = _extract_content(message)
                    if not content and recover_answer_from_reasoning:
                        content = _answer_from_reasoning(message.get("reasoning") or "")
                        if content:
                            _lineaje_payload = "Recovered answer from the reasoning field"
                            # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in OpenAICompatibleClient._post).
                            #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                            #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                            #   Do not remove without review. site_id='site:sha256:c3bbe445b49347f82d66ab5734bf0e9e4427ac3ddbd1047479984e61ba8762f0'
                            _gr_client = _lineaje_load_gr_client()
                            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:c3bbe445b49347f82d66ab5734bf0e9e4427ac3ddbd1047479984e61ba8762f0', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'backend/llm/openai_compatible.py', 'line': 125, 'function': 'OpenAICompatibleClient.chat._post'}, 'file': 'backend/llm/openai_compatible.py', 'line': 125, 'function': '_post', 'agent_name': 'OpenAICompatibleClient', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                            try:
                                _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
                            except _gr_client.GuardrailUnavailableError:
                                pass
                            except PermissionError:
                                pass
                            logger.info(
                                _lineaje_payload,
                                extra={"model": model, "provider": data.get("provider")},
                            )
                    if content:
                        # LINEAJE: runtime guardrail checks `content` as it flows from the agent to the user interface, before it leaves the application (in OpenAICompatibleClient._post).
                        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
                        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `content` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                        #   Do not remove without review. site_id='site:sha256:f94e47468454f7b574d9016a4c29e82063aca4e1a98e820468e23728be58df80'
                        _gr_client = _lineaje_load_gr_client()
                        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:f94e47468454f7b574d9016a4c29e82063aca4e1a98e820468e23728be58df80', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'backend/llm/openai_compatible.py', 'line': 130, 'function': 'OpenAICompatibleClient.chat._post'}, 'file': 'backend/llm/openai_compatible.py', 'line': 130, 'function': '_post', 'agent_name': 'OpenAICompatibleClient', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                        try:
                            content = _gr_client.enforce(_gr_site, content, content_type='text/plain')
                        except _gr_client.GuardrailUnavailableError:
                            pass
                        except PermissionError:
                            pass
                        return content

                    # 200 OK but no answer text: transient provider behaviour,
                    # so retry instead of surfacing an empty reply.
                    empty_responses += 1
                    last_exc = None
                    if attempt < _MAX_ATTEMPTS:
                        # LINEAJE: runtime guardrail checks `attempt` as it flows from the agent to the application log, before it is written to the log (in OpenAICompatibleClient._post).
                        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `attempt` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                        #   Do not remove without review. site_id='site:sha256:5eabc0b12a1ab00b86889c52b676308ae6253da9741e402a484d8040dd3aada2'
                        _gr_client = _lineaje_load_gr_client()
                        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5eabc0b12a1ab00b86889c52b676308ae6253da9741e402a484d8040dd3aada2', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'backend/llm/openai_compatible.py', 'line': 137, 'function': 'OpenAICompatibleClient.chat._post'}, 'file': 'backend/llm/openai_compatible.py', 'line': 137, 'function': '_post', 'agent_name': 'OpenAICompatibleClient', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                        try:
                            attempt = _gr_client.enforce(_gr_site, attempt, content_type='application/json')
                        except _gr_client.GuardrailUnavailableError:
                            pass
                        except PermissionError:
                            pass
                        logger.warning(
                            "Model returned empty content — retrying (%d/%d)",
                            attempt, _MAX_ATTEMPTS,
                            extra={
                                "model": model,
                                "provider": data.get("provider"),
                                "finish_reason": choices[0].get("finish_reason") if choices else None,
                            },
                        )
                        time.sleep(_RETRY_BACKOFF_SEC * attempt)
                        continue
                    break
                except requests.HTTPError as exc:
                    last_exc = exc
                    status = exc.response.status_code if exc.response is not None else None
                    # Retry only on transient upstream 5xx (e.g. 504 gateway
                    # timeout). 4xx are caller errors — fail fast.
                    if status is not None and 500 <= status < 600 and attempt < _MAX_ATTEMPTS:
                        # LINEAJE: runtime guardrail checks `status` as it flows from the agent to the application log, before it is written to the log (in OpenAICompatibleClient._post).
                        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `status` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                        #   Do not remove without review. site_id='site:sha256:f0bdd91c9d5b8cd54b6ede4906e40f67beb653d46e1f54c9497e073010a0b221'
                        _gr_client = _lineaje_load_gr_client()
                        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:f0bdd91c9d5b8cd54b6ede4906e40f67beb653d46e1f54c9497e073010a0b221', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'backend/llm/openai_compatible.py', 'line': 155, 'function': 'OpenAICompatibleClient.chat._post'}, 'file': 'backend/llm/openai_compatible.py', 'line': 155, 'function': '_post', 'agent_name': 'OpenAICompatibleClient', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                        try:
                            status = _gr_client.enforce(_gr_site, status, content_type='application/json')
                        except _gr_client.GuardrailUnavailableError:
                            pass
                        except PermissionError:
                            pass
                        logger.warning(
                            "Model gateway %s — retrying (%d/%d)",
                            status, attempt, _MAX_ATTEMPTS,
                            extra={"model": model},
                        )
                        time.sleep(_RETRY_BACKOFF_SEC * attempt)
                        continue
                    break
                except (requests.Timeout, requests.ConnectionError) as exc:
                    last_exc = exc
                    if attempt < _MAX_ATTEMPTS:
                        # LINEAJE: runtime guardrail checks `attempt` as it flows from the agent to the application log, before it is written to the log (in OpenAICompatibleClient._post).
                        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `attempt` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                        #   Do not remove without review. site_id='site:sha256:1a40e6203763684e2b36b717286ad396ca088de2b8b2c086d06e9d1c3c291f9c'
                        _gr_client = _lineaje_load_gr_client()
                        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1a40e6203763684e2b36b717286ad396ca088de2b8b2c086d06e9d1c3c291f9c', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'backend/llm/openai_compatible.py', 'line': 166, 'function': 'OpenAICompatibleClient.chat._post'}, 'file': 'backend/llm/openai_compatible.py', 'line': 166, 'function': '_post', 'agent_name': 'OpenAICompatibleClient', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                        try:
                            attempt = _gr_client.enforce(_gr_site, attempt, content_type='application/json')
                        except _gr_client.GuardrailUnavailableError:
                            pass
                        except PermissionError:
                            pass
                        logger.warning(
                            "Model gateway network error — retrying (%d/%d): %s",
                            attempt, _MAX_ATTEMPTS, exc,
                            extra={"model": model},
                        )
                        time.sleep(_RETRY_BACKOFF_SEC * attempt)
                        continue
                    break
                except requests.RequestException as exc:
                    last_exc = exc
                    break

            if last_exc is None and empty_responses:
                _lineaje_payload = "Model returned empty content on every attempt"
                # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in OpenAICompatibleClient._post).
                #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:d86e83aa13a8c555127f1f8b59c37db2680d2f31ca6ce3eb1c6290a0a9e741e7'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d86e83aa13a8c555127f1f8b59c37db2680d2f31ca6ce3eb1c6290a0a9e741e7', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'backend/llm/openai_compatible.py', 'line': 179, 'function': 'OpenAICompatibleClient.chat._post'}, 'file': 'backend/llm/openai_compatible.py', 'line': 179, 'function': '_post', 'agent_name': 'OpenAICompatibleClient', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                try:
                    _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    pass
                logger.warning(
                    _lineaje_payload,
                    extra={"model": model, "attempts": empty_responses},
                )
                return (
                    f"{model} returned an empty response {empty_responses} times in a row. "
                    "The upstream provider is flaky right now — please try again."
                )

            _lineaje_payload = "Model gateway request failed"
            # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in OpenAICompatibleClient._post).
            #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:e425886b6161bf62b9b855a159624bffd5f8b41afeb155d11977b4358344590a'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e425886b6161bf62b9b855a159624bffd5f8b41afeb155d11977b4358344590a', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'backend/llm/openai_compatible.py', 'line': 188, 'function': 'OpenAICompatibleClient.chat._post'}, 'file': 'backend/llm/openai_compatible.py', 'line': 188, 'function': '_post', 'agent_name': 'OpenAICompatibleClient', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.warning(
                _lineaje_payload,
                extra={"model": model, "error": str(last_exc)},
            )
            return f"Model gateway unavailable for {model}: {last_exc}"

        return await asyncio.to_thread(_post)

    async def chat_vision(
        self,
        model: str,
        image_base64: str,
        mime_type: str,
        prompt: str,
        max_tokens: int = 500,
    ) -> str:
        """Send an image to a vision-capable model as an image_url content block."""
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:{mime_type};base64,{image_base64}"},
                    },
                ],
            }
        ]
        return await self.chat(model=model, messages=messages, temperature=0.0, max_tokens=max_tokens)
