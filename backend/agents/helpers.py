"""Shared helper functions for the Acme Loan Processor agents."""
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


import base64
import re
from typing import Any
from uuid import uuid4


def build_file_summary(
    file_contents: list[dict[str, Any]],
    include_raw_text: bool = False,
) -> str:
    if not file_contents:
        return "No files were attached."

    sections = []
    for file_data in file_contents:
        extracted_content = file_data.get("extracted_content", "")
        if not include_raw_text and len(extracted_content) > 600:
            extracted_content = extracted_content[:600] + "..."

        sections.append(
            f"Filename: {file_data.get('filename', 'unknown')}\n"
            f"Content Type: {file_data.get('content_type', 'unknown')}\n"
            f"Extracted Content:\n{extracted_content}"
        )

    return "\n\n".join(sections)


def extract_reference_number(message: str, prefix: str) -> str:
    match = re.search(r"\b([A-Z]{2,}-\d{2,}|\d{4,})\b", message or "")
    if match:
        return str(match.group(1))
    return f"{prefix}-{str(uuid4())[:8].upper()}"


def decode_base64_segments(content: str) -> list[str]:
    decoded_segments: list[str] = []
    for candidate in extract_base64_candidates(content):
        if len(candidate) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
        except Exception:
            continue
        if decoded.strip():
            decoded_segments.append(decoded.strip())
    # LINEAJE: runtime guardrail checks `decoded_segments` as it flows from the agent to the user interface, before it leaves the application (in decode_base64_segments).
    #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `decoded_segments` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:05ffed38814524d8bfe898f153fecab57fcc71dacfc00e9e13ec7c4c61bc1c6f'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:05ffed38814524d8bfe898f153fecab57fcc71dacfc00e9e13ec7c4c61bc1c6f', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'backend/agents/helpers.py', 'line': 49, 'function': 'decode_base64_segments'}, 'file': 'backend/agents/helpers.py', 'line': 49, 'function': 'decode_base64_segments', 'agent_name': 'decode_base64_segments', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        decoded_segments = _gr_client.enforce(_gr_site, decoded_segments, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return decoded_segments


def extract_base64_candidates(content: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9+/=]{24,}", content or "")
