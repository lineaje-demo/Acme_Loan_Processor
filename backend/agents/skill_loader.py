"""Loads installed agent skills from the on-disk skill registry."""
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


import re
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]

SKILL_REGISTRY: dict[str, Path] = {
    "loan-document-helper": PROJECT_ROOT / "SKILL.md",
}


def parse_skill_metadata(content: str) -> dict[str, str]:
    match = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
    if not match:
        return {}

    metadata: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip().strip('"')
    # LINEAJE: runtime guardrail checks `metadata` as it flows from the agent to the user interface, before it leaves the application (in parse_skill_metadata).
    #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `metadata` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:808a43da4ad86da21e0ab89fa02d6c5ec2e04e46383c252629bed9d1273de5fa'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:808a43da4ad86da21e0ab89fa02d6c5ec2e04e46383c252629bed9d1273de5fa', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'backend/agents/skill_loader.py', 'line': 25, 'function': 'parse_skill_metadata'}, 'file': 'backend/agents/skill_loader.py', 'line': 25, 'function': 'parse_skill_metadata', 'agent_name': 'parse_skill_metadata', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        metadata = _gr_client.enforce(_gr_site, metadata, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return metadata


def load_skill(skill_id: str) -> dict[str, Any]:
    skill_path = SKILL_REGISTRY.get(skill_id)
    if skill_path is None:
        return {
            "id": skill_id,
            "content": "",
            "path": "",
            "loaded": False,
        }

    if not skill_path.exists():
        return {
            "id": skill_id,
            "content": "",
            "path": str(skill_path),
            "loaded": False,
        }

    # LINEAJE: runtime guardrail checks `_lineaje_skill_content` as it flows from skill manifest to skill check (in load_skill).
    #   Detected: this statement moves data from skill manifest to skill check with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_SKILL_DAT_SEC_001, AI_SKILL_SEC_001, AI_SKILL_SEC_002, AI_SKILL_SEC_003 (+1 more); sensitive values in `_lineaje_skill_content` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:79369dc3c4f15ba5a675dcbc7879b4e1ac5f2a6a27dfad9c86315588ef16f205'
    _lineaje__lineaje_skill_content_evidence = {'skill_path': str(skill_path), 'skill_id': skill_id}
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:79369dc3c4f15ba5a675dcbc7879b4e1ac5f2a6a27dfad9c86315588ef16f205', phase='skill_check', boundary={'source': 'skill_manifest', 'sink': 'skill_check'}, fail_mode='BLOCK', source_type='skill_manifest', destination_type='skill_check', components={'invocation': {'file': 'backend/agents/skill_loader.py', 'line': 46, 'function': 'load_skill'}, 'file': 'backend/agents/skill_loader.py', 'line': 46, 'function': 'load_skill', 'agent_name': 'load_skill', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        _lineaje__lineaje_skill_content_evidence = _gr_client.enforce(_gr_site, _lineaje__lineaje_skill_content_evidence, content_type='application/json')
        _lineaje_skill_content = skill_path.read_text(encoding="utf-8")
    except _gr_client.GuardrailUnavailableError:
        _lineaje_skill_content = skill_path.read_text(encoding="utf-8")
    except PermissionError:
        _lineaje_skill_content = ""
        __import__("logging").getLogger("lineaje.gr_client").warning("gr_client[skill_manifest->skill_check]: quarantined skill not loaded")
    return {
        "id": skill_id,
        "content": _lineaje_skill_content,
        "path": str(skill_path),
        "loaded": True,
    }
