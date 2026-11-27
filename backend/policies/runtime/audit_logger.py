"""
Audit Logger

Provides audit logging for security-relevant events.

SECURITY NOTES (for Unifai demo):
- Minimal logging implementation
- No secure audit trail
- No tamper-proof storage
- No compliance reporting
"""
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
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Audit logging for security events.

    VULNERABILITY: Audit logging is minimal and not suitable
    for security compliance.

    Should provide:
    - Tamper-proof audit trail
    - Compliance reporting
    - Alert integration
    - Long-term retention
    """

    def __init__(self):
        self._events = []  # In-memory only - not persistent

    async def log_event(
        self,
        event_type: str,
        details: dict[str, Any],
        user_id: Optional[str] = None,
        severity: str = "info"
    ) -> None:
        """
        Log a security-relevant event.

        VULNERABILITY: Only logs to local logger, no secure audit trail.
        """
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": event_type,
            "details": details,
            "user_id": user_id,
            "severity": severity
        }

        self._events.append(event)

        # VULNERABILITY: Only local logging
        _lineaje_payload = f"Audit: {event_type}"
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in AuditLogger.log_event).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:edda7efe4a034fbf983348b66a04e78e877fe60540694fe14aea3cc12e99431e'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:edda7efe4a034fbf983348b66a04e78e877fe60540694fe14aea3cc12e99431e', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'backend/policies/runtime/audit_logger.py', 'line': 60, 'function': 'AuditLogger.log_event'}, 'file': 'backend/policies/runtime/audit_logger.py', 'line': 60, 'function': 'log_event', 'agent_name': 'AuditLogger', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
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
            extra=event
        )

    async def log_policy_violation(
        self,
        policy_type: str,
        violation_details: dict
    ) -> None:
        """
        Log a policy violation.

        VULNERABILITY: Violations logged but no alerting.
        """
        await self.log_event(
            event_type="policy_violation",
            details={
                "policy": policy_type,
                **violation_details
            },
            severity="warning"
        )

    async def log_data_access(
        self,
        resource: str,
        action: str,
        user_id: str
    ) -> None:
        """
        Log data access for compliance.

        VULNERABILITY: Minimal implementation.
        """
        await self.log_event(
            event_type="data_access",
            details={
                "resource": resource,
                "action": action
            },
            user_id=user_id
        )

    def get_recent_events(self, count: int = 100) -> list[dict]:
        """Get recent audit events (for debugging only)."""
        return self._events[-count:]
