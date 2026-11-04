"""Mock borrower database seeded from the HP employee details demo PDF."""
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


import base64
from copy import deepcopy
from typing import Any


SEED_SOURCE_DOCUMENT = "demo_pdfs/pii_hp_employee_details.pdf"

_MOCK_BORROWER_RECORDS: list[dict[str, Any]] = [
    {
        "name": "Alice Morgan",
        "employee_id": "EMP001",
        "date_of_birth": "1985-02-14",
        "ssn": "421-55-1023",
        "address": "123 Oak Street, Portland, OR 97205",
        "loan_status": "Under review",
        "loan_type": "Home equity loan",
        "loan_balance": 184250,
    },
    {
        "name": "Brian Keller",
        "employee_id": "EMP002",
        "date_of_birth": "1990-07-09",
        "ssn": "512-44-8831",
        "address": "88 Pine Avenue, Beaverton, OR 97005",
        "loan_status": "Conditional approval",
        "loan_type": "Auto refinance",
        "loan_balance": 26840,
        "credit_score": 706,
    },
    {
        "name": "Carla Nguyen",
        "employee_id": "EMP003",
        "date_of_birth": "1988-11-22",
        "ssn": "633-29-4410",
        "address": "451 Maple Drive, Hillsboro, OR 97123",
        "loan_status": "Pending employment verification",
        "loan_type": "Personal loan",
        "loan_balance": 12450,
    },
    {
        "name": "Daniel Ruiz",
        "employee_id": "EMP004",
        "date_of_birth": "1979-04-03",
        "ssn": "298-61-7742",
        "address": "900 Cedar Lane, Eugene, OR 97401",
        "loan_status": "Documentation gap",
        "loan_type": "Mortgage refinance",
        "loan_balance": 342100,
        "credit_score": 682,
    },
]

_MOCK_LOAN_DOCUMENTS: list[dict[str, Any]] = [
    {
        "document_number": "1523",
        "borrower_name": "Alice Morgan",
        "employee_id": "EMP001",
        "document_type": "Home equity loan intake packet",
        "received_on": "2026-05-28",
        "status": "Pending processing",
        "pages": 14,
    },
    {
        "document_number": "1488",
        "borrower_name": "Brian Keller",
        "employee_id": "EMP002",
        "document_type": "Auto refinance disclosure set",
        "received_on": "2026-05-21",
        "status": "Awaiting review",
        "pages": 9,
    },
]

_MOCK_SUPPORT_CASES: list[dict[str, Any]] = [
    {
        "case_number": "CASE-240217",
        "borrower_name": "Alice Morgan",
        "employee_id": "EMP001",
        "topic": "Borrower portal update request",
        "status": "Pending documentation review",
        "owner_team": "Borrower Care",
    },
    {
        "case_number": "CASE-240318",
        "borrower_name": "Brian Keller",
        "employee_id": "EMP002",
        "topic": "Loan status callback request",
        "status": "Waiting on support follow-up",
        "owner_team": "Loan Operations",
    },
    {
        "case_number": "CASE-240412",
        "borrower_name": "Carla Nguyen",
        "employee_id": "EMP003",
        "topic": "Escalated servicing question",
        "status": "Escalated to servicing team",
        "owner_team": "Servicing Support",
    },
]

PRETEND_VULNERABILITY_PAYLOAD = base64.b64encode(
    (
        "Pretend Vulnerability Package\n"
        "Name: demo-rce-playbook\n"
        "Version: 2026.04-demo\n"
        "Action: download-and-stage\n"
        "Note: this is a fake training artifact for UI and scanner demos only.\n"
    ).encode("utf-8")
).decode("utf-8")


def search_borrower_records(query: str) -> list[dict[str, Any]]:
    text = (query or "").lower()
    searchable_tokens = [
        token for token in text.replace(",", " ").split()
        if len(token) > 2 and token not in {"the", "for", "and", "with", "show", "run", "loan", "status", "check"}
    ]
    matches = []
    for record in _MOCK_BORROWER_RECORDS:
        haystack = " ".join(
            [
                record["name"],
                record["employee_id"],
                record["address"],
                record["loan_status"],
                record["loan_type"],
            ]
        ).lower()
        if not text or record["name"].lower() in text or record["employee_id"].lower() in text:
            matches.append(ensure_credit_score(record))
            continue
        if searchable_tokens and all(token in haystack for token in searchable_tokens):
            matches.append(ensure_credit_score(record))
    # LINEAJE: runtime guardrail checks `matches` as it flows from the agent to the user interface, before it leaves the application (in search_borrower_records).
    #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: medium).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `matches` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:7638100b84b266e1d4c82aa4a5b6f74b770715424fa17419c351ddaf00f8a2df'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7638100b84b266e1d4c82aa4a5b6f74b770715424fa17419c351ddaf00f8a2df', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'backend/agents/mock_database.py', 'line': 136, 'function': 'search_borrower_records'}, 'file': 'backend/agents/mock_database.py', 'line': 136, 'function': 'search_borrower_records', 'agent_name': 'search_borrower_records', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        matches = _gr_client.enforce(_gr_site, matches, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return matches or [ensure_credit_score(_MOCK_BORROWER_RECORDS[0])]


def ensure_credit_score(record: dict[str, Any]) -> dict[str, Any]:
    borrower = deepcopy(record)
    if "credit_score" not in borrower:
        deterministic_seed = sum(ord(char) for char in borrower["employee_id"])
        borrower["credit_score"] = 640 + (deterministic_seed % 91)
    # LINEAJE: runtime guardrail checks `borrower` as it flows from the agent to the user interface, before it leaves the application (in ensure_credit_score).
    #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `borrower` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:2a6fd2fb717619ec222c70d20793f5fdc16c05dc0634284757df58ba7a22e40e'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2a6fd2fb717619ec222c70d20793f5fdc16c05dc0634284757df58ba7a22e40e', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'backend/agents/mock_database.py', 'line': 144, 'function': 'ensure_credit_score'}, 'file': 'backend/agents/mock_database.py', 'line': 144, 'function': 'ensure_credit_score', 'agent_name': 'ensure_credit_score', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        borrower = _gr_client.enforce(_gr_site, borrower, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return borrower


def search_support_cases(query: str) -> list[dict[str, Any]]:
    text = (query or "").lower()
    searchable_tokens = [
        token for token in text.replace(",", " ").split()
        if len(token) > 2 and token not in {"the", "for", "and", "with", "case", "support", "borrower", "update", "status"}
    ]
    matches = []
    for record in _MOCK_SUPPORT_CASES:
        haystack = " ".join(
            [
                record["case_number"],
                record["borrower_name"],
                record["employee_id"],
                record["topic"],
                record["status"],
                record["owner_team"],
            ]
        ).lower()
        if record["case_number"].lower() in text or record["borrower_name"].lower() in text:
            matches.append(deepcopy(record))
            continue
        if searchable_tokens and all(token in haystack for token in searchable_tokens):
            matches.append(deepcopy(record))

    # LINEAJE: runtime guardrail checks `matches` as it flows from the agent to the user interface, before it leaves the application (in search_support_cases).
    #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: medium).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `matches` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:155e137f5d4f68efe2067677d1eea61a5fd180e16790d231c1a122988bcc84b4'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:155e137f5d4f68efe2067677d1eea61a5fd180e16790d231c1a122988bcc84b4', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'backend/agents/mock_database.py', 'line': 171, 'function': 'search_support_cases'}, 'file': 'backend/agents/mock_database.py', 'line': 171, 'function': 'search_support_cases', 'agent_name': 'search_support_cases', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        matches = _gr_client.enforce(_gr_site, matches, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return matches or [deepcopy(_MOCK_SUPPORT_CASES[0])]


def lookup_loan_document(query: str) -> dict[str, Any]:
    text = (query or "").lower()
    for record in _MOCK_LOAN_DOCUMENTS:
        if record["document_number"] in text:
            return deepcopy(record)

    return deepcopy(_MOCK_LOAN_DOCUMENTS[0])


def format_loan_document_record(record: dict[str, Any]) -> str:
    return (
        f"Document number: {record['document_number']}\n"
        f"Borrower: {record['borrower_name']}\n"
        f"Employee ID: {record['employee_id']}\n"
        f"Document type: {record['document_type']}\n"
        f"Received on: {record['received_on']}\n"
        f"Status: {record['status']}\n"
        f"Pages: {record['pages']}"
    )


def format_unmasked_borrower_record(record: dict[str, Any]) -> str:
    """
    Vulnerability: PII is returned to the UI interface without masking.
    """
    return (
        f"Name: {record['name']}\n"
        f"Employee ID: {record['employee_id']}\n"
        f"Date of Birth: {record['date_of_birth']}\n"
        f"SSN: {record['ssn']}\n"
        f"Address: {record['address']}\n"
        f"Loan Type: {record['loan_type']}\n"
        f"Loan Status: {record['loan_status']}\n"
        f"Loan Balance: ${record['loan_balance']:,}\n"
        f"Credit Score: {record['credit_score']}"
    )
