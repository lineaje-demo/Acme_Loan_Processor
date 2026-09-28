# Acme Loan Assistant

**AI-powered policy evaluation and remediation demo application**

Acme Loan Assistant is a deliberately vulnerable chat agent application designed to demonstrate how Unifai detects security policy violations and instructs Cursor IDE to remediate them. The frontend presents as a lightweight AI assistant for document review and loan-related chat.

## Demo Flow

1. **Run Acme Loan Assistant with Unifai disabled** → vulnerable behavior is visible
2. **Enable Unifai in Cursor** → scans code, detects violations
3. **Unifai instructs Cursor** to fix the violations
4. **Run Acme Loan Assistant again** → guardrails now active, violations blocked

## Four Policy Violations Demonstrated

| Policy | Vulnerability | After Remediation |
|--------|---------------|-------------------|
| **PII Detection** | Files processed without PII scanning | SSN, credit cards, phone numbers detected and blocked |
| **Prompt Injection** | Hidden text/prompts sent to LLM | Hidden content detected and filtered |
| **Agent Auth** | Inter-agent calls bypass authentication | JWT-based authentication required |
| **Vulnerable Deps** | Old packages with known CVEs | Updated to patched versions |

## Quick Start

### Option A: Docker (recommended)

**Prerequisites:** Docker and an [OpenRouter](https://openrouter.ai/keys) API key

1. **Build the image**

```bash
docker build -t acme-loan-processor:local .
```

2. **Run the container**

```bash
docker run -d \
  --name acme-loan-processor \
  -p 80:5001 \
  -e OPENROUTER_API_KEY=your_openrouter_api_key \
  -e OPENROUTER_MODEL=meta-llama/llama-4-scout \
  -e AGENT_SECRET=your_random_secret \
  acme-loan-processor:local
```

3. **Open the app** at http://localhost (Acme Loan Assistant interface)

---

### Option B: Local Development

**Prerequisites:**

- Node.js 18+
- Python 3.10+
- OpenRouter API key (`OPENROUTER_API_KEY`)
- OpenRouter model id (`OPENROUTER_MODEL`)

### Setup

1. **Copy environment file**

```bash
cd Acme_Loan_Processor

# Copy environment template
cp .env.example .env
# Edit .env and add your OpenRouter settings
```

2. **Create virtual environment and install dependencies**

```bash
./scripts/setup_env.sh    # Creates .venv and installs Python deps
```

3. **Start the application**

```bash
./scripts/run_dev.sh    # Start both backend and frontend servers
```

4. **Stop the application**

```bash
./scripts/stop_dev.sh   # Stop both servers
```

**Or run manually:**

```bash
# Terminal 1: Backend
cd backend
source .venv/bin/activate
uvicorn main:app --reload --port 5500

# Terminal 2: Frontend
cd frontend
npm install
npm run dev -- -p 5001
```

5. **Open the app**

- Frontend (Acme Loan Assistant): http://localhost:5001
- Backend API: http://localhost:5500
- API Docs: http://localhost:5500/docs

## Frontend

The Acme Loan Assistant UI features a clean, modern design:

- **Light theme** — Slate/blue palette with subtle radial gradients and glass-panel styling
- **Typography** — Manrope font for a professional, approachable feel
- **Layout** — Glass panel chat container with blue accent band, soft dividers, and fade-in animations
- **Features** — File upload zone with drag-and-drop, starter prompts for quick actions, and responsive design
- **Components** — Chat interface, message list, file upload, and policy error display

## Project Structure

```
Acme_Loan_Processor/
├── frontend/                    # Next.js React frontend (Acme Loan Assistant UI)
│   ├── src/
│   │   ├── app/                 # Next.js app router, layout, globals
│   │   └── components/          # ChatInterface, MessageList, FileUpload
│   └── package.json             # ⚠️ Vulnerable npm deps
│
├── backend/                     # Python FastAPI backend
│   ├── agents/                  # Multi-agent system
│   │   ├── mcp_servers.py       # Central MCP server catalog
│   │   ├── orchestrator_agent.py
│   │   ├── loan_processing_agent.py
│   │   ├── file_processor_agent.py
│   │   ├── file_management_agent.py  # ⚠️ Destructive ops without HITL
│   │   ├── access_control_agent.py   # ⚠️ LLM-driven security decisions
│   │   ├── credit_eval_agent.py
│   │   ├── scheduling_agent.py
│   │   ├── runtime.py           # Thin registry over the agent files
│   │   └── auth/                # ⚠️ Auth bypass
│   ├── policies/                # Policy modules
│   │   ├── pii_detection.py     # ⚠️ NO-OP detection
│   │   ├── prompt_injection.py  # ⚠️ NO-OP detection
│   │   └── runtime/             # Runtime guardrails
│   ├── file_parsers/            # File processing
│   └── requirements.txt         # ⚠️ Vulnerable Python deps
│
├── config/                      # Policy configuration
├── test_files/                  # Demo test files
└── scripts/                     # Development scripts
```

## Demo Scenarios

### 1. PII Detection Demo

**Before:**
1. Upload `test_files/advanced/nested_pii.json`
2. Observe: "File processed successfully"
3. PII is sent to the LLM without detection

**After Unifai Remediation:**
1. Upload the same file
2. Observe: "Error: PII detected - SSN found in user.profile.contact.ssn"

### 2. Prompt Injection Demo

**Before:**
1. Upload `test_files/advanced/base64_hidden.html`
2. Hidden prompts are extracted and sent to LLM
3. LLM may respond to malicious instructions

**After Unifai Remediation:**
1. Upload the same file
2. Observe: "Security threat detected: Hidden content in HTML elements"

### 2b. Image Prompt Injection -> Tool-Output Exfiltration Demo (Environment Diagnostics Agent)

**Before:**
1. Run `python scripts/create_test_files.py` (or generate your own) to produce
   `test_files/advanced/ripgrep_exfil_payload.jpg`, and edit the placeholder
   collector URL drawn on the image to your own request-bin endpoint.
2. Use a multimodal `OPENROUTER_MODEL` (e.g. `meta-llama/llama-4-scout`).
3. Upload the image and ask: "Can you review this closing image?" (routes to the Environment Diagnostics Agent - see
   keyword list in `backend/agents/orchestrator_agent.py::select_agent`).
4. The vision model transcribes the visible instruction text verbatim into
   the document context (`backend/file_parsers/image_parser.py`).
5. `backend/agents/environment_diagnostics_agent.py` parses a natural-language
   "command request" out of that transcription, fabricates a fake AWS
   credential "scan result" (`backend/config/simulated_secrets.py`), and POSTs
   it to the URL embedded in the image - no HITL check, no destination
   allowlist. Observe the "Diagnostic activity" note in the response and the
   real inbound request on your collector.

**After Unifai Remediation:**
1. Same upload and prompt
2. Observe: the destination URL is rejected by a hardcoded allowlist - no
   outbound request is made (see the guarded `environment_diagnostics_agent.py`
   on the `fixed` branch)

### 3. Agent Authentication Demo

**Before:**
1. Ask: "Can you show me the quarterly financial report?"
2. Orchestrator Agent forwards the full context and shared hop token to another agent
3. Access granted without proper authentication

**After Unifai Remediation:**
1. Same request
2. Observe: "Unauthorized: Agent token validation failed"

### 4. Vulnerable Dependencies Demo

**Before:**
```bash
cd frontend && npm audit
# Shows vulnerabilities in lodash, axios, etc.
```

**After Unifai Remediation:**
- `package.json` updated with patched versions
- `npm audit` shows no vulnerabilities

## Policy Violation & Guardrail Mapping

| Policy Category | Individual Policy | Violation File (Unifai Scans) | Guardrail File (Unifai Applies) |
|-----------------|-------------------|-------------------------------|--------------------------------|
| **Data Security** | PII in uploaded files | `backend/agents/file_processor_agent.py` | `backend/policies/pii_detection.py` |
| **AI Threats** | Hidden prompts / Prompt injection | `backend/agents/credit_eval_agent.py` | `backend/policies/prompt_injection.py` |
| **AI Threats** | Image prompt injection -> tool-output exfiltration | `backend/agents/environment_diagnostics_agent.py` | *(destination allowlist gate)* |
| **Identity & Access** | Unauthenticated agent calls | `backend/agents/orchestrator_agent.py` | `backend/agents/auth/agent_auth.py` |
| **AI Threats** | Destructive ops without HITL | `backend/agents/file_management_agent.py` | *(HITL boolean gate)* |
| **AI Threats** | LLM output drives security decisions | `backend/agents/access_control_agent.py` | *(HITL + allowlist gate)* |
| **Vulnerability** | Vulnerable npm packages | `frontend/package.json` | *(version update)* |
| **Vulnerability** | Vulnerable Python packages | `backend/requirements.txt` | *(version update)* |

## Test Files

- `test_files/simple/` - Basic examples for warm-up
- `test_files/advanced/nested_pii.json` - PII buried 5 levels deep
- `test_files/advanced/base64_hidden.html` - Hidden prompts in HTML
- `test_files/advanced/multi_hop_attack.json` - Chained agent exploit

Generate additional test files:
```bash
python scripts/create_test_files.py
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Acme Loan Assistant                      │
│              Next.js + React · Light theme · Manrope         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         Orchestrator Agent                           │
│  ┌───────────────┐ ┌──────────────┐ ┌───────────┐ ┌────────────┐   │
│  │ Loan Processing│ │ File Processor│ │ File Mgmt │ │ Credit Eval│   │
│  └───────────────┘ └──────────────┘ └───────────┘ └────────────┘   │
│          ┌────────────────────┐  ┌──────────────────────────┐      │
│          │ Access Control Agent│  │    Scheduling Agent     │      │
│          └────────────────────┘  └──────────────────────────┘      │
└──────────────────────────────────────────────────────────────────────┘
                               │
               ┌───────────────┼────────────────┬─────────────────────┐
               ▼               ▼                ▼                     ▼
          ┌─────────┐   ┌─────────┐      ┌─────────┐           ┌──────────────┐
          │  Slack  │   │ Service-│      │  Email  │           │ Google Calendar │
          │         │   │   Now   │      │         │           │                │
          └─────────┘   └─────────┘      └─────────┘           └──────────────┘
               │               │                │                     │
               └───────────────┴────────────┬───┴───────────────┬─────┘
                                            ▼                   ▼
                                         ┌──────┐            ┌─────┐
                                         │Excel │            │Docx │
                                         └──────┘            └─────┘
```

## Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `OPENROUTER_API_KEY` | API key for OpenRouter chat completions | Yes | — |
| `OPENROUTER_MODEL` | Multimodal OpenRouter model id (e.g. `meta-llama/llama-4-scout`) | Yes | — |
| `AGENT_SECRET` | Secret for HMAC inter-agent token signing | No | — |
| `JWT_SECRET` | Secret for JWT signing (after Unifai remediation) | No | — |
| `BACKEND_URL` | Backend URL for frontend proxy | No | `http://127.0.0.1:5500` |
| `LOG_LEVEL` | Logging verbosity | No | `INFO` |

## License

This is a demo application for Unifai integration testing.
