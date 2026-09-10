# ShadowTrace-XAI

ShadowTrace-XAI is an explainable Bitcoin transaction forensics platform built
for Smart India Hackathon 2026. It helps investigators ingest transaction data,
detect suspicious flows, inspect graph evidence, and export court-ready dossiers
with a cryptographic chain of custody.

## SIH Details

| Field | Value |
| --- | --- |
| Problem Statement ID | SIH26146 |
| Problem Statement Title | AI-Powered Monitoring & Analysis of Bitcoin Transaction Traffic |
| Theme | Blockchain & Cybersecurity |
| Category | Software |
| Team Name | LocalDost |
| Project Name | ShadowTrace-XAI |

## Problem

Illicit cryptocurrency flows move quickly through peel chains, exchange
cash-outs, darknet wallets, ransomware clusters, and other multi-hop patterns.
Manual blockchain review is slow, expensive, and difficult to explain in a way
that supports regulatory action or legal review.

## Proposed Solution

ShadowTrace-XAI combines graph analytics, machine learning, explainable AI, and
local evidence generation. The system builds a transaction graph, scores risky
transactions, shows the surrounding money movement and network metadata, and
generates a PDF dossier that preserves the evidence trail.

## Key Features

- CSV/JSON transaction ingestion with validation and enrichment.
- Wallet, transaction, IP, ASN, exchange, peel-chain, and timing graph signals.
- GCN/GraphSAGE-based suspicious transaction scoring.
- Explainable AI breakdowns for each alert.
- Investigator dashboard with alert queue, graph view, evidence view, dossier
  generation, and human feedback.
- Local SQLite/DuckDB-backed workflow suitable for offline or edge deployment.
- SHA-256 custody hashes and WeasyPrint dossier exports for review.
- Compatibility endpoints for the team ML prototype and feedback loop.

## Technology Stack

| Layer | Technologies |
| --- | --- |
| Frontend | React, TypeScript, Vite, Tailwind CSS, Cytoscape-ready graph UX |
| Backend | Python, FastAPI, DuckDB, SQLite, Polars, WeasyPrint |
| ML/XAI | PyTorch, PyTorch Geometric, GCN, GraphSAGE, GNNExplainer-style outputs |
| Data | Elliptic Bitcoin dataset format, MaxMind GeoIP local databases |
| Tooling | pytest, Makefile, offline wheelhouse/release-bundle scripts |

## Repository Structure

```text
ShadowTrace-SIH/
├── README.md
├── SUBMISSION_GUIDE.md
├── backend/
├── docs/
├── frontend/
├── ml-model/
└── submission/
```

- `frontend/` contains the Vite React investigator dashboard.
- `backend/` contains the FastAPI forensic API, tests, offline verification,
  dossier generation, and release tooling.
- `ml-model/` contains the team GraphSAGE prototype and model assets.
- `docs/` contains dataset restore notes.
- `submission/` contains SIH presentation/demo submission references.

## Setup And Run

### 1. Frontend

```bash
cd frontend
npm install
npm run dev
```

The dashboard runs at `http://127.0.0.1:5173/` and proxies `/api` requests to
the backend at `http://127.0.0.1:8000`.

### 2. Backend

```bash
cd backend
python -m venv .venv
python -m pip install -r requirements.txt
python scripts/run_pipeline.py --sample
python -m uvicorn shadowtrace.main:app --host 127.0.0.1 --port 8000
```

For the final offline Linux target, follow the stricter setup in
`backend/README.md`, including the local wheelhouse and MaxMind GeoIP database
requirements.

### 3. ML Prototype Assets

The backend defaults to the model bundle at `ml-model/src`. To use another model
folder, set:

```bash
set SHADOWTRACE_TEAM_MODEL_ROOT=path\to\model\src
```

On Linux/macOS:

```bash
export SHADOWTRACE_TEAM_MODEL_ROOT=/path/to/model/src
```

## Output

The reviewer can inspect:

- Ranked suspicious transaction alerts.
- N-hop graph evidence around a selected transaction.
- XAI feature attribution for a threat score.
- Investigator feedback recording.
- Downloadable evidence dossiers with custody hashes.

## Dataset Assets

Two large CSV assets are stored as GitHub Release assets instead of normal Git
files. Restore instructions are in `docs/DATASETS.md`.

## Team

Team name: LocalDost

| Member | Role |
| --- | --- |
| Add member name | ML model and XAI pipeline |
| Add member name | Backend API and evidence pipeline |
| Add member name | Frontend dashboard and UX |
| Add member name | Dataset, testing, documentation, and demo |

Update this table with final member names before sharing the repository link.

## Submission Artifacts

- Presentation: `submission/LocalDost_SIH2026_Presentation.pdf`
- Presentation note: `submission/PRESENTATION.md`
- Demo note: `submission/DEMO.md`
- Submission checklist: `SUBMISSION_GUIDE.md`

## Verification

Useful local checks:

```bash
cd frontend
npm run build
```

```bash
python -m pytest backend/tests/test_contracts.py -q
```

## Security Note

Do not commit passwords, API keys, access tokens, private credentials, or `.env`
files containing secrets.
