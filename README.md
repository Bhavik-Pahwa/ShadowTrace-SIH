# ShadowTrace-XAI

ShadowTrace-XAI is an explainable Bitcoin transaction forensics platform built
for Smart India Hackathon 2026. It helps investigators ingest transaction data,
detect suspicious flows, inspect graph evidence, and export court-ready dossiers
with a cryptographic chain of custody.

## 1. Project Information

- **Project Title:** ShadowTrace-XAI
- **PS ID:** SIH26146
- **PS Title:** AI-Powered Monitoring & Analysis of Bitcoin Transaction Traffic
- **Category:** Software
- **Theme:** Blockchain & Cybersecurity
- **Team Name:** LocalDost

## 2. Problem Statement

Illicit cryptocurrency flows move quickly through peel chains, exchange
cash-outs, darknet wallets, ransomware clusters, and other multi-hop patterns.
Manual blockchain review is slow, expensive, and difficult to explain in a way
that supports regulatory action or legal review.

## 3. Proposed Solution

ShadowTrace-XAI combines graph analytics, machine learning, explainable AI, and
local evidence generation. The system builds a transaction graph, scores risky
transactions, shows the surrounding money movement and network metadata, and
generates a PDF dossier that preserves the evidence trail.

## 4. Key Features

- CSV/JSON transaction ingestion with validation and enrichment.
- Wallet, transaction, IP, ASN, exchange, peel-chain, and timing graph signals.
- GCN/GraphSAGE-based suspicious transaction scoring.
- Explainable AI breakdowns for each alert.
- Investigator dashboard with alert queue, graph view, evidence view, dossier
  generation, and human feedback.
- Local SQLite/DuckDB-backed workflow suitable for offline or edge deployment.
- SHA-256 custody hashes and WeasyPrint dossier exports for review.
- Compatibility endpoints for the team ML prototype and feedback loop.

## 5. Technology Stack

| Layer    | Technologies                                                           |
| -------- | ---------------------------------------------------------------------- |
| Frontend | React, TypeScript, Vite, Tailwind CSS, Cytoscape-ready graph UX        |
| Backend  | Python, FastAPI, DuckDB, SQLite, Polars, WeasyPrint                    |
| ML/XAI   | PyTorch, PyTorch Geometric, GCN, GraphSAGE, GNNExplainer-style outputs |
| Data     | Elliptic Bitcoin dataset format, MaxMind GeoIP local databases         |
| Tooling  | pytest, Makefile, offline wheelhouse/release-bundle scripts            |

## 6. Architecture

See [docs/architecture.md](docs/architecture.md).

```text
Investigator
  |
  v
React Dashboard
  |
  v
FastAPI Backend
  |
  +--> DuckDB / SQLite Evidence Stores
  |
  +--> Graph Builder + Heuristics
  |
  +--> GCN / GraphSAGE Model
  |
  +--> XAI Evidence + Custody Hash
  |
  v
PDF Dossier / Alert Review Output
```

## 7. Repository Structure

```text
ShadowTrace-SIH/
|-- README.md
|-- assets/
|   `-- screenshots/
|-- backend/
|-- docs/
|-- frontend/
|-- ml-model/
`-- submission/
```

### What Goes Where?

| Item                                   | Location              |
| -------------------------------------- | --------------------- |
| Frontend source code                   | `frontend/`           |
| Backend source code                    | `backend/`            |
| ML prototype and model assets          | `ml-model/`           |
| Architecture and dataset documentation | `docs/`               |
| Project screenshots / prototype photos | `assets/screenshots/` |
| Final presentation and demo links      | `submission/`         |
| Project overview                       | `README.md`           |

## 8. Final Presentation

- `submission/LocalDost_SIH2026_Presentation.pdf`

## 9. Demo Video

- `submission/DEMO.md`

## 10. Screenshots / Prototype Photos

### Home & Data Ingestion

| Home | Data Ingestion |
| :---: | :---: |
| ![Home](assets/screenshots/01-home.png) | ![Data Ingestion](assets/screenshots/02-ingest.png) |

### Alerts & Graph Investigation

| Alerts | Transaction Graph |
| :---: | :---: |
| ![Alerts](assets/screenshots/03-alerts.png) | ![Transaction Graph](assets/screenshots/04-graph.png) |

### Analytics & Forensic Dossier

| Analytics | Forensic Dossier |
| :---: | :---: |
| ![Analytics](assets/screenshots/05-analytics.png) | ![Forensic Dossier](assets/screenshots/06-dossier.png) |

### Human-in-the-Loop Feedback

![Human-in-the-Loop Feedback](assets/screenshots/07-feedback.png)

## 11. Installation

### Frontend

```bash
cd frontend
npm install
```

### Backend

```bash
cd backend
python -m venv .venv
python -m pip install -r requirements.txt
```

For final offline Linux setup, follow the stricter instructions in
`backend/README.md`, including wheelhouse and MaxMind GeoIP database
requirements.

## 12. Run

Start the backend API:

```bash
cd backend
python scripts/run_pipeline.py --sample
python -m uvicorn shadowtrace.main:app --host 127.0.0.1 --port 8000
```

Start the frontend dashboard in another terminal:

```bash
cd frontend
npm run dev
```

The dashboard runs at `http://127.0.0.1:5173/` and proxies `/api` requests to
the backend at `http://127.0.0.1:8000`.

## 13. Output

The reviewer can inspect:

- Ranked suspicious transaction alerts.
- N-hop graph evidence around a selected transaction.
- XAI feature attribution for a threat score.
- Investigator feedback recording.
- Downloadable evidence dossiers with custody hashes.

## 14. Dataset Assets

Two large CSV assets are stored as GitHub Release assets instead of normal Git
files. Restore instructions are in [docs/DATASETS.md](docs/DATASETS.md).
