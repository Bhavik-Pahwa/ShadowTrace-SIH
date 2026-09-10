# ShadowTrace-XAI Architecture

## Overview

ShadowTrace-XAI is split into three implementation areas:

- `frontend/`: the investigator dashboard.
- `backend/`: the FastAPI forensic workflow and evidence API.
- `ml-model/`: the team GraphSAGE prototype and model assets.

```text
Investigator
  |
  v
React + TypeScript Dashboard
  |
  v
FastAPI Backend
  |
  +--> Ingestion and validation
  |
  +--> Graph construction and heuristics
  |
  +--> GCN / GraphSAGE scoring
  |
  +--> XAI attribution
  |
  +--> DuckDB / SQLite storage
  |
  v
Alert queue, graph evidence, feedback, PDF dossier
```

## Runtime Flow

1. The reviewer starts the FastAPI backend and runs the sample pipeline.
2. Transaction data is validated, normalized, and stored locally.
3. The backend builds transaction, wallet, IP, ASN, and exchange graph edges.
4. Heuristics and ML models score suspicious transaction behavior.
5. XAI evidence explains the risk score with feature contributions and graph
   context.
6. The frontend loads alerts, graph payloads, evidence records, and dossier
   downloads through `/api` routes.
7. Investigator feedback is written locally for the active-learning demo loop.

## Main Components

| Component | Responsibility |
| --- | --- |
| `frontend/src/App.tsx` | Single-page dashboard, alert views, graph evidence, dossier and feedback UI |
| `backend/shadowtrace/main.py` | FastAPI route layer |
| `backend/shadowtrace/pipeline.py` | End-to-end ingest, graph, scoring, XAI, and persistence workflow |
| `backend/shadowtrace/graph_builder.py` | Transaction graph and heuristic feature construction |
| `backend/shadowtrace/ml.py` | Backend GCN scoring path |
| `backend/shadowtrace/team_model.py` | Compatibility adapter for `ml-model/src` GraphSAGE assets |
| `backend/shadowtrace/dossier.py` | Court-ready PDF dossier generation |
| `ml-model/src/` | Team ML prototype scripts, weights, and sample outputs |

## Storage

- DuckDB stores normalized transactions, alerts, graph evidence, and XAI records.
- SQLite stores investigator feedback for the prototype active-learning loop.
- Local files store generated PDF dossiers and offline release artifacts.

## Offline Readiness

The backend includes verification and bundle scripts for offline Linux demos.
MaxMind GeoIP databases and wheelhouse assets are expected to be provided
locally for strict target verification.
