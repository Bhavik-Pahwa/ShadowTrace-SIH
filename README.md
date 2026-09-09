# ShadowTrace-SIH

ShadowTrace-XAI is an SIH forensic Bitcoin anomaly detection prototype with a
React dashboard frontend and an offline-first FastAPI backend.

## Frontend

```bash
npm install
npm run dev
```

The Vite frontend runs at `http://127.0.0.1:5173/` and proxies `/api` requests
to the backend at `http://127.0.0.1:8000`.

## Backend

```bash
cd backend
python -m venv .venv
python -m pip install -r requirements.txt
python scripts/run_pipeline.py --sample
python -m uvicorn shadowtrace.main:app --host 127.0.0.1 --port 8000
```

On the final offline Linux target, follow the stricter setup in
`backend/README.md`, including the local wheelhouse and MaxMind GeoIP database
requirements.

## Large CSV Assets

Two CSV files are too large for normal GitHub git storage and are published as
release assets. See `DATASETS.md` for download links and restore paths.
