# ShadowTrace-XAI Backend

FastAPI backend for the SIH ShadowTrace-XAI forensic workflow.

## Run

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
make install-offline
python scripts/verify_offline.py
python scripts/run_pipeline.py --sample
uvicorn shadowtrace.main:app --host 0.0.0.0 --port 8000
```

`scripts/verify_offline.py` checks imports, local GeoIP database availability,
wheelhouse package versions and compatibility tags, an offline pip resolver
dry-run that ignores installed packages, and whether PyTorch Geometric extension
modules are present. It reports unverifiable offline wheel status as a risk
instead of passing silently.

Use `python scripts/verify_offline.py --runtime --runtime-dossier` to run the
sample pipeline and dossier generation while raw sockets, connection helpers,
and DNS helpers are blocked. On a non-target development machine that lacks
WeasyPrint native libraries, set `SHADOWTRACE_ALLOW_PDF_FALLBACK=1` only for
this local rehearsal.

See `PRD_IMPLEMENTATION_CHECKLIST.md` for the source PRD checklist and
`PRD_COMPLIANCE_AUDIT.md` for the item-by-item implementation mapping and
target readiness risks.

Use Python 3.10-3.12 for the backend environment. The PyTorch/PyG wheel stack is
not reliably available for newer interpreters.

Build the offline wheelhouse on the same Linux architecture and Python minor
version as the target demo machine:

```bash
make wheelhouse
# or, after installation:
shadowtrace-build-wheelhouse --root /path/to/backend
```

Equivalent direct command:

```bash
python scripts/build_offline_wheelhouse.py
```

Then install from that local wheelhouse only:

```bash
make install-offline
```

`make install-offline` installs dependencies from `wheelhouse/`, then installs
the local `shadowtrace-xai-backend` package with `--no-deps --no-build-isolation`
so the console commands are available without network dependency resolution.

`requirements-pyg-extensions.txt` pins the PyG extension wheels separately
because they must come from target-matched offline wheel files, not a source
build during the demo. The verifier rejects wrong-platform wheels such as a
Windows `torch_scatter` artifact in a Linux target wheelhouse.

After the wheelhouse and MaxMind databases are present, build the handoff
archive:

```bash
make bundle-offline
# or, after installation:
shadowtrace-build-bundle --root /path/to/backend
```

This refuses to package a target bundle until the GeoIP databases are readable
and the wheelhouse satisfies the offline resolver. It excludes generated DuckDB
data, reports, caches, and editable-install metadata. The ZIP includes a
`BUNDLE_MANIFEST.json` file with SHA-256 hashes and byte sizes for every
packaged file, plus the project `.dockerignore` used to keep generated
databases, reports, caches, and ZIP archives out of Docker builds without
excluding required offline assets such as `wheelhouse/` or `data/geoip/*.mmdb`.

After copying the archive, verify its manifest:

```bash
python scripts/verify_bundle_manifest.py shadowtrace-xai-offline-bundle.zip
# or, after installation:
shadowtrace-verify-bundle shadowtrace-xai-offline-bundle.zip
```

## GeoIP

Place local MaxMind databases here:

```text
backend/data/geoip/GeoLite2-City.mmdb
backend/data/geoip/GeoLite2-ASN.mmdb
```

The runtime never performs remote GeoIP/OSINT lookups.

The final Linux verification gate exports `SHADOWTRACE_REQUIRE_GEOIP=1`, which
turns missing City/ASN databases into a runtime failure instead of allowing the
development fallback metadata path.

The same target gate exports `SHADOWTRACE_REQUIRE_PYG_EXTENSIONS=1`, which turns
missing `torch_scatter`/`torch_sparse` modules into a scoring failure instead of
allowing a development fallback path to mask a broken offline PyG install.

## Team ML Prototype Endpoints

The backend also exposes compatibility endpoints for the team GraphSAGE model
folder at `../ml-model/src`, or another folder supplied through
`SHADOWTRACE_TEAM_MODEL_ROOT`:

```text
GET  /api/investigate/{tx_id}
POST /api/feedback
```

`/api/investigate/{tx_id}` loads the team `shadowtrace.pt` GraphSAGE weights and
the local `outputs/nodes.csv`, `outputs/edges.csv`, and `outputs/xai_sample.json`
assets when the requested transaction belongs to that model bundle. For regular
PRD backend alert IDs, it returns a compatibility view over the backend alert and
evidence records. `/api/feedback` records investigator labels in
`backend/data/feedback.db` for the active-learning demo loop.

## Verification

```bash
make verify
make audit-artifacts
make run
make smoke-api
```

`make audit-artifacts` or `shadowtrace-artifact-audit` checks the stored DuckDB
artifacts after ingestion: every alert must have a full graph payload with
required metadata, evidence contributions must sum exactly to the threat score,
and the custody hash must recompute from the default graph payload.

`make smoke-api` expects the API to be running with data already ingested. It
checks the exact frontend-facing contract, evidence hash recomputation, dossier
generation, and explicit PDF download route.

On the final offline Linux demo machine, run the full target gate:

```bash
make verify-linux-target
```

That strict gate checks dependencies, confirms runtime network entry points are
blocked through both the sample pipeline and dossier generation, runs tests,
audits stored graph/evidence artifacts, starts the API on loopback, and executes
the endpoint smoke test.

On a non-target development machine that lacks WeasyPrint native libraries, set
`SHADOWTRACE_ALLOW_PDF_FALLBACK=1` only for local smoke tests. Leave it unset in
the Linux demo/runtime environment so WeasyPrint failures surface clearly.
