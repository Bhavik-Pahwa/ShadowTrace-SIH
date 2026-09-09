# ShadowTrace-XAI PRD Compliance Audit

This audit maps the backend PRD requirements to current implementation evidence.
It is intentionally strict: target-environment risks remain open until verified on
the offline Linux machine.

## Section 2 Tech Stack

- Python 3.10+: `pyproject.toml` constrains installs to Python `>=3.10,<3.13`, and strict verification flags newer interpreters that cannot reliably run the pinned PyTorch/PyG wheel stack.
- polars ingestion: `shadowtrace.ingestion._read_file()` uses `polars.read_csv()`, `polars.read_json()`, and `polars.read_ndjson()`.
- Ingestion normalizes rows through `DataFrame.iter_rows(named=True)` instead of materializing a second full `to_dicts()` copy.
- DuckDB persistence: `shadowtrace.store.DuckDBStore` stores transactions, alerts, and evidence in DuckDB.
- NetworkX graph modeling: `shadowtrace.graph_builder.build_graph()` builds a `networkx.MultiDiGraph`.
- Neo4j avoided: no Neo4j dependency or service is present.
- GeoIP2 local enrichment: `shadowtrace.geoip.GeoIPEnricher` reads local `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` paths when present.
- GeoIP reader handles are closed after ingestion completes or fails.
- Partially opened GeoIP reader handles are closed if another MaxMind reader fails during setup.
- `SHADOWTRACE_REQUIRE_GEOIP=1` makes `GeoIPEnricher` fail fast when either required MaxMind database is missing; the Linux target verification script exports this flag.
- Local MaxMind files: not verified on this host because `backend/data/geoip/GeoLite2-City.mmdb` and `backend/data/geoip/GeoLite2-ASN.mmdb` are currently absent; the verifier now opens present files with `geoip2.database.Reader` and checks metadata so placeholder files fail.
- PyTorch + PyTorch Geometric: `shadowtrace.ml.ShadowTraceGCN` uses `torch_geometric.nn.GCNConv`.
- `torch_scatter`/`torch_sparse` offline wheels: not verified on this Windows/Python 3.14 host; strict verifier fails until a matching offline wheelhouse is present.
- `SHADOWTRACE_REQUIRE_PYG_EXTENSIONS=1` makes `shadowtrace.ml.score_transactions()` fail fast when `torch_scatter` or `torch_sparse` is unavailable; the Linux target verification script exports it.
- Wheelhouse builder: `scripts/build_offline_wheelhouse.py` and the `shadowtrace-build-wheelhouse` console entrypoint download binary wheels only, use `requirements-pyg-extensions.txt` for `torch-scatter==2.1.2` and `torch-sparse==0.6.18`, and refuse mismatched non-Linux or Python 3.14-style hosts.
- Packaged wheelhouse and release-bundle builders support explicit `--root`; installed commands default to the current working directory when it looks like the backend root, while source wrappers pass the checked-out backend root explicitly.
- Source builder wrappers recognize both `--root PATH` and `--root=PATH` before appending their checked-out backend root.
- Wheelhouse builder validates the downloaded `wheelhouse/` with the same pinned-version and compatible-tag verifier before reporting success.
- Wheelhouse builder and verifier run an offline `pip install --dry-run --ignore-installed --no-index --find-links wheelhouse` resolver check for `requirements.txt` and `requirements-pyg-extensions.txt`, catching missing transitive dependency wheels before the target goes air-gapped without relying on packages already installed in the current environment.
- Wheelhouse verifier: `shadowtrace.offline_verify.wheelhouse_status()` requires all directly pinned install/verification wheel names, versions, and compatible wheel tags, including `torch_scatter==2.1.2`, `torch_sparse==0.6.18`, `pytest==8.3.5`, and `httpx==0.28.1`; wrong-platform wheels do not satisfy a Linux target check.
- Tests verify the wheelhouse verifier covers all direct pinned packages from `requirements.txt` and `requirements-pyg-extensions.txt`.
- Wheelhouse verifier accepts PyG local-version tags such as `+pt25cpu` while still requiring the pinned public extension versions.
- GNNExplainer: `shadowtrace.xai.explain_subgraph_with_gnnexplainer()` uses `torch_geometric.explain.GNNExplainer` when model artifacts are available and tags retained subgraphs with explanation provenance.
- SHAP/TreeSHAP: `shadowtrace.xai.build_tree_shap_attributions()` uses `shap.TreeExplainer` over a RandomForest surrogate.
- FastAPI + uvicorn: `shadowtrace.main` defines the FastAPI app and `requirements.txt` includes `uvicorn`.
- WeasyPrint + Jinja2: `shadowtrace.dossier.generate_dossier()` renders Jinja2 HTML through WeasyPrint.

## Section 4 Dataset And Synthetic Augmentation

- Elliptic-style labels are normalized from `class`, `label`, or `target`.
- Elliptic class `3` is normalized to `unknown`.
- Unsupported supplied class labels are rejected as malformed ingest rows.
- Elliptic-style transaction IDs are normalized from `tx_id`, `txid`, `txId`, `transaction_id`, or `id`.
- Offline ingestion accepts CSV, JSON array/object files, JSONL, and NDJSON; the public Section 5 upload endpoint remains CSV-only.
- `time_step`/`timestep`/`step` values are converted to timestamps when no timestamp is supplied.
- Supplied `time_step`/`timestep`/`step` values must be integers in the Elliptic 1-49 range.
- Base58/Bech32 address arrays are generated when input/output addresses are absent.
- Satoshi amounts are generated when input/output amounts are absent.
- Ingestion rejects rows where `sum(inputs) < sum(outputs)`.
- Ingestion rejects decimal and negative satoshi amounts.
- Ingestion parses satoshi amounts exactly with decimal/integer semantics instead of binary floating point, preserving large integer amounts without silent rounding.
- Ingestion rejects duplicate transaction IDs before DuckDB insertion.
- Ingestion rejects mismatched input/output address and amount array lengths.
- Synthetic amount generation for transactions with more than two outputs preserves `sum(inputs) >= sum(outputs)`.
- `src_ip`, `dst_ip`, `src_port`, and `dst_port` are injected when absent.
- Supplied `src_ip`/`dst_ip` values are validated as IP addresses during ingestion.
- Supplied `src_port`/`dst_port` values are validated as integer ports in the range 0-65535 during ingestion.
- Supplied Unix epoch timestamps are normalized to UTC ISO `Z` strings; malformed supplied timestamps are rejected before graph construction.
- Class-1/illicit rows receive synthetic Tor/bulletproof ASN/IP signals through `make_ip()` and `make_asn()`.
- Rows carry `heuristics.data_provenance` with `dataset`, `ledger_layer`, `network_layer`, and `semi_synthetic` fields.
- Transaction graph nodes expose `data_provenance` inline so dossier graph metadata can disclose synthetic augmentation.
- Numeric non-core Elliptic columns are summarized into `elliptic_feature_count`, `elliptic_feature_mean`, and `elliptic_feature_std`.
- Parent/source/previous transaction columns are converted into spend links for graph topology.
- Exchange address columns are retained as exchange-wallet metadata.

## Section 5 API Contract

- `POST /api/ingest` accepts multipart CSV upload and returns exactly `status`, `message`, `job_id`, and `rows_processed`.
- `/api/ingest` rejects non-CSV uploads with the standardized error shape; JSON/NDJSON parsing remains available only at the lower ingestion-engine layer.
- `/api/ingest` rejects zero-row CSV uploads with the standardized `Empty dataset.` error shape.
- `/api/ingest` rejects CSV uploads with no recognized transaction columns using the standardized error shape.
- `GET /api/alerts?limit=50&offset=0` returns exactly `status`, `total_count`, and `alerts`.
- Alert items return exactly `tx_id`, `threat_score`, `timestamp`, `primary_anomaly`, and `risk_level`.
- Alert pagination is handled in DuckDB with `limit ? offset ?`.
- Alert `total_count` is computed from DuckDB.
- `GET /api/graph/{tx_id}` returns exactly `tx_id` and `elements`.
- Graph `elements` contains `nodes` and `edges`.
- Graph nodes embed their metadata inline under `data`.
- Root transaction graph nodes expose `type: "hub"` and `risk` metadata, matching the Section 5 graph example.
- Flagged transaction graph nodes embed `threat_score`, `risk_level`, and `primary_anomaly` inline.
- Graph edges embed their metadata inline under `data`.
- `SPENT` and `RECEIVED` edges include `amount_btc` and `timestamp`.
- `/api/graph/{tx_id}` returns the full server-side N-hop payload using the configured default `DEFAULT_HOPS = 4`; no extra public query parameter and no per-node follow-up endpoint exists.
- `/api/graph/{tx_id}` retains terminal exchange wallet outputs for transactions included in the N-hop graph so peel-chain cashout context is embedded inline.
- A cold API process can hydrate the NetworkX graph from existing DuckDB transactions without rerunning model/XAI scoring on the first graph request.
- `GET /api/evidence/{tx_id}` returns exactly `tx_id`, `overall_threat_score`, `xai_breakdown`, and `chain_of_custody_hash`.
- Evidence features return exactly `feature`, `value`, and `contribution_percentage`.
- Evidence contributions are generated with a programmatic equality check against `overall_threat_score`.
- Contract tests verify contribution sums for every generated alert.
- `chain_of_custody_hash` is computed with `hashlib.sha256()` over `tx_id`, timestamp, and localized subgraph JSON.
- Contract and reproducibility tests recompute the custody hash from API graph payloads.
- Reproducibility tests verify stored evidence hashes are computed from the current default graph payload.
- `POST /api/generate-dossier` request body accepts only `tx_id`, `investigator_id`, `include_xai_visuals`, and `include_network_metadata`.
- `/api/generate-dossier` request validation requires strict JSON strings for `tx_id`/`investigator_id` and strict JSON booleans for `include_xai_visuals`/`include_network_metadata`; stringified booleans are rejected with the standardized 422 error shape.
- `/api/generate-dossier` returns exactly `status`, `message`, `file_path`, and `download_url`.
- `/api/generate-dossier` returns an absolute server-local `file_path`.
- Dossier `download_url` maps to `/api/downloads/...`, which is served through explicit PDF download routes.
- Missing dossier downloads return the standardized error shape.
- Non-PDF download requests and encoded path traversal attempts return the standardized error shape.
- Standardized error shape is installed for application, HTTP, validation, and unhandled exceptions.
- Framework-level unknown API routes are handled through the standardized error shape.
- Live API smoke verifies all graph node/edge types, inline transaction and network metadata, graph root `type`/`risk`, exact evidence keys, evidence sum/hash invariants, absolute dossier `file_path`, dossier generation, PDF download, and standardized unknown-graph errors.
- Prototype compatibility endpoints `/api/investigate/{tx_id}` and `/api/feedback` are present for the team GraphSAGE human-in-the-loop demo while the original Section 5 PRD endpoint shapes remain unchanged.
- Evidence and dossier endpoints return standardized `Evidence not found.` errors for known transactions that were not flagged as alerts.

## Section 6 Graph Data Model And Heuristics

- Node type `Transaction` is emitted for transactions.
- Node type `WalletAddress` is emitted for input/output/change/exchange wallets.
- Wallet address node `type` preserves higher-signal roles when the same address appears multiple times, so change outputs and exchange outputs are not overwritten when later spent as inputs.
- Node type `IPAddress` is emitted for source IP addresses.
- Node type `ASN` is emitted for ASN infrastructure.
- Edge type `SPENT` connects wallet inputs to transactions.
- Edge type `RECEIVED` connects transactions to wallet outputs.
- Edge type `BROADCAST_FROM` connects transactions to source IPs.
- `BROADCAST_FROM` embeds `timestamp`, `src_port`, `dst_ip`, and `dst_port` metadata for the physical network layer.
- Edge type `BELONGS_TO` connects source IPs to ASNs.
- CIOH clusters all input addresses in a transaction through `EntityUnionFind.union()`.
- Wallet nodes receive deterministic `entity_id` values.
- Change-address detection uses script-type continuity.
- Change-address detection uses decimal-pattern scoring.
- Change-address detection accounts for address reuse.
- Change-address detection leaves single-output payment transactions unmarked because there is no change-vs-payment split to resolve.
- Address reuse is retained in `heuristics.address_reuse` and model feature `change_reuse` even when the final `change_address` candidate is another output.
- Peel-chain detection requires 1-input/2-output transaction topology.
- Peel-chain detection requires child hops within `Delta t <= 25s`.
- Peel-chain detection requires repeated small peel amounts within the configured tolerance.
- Fan-out detection flags one input split into at least five outputs and enforces a 25-second rapid context when linked parent/child timing is available.
- Fan-in detection flags at least five inputs consolidated into at most two outputs and enforces a 25-second rapid context when linked parent/child timing is available.

## Section 7 ML Model

- GCN architecture uses two PyTorch Geometric `GCNConv` layers.
- Node classification labels are licit, illicit, and unknown/anomalous.
- Features include `tx_volume`, `fee_ratio`, `input_count`, and `output_count`.
- Neighborhood features include `neighbor_illicit_ratio`, `parent_time_delta`, and `degree_centrality`.
- Threat scores are 0-100 and are derived from the combined illicit plus anomalous model probability.
- GCN scoring preserves the model's actual licit, illicit, and anomalous softmax probabilities and keeps rounded probabilities summing to 1.0.
- A validation split is created via `train_test_split(..., test_size=0.2, stratify=...)` when the dataset supports it.
- Validation metrics are retained in `GCNArtifacts.validation_metrics` and persisted in DuckDB `model_runs` as the latest run.
- A local fallback scorer exists when the host cannot run the GCN path; this is a runtime resilience fallback, not the target implementation path.

## Section 8 XAI

- GNNExplainer is invoked against retained PyG model artifacts when available.
- Reduced GNNExplainer subgraphs are retained in `ShadowTracePipeline.explainer_subgraphs` per alert with `metadata.method == "gnnexplainer"` on the verified sample path.
- Reduced GNNExplainer subgraphs are persisted internally in DuckDB evidence rows.
- Dossier visualization uses the retained or persisted XAI subgraph when `include_xai_visuals` is true.
- GNNExplainer fallback subgraphs are anchored on the requested root transaction when model artifacts or GNNExplainer execution are unavailable.
- GNNExplainer fallback keeps the requested root transaction's own network layer and excludes unrelated transaction IP/ASN edges from the localized graph.
- SHAP/TreeSHAP produces the human-readable evidence contribution rows.
- Contributions are normalized with largest-remainder allocation and checked so their sum exactly equals `overall_threat_score`, including adversarial small-score/flat-weight cases.

## Section 9 Dossier Generation

- Dossier HTML/CSS template is located in `shadowtrace/templates/dossier.html`.
- Template includes an NTRO agency header.
- Template includes evidence summary.
- Template includes feature attribution table.
- Feature attribution table is rendered even when `include_xai_visuals` is false; that flag only changes which graph is used for the visualization.
- Template includes subgraph visualization.
- Subgraph visualization centers the requested root transaction in dossier SVG output.
- Template includes subgraph metadata when requested.
- Template includes edge metadata when network metadata is requested, including source, target, relationship, amount, and timestamp columns.
- Template includes the real chain-of-custody hash.
- `generate_dossier()` writes PDFs into the local reports directory.
- Dossier filenames sanitize transaction IDs before writing to the reports directory.
- `/api/downloads/...` serves generated dossier files through GET/HEAD routes.
- Render-time measurement is returned internally from `generate_dossier()`.
- Offline verifier times a real WeasyPrint render and flags elapsed time above the 2-second target.
- Target render time under about two seconds is not fully verified on this Windows host because native WeasyPrint rendering is unavailable.

## Section 10 Non-Functional Requirements

- Runtime network calls are blocked in `tests/test_offline_runtime.py` and `scripts/verify_offline.py --runtime` by patching raw sockets, connection helpers, and DNS helper entry points.
- Runtime package source is statically checked so outbound network dependencies and helpers such as `socket`, `requests`, `urllib`, `httpx`, `aiohttp`, `urlopen`, `create_connection`, `getaddrinfo`, and `gethostbyname` cannot be introduced outside the offline verifier harness.
- `scripts/verify_offline.py --runtime --runtime-dossier` additionally generates a dossier PDF while raw sockets, connection helpers, and DNS helpers are blocked.
- `--runtime-dossier` implies runtime execution so the dossier no-network check cannot be accidentally skipped.
- `scripts/verify_linux_target.sh` fails fast if NetworkManager is available and `nmcli networking` does not report `disabled`, directly matching the PRD's `nmcli networking off` target rehearsal.
- Strict Linux verification flags a non-loopback default route through `/proc/net/route`, so the final target rehearsal can prove networking has actually been disabled.
- Standalone runtime verifier passed the sample pipeline with runtime network entry points blocked: `OK offline pipeline rows=90 alerts=39`.
- Strict target verifier currently fails because target Linux/offline artifacts are missing or unverifiable here.
- Bulk parsing uses polars and persistence/pagination uses DuckDB.
- End-to-end sample run exists through `python scripts/run_pipeline.py --sample`.
- Script and installed console pipeline entrypoints close their DuckDB connection before process exit for repeatable demo runs.
- Offline runtime verifier closes its DuckDB connection after the network-blocked sample pipeline check.
- DuckDB transaction rehydration orders by `timestamp, tx_id` so equal-timestamp time-step data has deterministic graph/model rebuild order.
- `Makefile` includes `install-offline`, `sample`, `test`, `audit-artifacts`, `verify`, `verify-strict`, `verify-linux-target`, `run`, `wheelhouse`, `bundle-offline`, and `verify-bundle` targets.
- `scripts/verify_linux_target.sh` checks disabled NetworkManager networking when `nmcli` is available, requires PyG extension availability during scoring, runs strict offline verification, the sample pipeline and dossier generation under network-entrypoint blocking, tests, audits stored artifacts, starts the API on loopback, and runs the live endpoint smoke test.
- `scripts/verify_linux_target.sh` supports `SHADOWTRACE_VERIFY_PORT` with a default of `8000`, checks that the uvicorn process it started is still alive during readiness polling, and fails if the server never becomes ready.
- `scripts/audit_prd_artifacts.py` and the `shadowtrace-artifact-audit` console entrypoint check every stored alert for required graph node/edge metadata, exact XAI contribution sums, alert/evidence score parity, and custody hash recomputation from the default graph payload.
- `scripts/build_release_bundle.py` and the `shadowtrace-build-bundle` console entrypoint validate readable MaxMind databases, compatible wheelhouse contents, and offline pip resolver completeness before creating a target handoff ZIP; generated DuckDB data, reports, caches, and editable-install metadata are excluded from the archive, `.dockerignore` is included, and `BUNDLE_MANIFEST.json` records SHA-256 hashes and byte sizes for every packaged file.
- Release-bundle validation derives required MaxMind paths from the supplied backend `--root`, so installed bundle commands validate the target project root rather than the package installation directory.
- Release-bundle validation reports missing GeoIP files once and skips readability checks until both required files are present, keeping target-prep failures concise.
- `scripts/verify_bundle_manifest.py` and the `shadowtrace-verify-bundle` console entrypoint verify transferred bundle ZIPs by checking the manifest exists, required target artifacts are present, file sizes match, and SHA-256 hashes match.
- `PRD_IMPLEMENTATION_CHECKLIST.md` preserves the source PRD-derived checklist and is included in release bundles for handoff review.
- Dockerfile exists for the Linux target with WeasyPrint native libraries and Python packages installed offline from `/app/wheelhouse`, including pinned PyG extension wheels from `requirements-pyg-extensions.txt`.
- Dockerfile avoids `pip install --upgrade pip`; Python requirements are installed only with `--no-index --find-links /app/wheelhouse`.
- Dockerfile installs the local package with `pip install --no-build-isolation --no-deps .` after source copy so console commands are available inside the container without dependency resolution.
- `.dockerignore` excludes generated DuckDB databases, reports, caches, editable-install metadata, and ZIP archives from Docker build contexts while keeping `wheelhouse/` and `data/geoip/*.mmdb` available for offline installation and enrichment.
- `make install-offline` installs dependencies from `wheelhouse/` and then installs the local package with `--no-build-isolation --no-deps -e .`, so clean offline target environments get the console commands.

## Current Verification Snapshot

- `python -m pytest backend/tests/test_contracts.py`: 26 passed.
- `python -m pytest backend/tests`: 118 passed.
- `python backend/scripts/verify_offline.py --runtime`: passed with runtime network entry points blocked.
- `python backend/scripts/run_pipeline.py --sample`: processed 90 rows and generated 39 alerts.
- `python backend/scripts/audit_prd_artifacts.py`: passed with `status=success`, `transactions=90`, and `alerts_audited=39`.
- `python -m pytest backend/tests/test_offline_runtime.py -q`: 24 passed after Linux-gate liveness/port hardening.
- `python -m pytest backend/tests/test_offline_runtime.py -q`: 34 passed after Docker context hygiene coverage was added.
- `python backend/scripts/verify_bundle_manifest.py backend/shadowtrace-xai-source-check.zip`: correctly failed for a source-only `--skip-validation` archive because required target artifacts were absent.
- `python backend/scripts/build_release_bundle.py`: failed as expected on this host because required MaxMind `.mmdb` files and the target wheelhouse are missing.
- `python backend/scripts/build_release_bundle.py --skip-validation --output shadowtrace-xai-source-check.zip`: created a source-only mechanics check archive that included `.dockerignore` and excluded generated DuckDB data, reports, caches, and editable-install metadata; release-bundle tests now require `PRD_IMPLEMENTATION_CHECKLIST.md`; the temporary ZIP was removed.
- `python scripts/smoke_api.py --base-url http://127.0.0.1:8000`: passed against a local server with prebuilt sample data after combined illicit/anomalous GCN scoring, cold-start graph hydration, persisted XAI subgraph storage, evidence hash validation, dossier generation, and PDF download validation.
- `make verify-linux-target`: present but not runnable to completion on this Windows/Python 3.14 host.
- `python backend/scripts/verify_offline.py --strict`: failed because target risks remain unresolved.

## Unresolved Target Risks

- Need verified Linux/Python 3.10-3.12 environment.
- Need populated offline wheelhouse containing all pinned target-matched wheels, including `torch_scatter==2.1.2` and `torch_sparse==0.6.18`.
- Need local MaxMind `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` files shipped into `backend/data/geoip/`.
- Need WeasyPrint native rendering verified on Linux.
- Need Docker/Linux target build run once Docker Desktop/Linux engine or a Linux host is available.
- Need shell syntax/execution check for `scripts/verify_linux_target.sh` on Linux; `bash -n` could not run here because this Windows host has no usable `/bin/bash`.
