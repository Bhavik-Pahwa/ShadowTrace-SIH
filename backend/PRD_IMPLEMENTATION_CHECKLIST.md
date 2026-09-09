# ShadowTrace-XAI Backend PRD Implementation Checklist

This checklist is derived from `ShadowTrace-XAI-Backend-PRD.md` and is kept as
the durable implementation contract for the backend. Instructions in the PRD are
treated as product requirements; this file is not a substitute for
`PRD_COMPLIANCE_AUDIT.md`, which maps each item to implementation evidence.

## Section 1 Purpose

- [ ] Ingest bulk synthetic Bitcoin transaction metadata.
- [ ] Ingest bulk synthetic network metadata.
- [ ] Fuse the physical network layer: IP.
- [ ] Fuse the physical network layer: ASN.
- [ ] Fuse the physical network layer: port.
- [ ] Fuse the physical network layer: timing.
- [ ] Fuse the blockchain ledger layer: wallet.
- [ ] Fuse the blockchain ledger layer: TXID.
- [ ] Fuse the blockchain ledger layer: amount.
- [ ] Run entity clustering.
- [ ] Run a GNN-based anomaly detector over the resulting graph.
- [ ] Produce ranked alerts.
- [ ] Produce explainable alerts.
- [ ] Use GNNExplainer for explainability.
- [ ] Use SHAP for explainability.
- [ ] Generate an offline PDF dossier for any flagged transaction.
- [ ] PDF dossier must be court-ready.
- [ ] Everything must run on a single Linux machine.
- [ ] Runtime must have zero network access.

## Section 2 Tech Stack

- [ ] Use Python 3.10+.
- [ ] Use `polars` and/or `duckdb` for ingestion.
- [ ] Use fast, low-memory bulk CSV parsing.
- [ ] Use fast, low-memory bulk JSON parsing.
- [ ] Make no external calls during ingestion.
- [ ] Use `networkx` for graph modeling.
- [ ] Use an in-memory graph.
- [ ] Avoid Neo4j.
- [ ] Use `geoip2` for GeoIP/OSINT enrichment.
- [ ] Use local MaxMind `GeoLite2-City.mmdb`.
- [ ] Use local MaxMind `GeoLite2-ASN.mmdb`.
- [ ] Ship local MaxMind files in the repo or target bundle.
- [ ] Perform zero external GeoIP/OSINT lookups.
- [ ] Use PyTorch for ML.
- [ ] Use PyTorch Geometric (`torch_geometric`) for ML.
- [ ] Implement a GCN-based node classifier over the fused graph.
- [ ] Use GNNExplainer for subgraph attribution.
- [ ] Use `shap`/TreeSHAP for feature contribution percentages.
- [ ] XAI contribution percentages must sum to the overall threat score.
- [ ] Use FastAPI for the API.
- [ ] Use `uvicorn` to serve the API.
- [ ] Use `weasyprint` for dossier generation.
- [ ] Use `jinja2` for dossier generation.
- [ ] Render an HTML/CSS template to PDF fully offline.
- [ ] Use the Kaggle Elliptic transaction graph as the dataset base.
- [ ] Augment the Elliptic dataset with synthetic addresses.
- [ ] Augment the Elliptic dataset with synthetic IPs.
- [ ] Augment the Elliptic dataset with synthetic ports.
- [ ] Pre-download exact `torch-scatter` wheels matching torch, OS, and CPU/CUDA.
- [ ] Pre-download exact `torch-sparse` wheels matching torch, OS, and CPU/CUDA.
- [ ] Test a clean install of the PyG extension wheels on a disconnected machine before the deadline.
- [ ] Treat PyG extension wheels as the most likely offline packaging risk.

## Section 3 System Architecture

- [ ] Accept a raw CSV dataset as input.
- [ ] Accept a raw JSON dataset as input at the ingestion-engine layer.
- [ ] Run the ingestion engine with polars/duckdb.
- [ ] Enrich from local GeoLite2 `.mmdb` files.
- [ ] Build the graph with NetworkX.
- [ ] Run CIOH (Common Input Ownership Heuristic) during graph construction.
- [ ] Run change-address detection during graph construction.
- [ ] Run peel-chain topology detection during graph construction.
- [ ] Run fan-out topology detection during graph construction.
- [ ] Run fan-in topology detection during graph construction.
- [ ] Run a PyTorch Geometric GNN detection engine after graph construction.
- [ ] Classify nodes as licit.
- [ ] Classify nodes as illicit.
- [ ] Classify nodes as anomalous.
- [ ] Output a `threat_score` from the detection engine.
- [ ] Run GNNExplainer in the XAI layer.
- [ ] GNNExplainer must isolate the minimal high-impact subgraph.
- [ ] Run SHAP/TreeSHAP in the XAI layer.
- [ ] SHAP/TreeSHAP must produce per-feature contribution percentages.
- [ ] Contribution percentages must sum to `threat_score`.
- [ ] Serve all Section 5 endpoints through FastAPI.
- [ ] Generate PDF dossiers through WeasyPrint and Jinja2.

## Section 4 Dataset And Synthetic Augmentation

- [ ] Base the demo on the Kaggle Elliptic dataset.
- [ ] Support roughly 200k labeled Bitcoin transactions.
- [ ] Support licit labels.
- [ ] Support illicit labels.
- [ ] Support unknown labels.
- [ ] Account for Elliptic node features being anonymized and aggregated.
- [ ] Do not require real addresses in Elliptic input.
- [ ] Do not require real IPs in Elliptic input.
- [ ] Do not require raw amounts in Elliptic input.
- [ ] Convert `time_step` to Unix epoch timestamps.
- [ ] Accept `time_step` values 1-49.
- [ ] Generate realistic Base58 address arrays when addresses are absent.
- [ ] Generate realistic Bech32 address arrays when addresses are absent.
- [ ] Generate satoshi amounts when amounts are absent.
- [ ] Ensure generated satoshi amounts respect `sum(inputs) >= sum(outputs)`.
- [ ] Inject `src_ip` values when absent.
- [ ] Inject `dst_ip` values when absent.
- [ ] Inject port values when absent.
- [ ] Deliberately assign Tor-exit-node subnets to class-1 illicit rows.
- [ ] Deliberately assign bulletproof-hosting ASNs to class-1 illicit rows.
- [ ] Ensure the network-layer signal is present for the GNN.
- [ ] Ensure the network-layer signal is present for heuristics.
- [ ] Be explicit internally that the demo is semi-synthetic by design.
- [ ] Track that the network-layer signal is hand-planted on top of a real independently labeled ledger-layer dataset.
- [ ] Avoid implying the model discovered a real-world pattern unsupervised.
- [ ] Present the dataset as a proof of concept on an augmented labeled set.

## Section 5 API Contract

- [ ] `POST /api/ingest` must accept multipart form-data.
- [ ] `POST /api/ingest` must accept a raw CSV file.
- [ ] `POST /api/ingest` success response must include exactly `status`.
- [ ] `POST /api/ingest` success response must include exactly `message`.
- [ ] `POST /api/ingest` success response must include exactly `job_id`.
- [ ] `POST /api/ingest` success response must include exactly `rows_processed`.
- [ ] `POST /api/ingest` success response `status` must be `"success"`.
- [ ] `POST /api/ingest` success response `message` must be `"Dataset ingested successfully."`.
- [ ] `POST /api/ingest` success response `job_id` must look like `"job_0987"`.
- [ ] `POST /api/ingest` success response `rows_processed` must be numeric.
- [ ] `GET /api/alerts?limit=50&offset=0` must support `limit`.
- [ ] `GET /api/alerts?limit=50&offset=0` must support `offset`.
- [ ] `GET /api/alerts?limit=50&offset=0` must use real pagination.
- [ ] `GET /api/alerts?limit=50&offset=0` must return accurate `total_count`.
- [ ] `GET /api/alerts?limit=50&offset=0` must not rely on slicing a fully-loaded array when the dataset grows large.
- [ ] `GET /api/alerts` success response must include exactly `status`.
- [ ] `GET /api/alerts` success response must include exactly `total_count`.
- [ ] `GET /api/alerts` success response must include exactly `alerts`.
- [ ] Alert items must include exactly `tx_id`.
- [ ] Alert items must include exactly `threat_score`.
- [ ] Alert items must include exactly `timestamp`.
- [ ] Alert items must include exactly `primary_anomaly`.
- [ ] Alert items must include exactly `risk_level`.
- [ ] `GET /api/graph/{tx_id}` must return `tx_id`.
- [ ] `GET /api/graph/{tx_id}` must return `elements`.
- [ ] Graph `elements` must contain `nodes`.
- [ ] Graph `elements` must contain `edges`.
- [ ] Graph node records must use `{ "data": ... }`.
- [ ] Transaction node metadata must include `id`.
- [ ] Transaction node metadata must include `label`.
- [ ] Transaction node metadata must include `type`.
- [ ] Transaction node metadata must include `risk`.
- [ ] WalletAddress node metadata must include `id`.
- [ ] WalletAddress node metadata must include `label`.
- [ ] WalletAddress node metadata must include `type`.
- [ ] WalletAddress node metadata must include `entity_id`.
- [ ] IPAddress node metadata must include `id`.
- [ ] IPAddress node metadata must include `label`.
- [ ] IPAddress node metadata must include `type`.
- [ ] IPAddress node metadata must include `country`.
- [ ] ASN node metadata must include `id`.
- [ ] ASN node metadata must include `label`.
- [ ] ASN node metadata must include `type`.
- [ ] ASN node metadata must include `description`.
- [ ] Graph edge records must use `{ "data": ... }`.
- [ ] Graph edge metadata must include `source`.
- [ ] Graph edge metadata must include `target`.
- [ ] Graph edge metadata must include `relationship`.
- [ ] `SPENT` edges must include `amount_btc`.
- [ ] `SPENT` edges must include `timestamp`.
- [ ] `RECEIVED` edges must include `amount_btc`.
- [ ] `RECEIVED` edges must include `timestamp`.
- [ ] `BROADCAST_FROM` edges must be included.
- [ ] `BELONGS_TO` edges must be included.
- [ ] `/api/graph/{tx_id}` must return the complete N-hop subgraph in one payload.
- [ ] The default N-hop depth must be 3-4.
- [ ] N-hop traversal must run server-side through NetworkX.
- [ ] The graph payload must include the full peel chain.
- [ ] The graph payload must include terminal exchange wallets.
- [ ] The graph payload must include the IP network layer.
- [ ] The graph payload must include the ASN network layer.
- [ ] All node metadata must be embedded inline.
- [ ] All edge metadata must be embedded inline.
- [ ] The frontend must not need recursive fetching.
- [ ] The frontend must not need client-side graph merging.
- [ ] The frontend must not need fallback values for `amount_btc` or `timestamp`.
- [ ] `GET /api/evidence/{tx_id}` must be scoped to the primary/root flagged transaction.
- [ ] `GET /api/evidence/{tx_id}` must not expose per-node evidence.
- [ ] `GET /api/evidence/{tx_id}` response must include exactly `tx_id`.
- [ ] `GET /api/evidence/{tx_id}` response must include exactly `overall_threat_score`.
- [ ] `GET /api/evidence/{tx_id}` response must include exactly `xai_breakdown`.
- [ ] `GET /api/evidence/{tx_id}` response must include exactly `chain_of_custody_hash`.
- [ ] Evidence feature rows must include exactly `feature`.
- [ ] Evidence feature rows must include exactly `value`.
- [ ] Evidence feature rows must include exactly `contribution_percentage`.
- [ ] `contribution_percentage` values must sum exactly to `overall_threat_score`.
- [ ] The exact-sum property must hold for every alert.
- [ ] `chain_of_custody_hash` must be a real SHA-256.
- [ ] `chain_of_custody_hash` must be computed over localized subgraph JSON or `tx_id` plus `timestamp`.
- [ ] `chain_of_custody_hash` must not be a placeholder.
- [ ] `chain_of_custody_hash` must not be static.
- [ ] `POST /api/generate-dossier` request must include `tx_id`.
- [ ] `POST /api/generate-dossier` request must include `investigator_id`.
- [ ] `POST /api/generate-dossier` request must include `include_xai_visuals`.
- [ ] `POST /api/generate-dossier` request must include `include_network_metadata`.
- [ ] `POST /api/generate-dossier` response must include exactly `status`.
- [ ] `POST /api/generate-dossier` response must include exactly `message`.
- [ ] `POST /api/generate-dossier` response must include exactly `file_path`.
- [ ] `POST /api/generate-dossier` response must include exactly `download_url`.
- [ ] `POST /api/generate-dossier` response `status` must be `"success"`.
- [ ] `POST /api/generate-dossier` response `message` must be `"Dossier generated successfully."`.
- [ ] `file_path` must be server-local.
- [ ] `file_path` must be informational only.
- [ ] The frontend must use `download_url`.
- [ ] `download_url` must be servable as a static download.
- [ ] Every endpoint failure must use standardized error shape.
- [ ] Standardized error shape must include `status`.
- [ ] Standardized error shape must include `code`.
- [ ] Standardized error shape must include `message`.
- [ ] Standardized error shape must include `details`.
- [ ] Standardized error `status` must be `"error"`.
- [ ] Unknown `tx_id` must use standardized error shape.
- [ ] Malformed ingest file must use standardized error shape.
- [ ] Empty dataset must use standardized error shape.

## Section 6 Graph Data Model And Heuristics

- [ ] Emit `Transaction` nodes.
- [ ] Emit `WalletAddress` nodes.
- [ ] Emit `IPAddress` nodes.
- [ ] Emit `ASN` nodes.
- [ ] Emit `SPENT` edges.
- [ ] Emit `RECEIVED` edges.
- [ ] Emit `BROADCAST_FROM` edges.
- [ ] Emit `BELONGS_TO` edges.
- [ ] CIOH must treat all input addresses spent in the same transaction as one entity.
- [ ] CIOH must collapse same-transaction input addresses into a `Master Entity ID`.
- [ ] CIOH must expose that entity identifier on wallet nodes.
- [ ] Change-address detection must identify the change output.
- [ ] Change-address detection must distinguish change output from payment output.
- [ ] Change-address detection must use script-type continuity.
- [ ] Change-address detection must use decimal-pattern heuristics.
- [ ] Peel-chain detection must flag chains of 1-input/2-output transactions.
- [ ] Peel-chain detection must use tight timestamp deltas.
- [ ] Peel-chain detection blueprint default must be `Delta t <= 25s` between hops.
- [ ] Peel-chain detection must require a small repeated peel amount at each hop.
- [ ] Fan-out detection must flag rapid splitting of one balance into many addresses.
- [ ] Fan-out detection must cover smurfing behavior.
- [ ] Fan-in detection must flag consolidation of many addresses into one address.
- [ ] Fan-in detection must cover pre-cashout aggregation.
- [ ] Heuristics must run before or alongside the GNN.
- [ ] Heuristics must not be a substitute for the GNN.
- [ ] Heuristics must be the foundation the GNN features build on.

## Section 7 ML Model

- [ ] Implement a Graph Convolutional Network architecture.
- [ ] Implement the GCN through PyTorch Geometric.
- [ ] Classify nodes as licit.
- [ ] Classify nodes as illicit.
- [ ] Classify nodes as anomalous.
- [ ] Include local feature `tx_volume`.
- [ ] Include local feature `fee_ratio`.
- [ ] Include local feature `input_count`.
- [ ] Include local feature `output_count`.
- [ ] Include neighborhood feature `neighbor_illicit_ratio`.
- [ ] Include neighborhood feature `parent_time_delta`.
- [ ] Include neighborhood feature `degree_centrality`.
- [ ] Output `threat_score`.
- [ ] `threat_score` must be in the range 0-100.
- [ ] `threat_score` must be derived from illicit/anomalous model confidence or probability.
- [ ] Hold out a portion of the augmented Elliptic set for validation.
- [ ] Do not report only training-set performance in the write-up.

## Section 8 Explainability

- [ ] GNNExplainer must isolate the smallest high-impact subgraph responsible for a node classification.
- [ ] GNNExplainer output must back the peel-chain visualization.
- [ ] SHAP/TreeSHAP must produce human-readable contribution rows.
- [ ] SHAP/TreeSHAP must produce `contribution_percentage` breakdowns.
- [ ] Contribution percentages must be normalized or scaled to sum to `overall_threat_score` exactly.
- [ ] Exact contribution sums must be confirmed for every alert.

## Section 9 Dossier Generation

- [ ] Use an HTML/CSS dossier template.
- [ ] Render the template with Jinja2.
- [ ] Include an agency header.
- [ ] Include an evidence summary.
- [ ] Include a feature attribution table.
- [ ] Include a subgraph visualization.
- [ ] Include the real `chain_of_custody_hash`.
- [ ] Render the dossier via `weasyprint` on `POST /api/generate-dossier`.
- [ ] Target render time must be under approximately 2 seconds.
- [ ] Write output to a local reports directory.
- [ ] Expose output through `download_url`.
- [ ] Expose output through `/api/downloads/...` as a static file.

## Section 10 Non-Functional Requirements

- [ ] Runtime must be 100% offline.
- [ ] Target runtime must be Linux.
- [ ] There must be no runtime network calls anywhere in the pipeline.
- [ ] GeoIP must be local and offline.
- [ ] ML inference must be local and offline.
- [ ] PDF generation must be local and offline.
- [ ] `/api/alerts` pagination is required.
- [ ] `/api/alerts` pagination must remain correct at realistic dataset scale.
- [ ] Standardized error responses are required on every endpoint.
- [ ] Unknown `tx_id` must return standardized error responses.
- [ ] Malformed ingest file must return standardized error responses.
- [ ] Ingestion must use `polars`/`duckdb`.
- [ ] Bulk CSV parsing must not use plain pandas.
- [ ] Bulk JSON parsing must not use plain pandas.
- [ ] Full pipeline must run end-to-end via a single command/script.
- [ ] End-to-end command must cover ingest.
- [ ] End-to-end command must cover graph construction.
- [ ] End-to-end command must cover GNN.
- [ ] End-to-end command must cover XAI.
- [ ] End-to-end command must cover API readiness.
- [ ] End-to-end command must run on a clean Linux machine.
- [ ] End-to-end command must run with networking disabled.
- [ ] Final target validation should be run after `nmcli networking off`.

## Section 11 Out Of Scope

- [ ] Do not implement frontend features in this backend scope.
- [ ] Do not implement authentication.
- [ ] Do not implement multi-investigator support.
- [ ] Treat `investigator_id` as a fixed demo string.
- [ ] Do not use real seized data.
- [ ] Do not use live-intercept data.
- [ ] Use synthetic or augmented dataset only.
