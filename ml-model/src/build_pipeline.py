"""
ShadowTrace-XAI :: Elliptic Bitcoin Dataset Engineering Pipeline
=================================================================

Turns the raw Elliptic CSVs into a PyG-ready (nodes.csv, edges.csv) pair with:
  - exact preservation of the original 203,769 nodes / 234,355 edges
  - hard per-time-step partitioning (no cross-time-step edges, verified not assumed)
  - class remap: illicit(1)->1, licit(2)->0, unknown->-1
  - synthetic OSINT telemetry (ASN category, port, Tor/VPN flags) sampled
    INDEPENDENTLY of the label, so no column can act as a leakage shortcut
  - a CIOH-style entity-clustering heuristic (via connected components),
    with large hub clusters flagged and excluded from further heuristic linking
  - a synthetic "change output" heuristic on edges
  - synthetic wallet-reuse "peel chain" edges layered on top of (not replacing)
    the original edge list, clearly tagged edge_type='heuristic_reuse'
"""

import numpy as np
import pandas as pd
import networkx as nx
from scipy.sparse import coo_matrix
from scipy.sparse.csgraph import connected_components

RNG = np.random.default_rng(42)

# Point directly to the folder in your src directory
RAW_DIR = "elliptic_bitcoin_dataset"
OUT_NODES = "nodes.csv"
OUT_EDGES = "edges.csv"

# ---------------------------------------------------------------------------
# 1. Load raw data, preserving every row
# ---------------------------------------------------------------------------
feat = pd.read_csv(f"{RAW_DIR}/elliptic_txs_features.csv", header=None)
n_feat_cols = feat.shape[1] - 2  # excl txId, time_step
feat.columns = ["txId", "time_step"] + [f"feat_{i+1}" for i in range(n_feat_cols)]

classes = pd.read_csv(f"{RAW_DIR}/elliptic_txs_classes.csv")
classes["class"] = classes["class"].map({"1": 1, "2": 0, "unknown": -1})

edges = pd.read_csv(f"{RAW_DIR}/elliptic_txs_edgelist.csv")
edges = edges.rename(columns={"txId1": "source", "txId2": "target"})
edges["edge_type"] = "original"

assert feat.shape[0] == 203_769, f"node count changed: {feat.shape[0]}"
assert edges.shape[0] == 234_355, f"edge count changed: {edges.shape[0]}"

nodes = feat.merge(classes, on="txId", how="left")
assert nodes["class"].isna().sum() == 0

# sanity counts against the spec
vc = nodes["class"].value_counts()
print("Label counts -> illicit(1):", vc.get(1, 0), "licit(0):", vc.get(0, 0),
      "unknown(-1):", vc.get(-1, 0))

# ---------------------------------------------------------------------------
# 2. Temporal integrity check
# ---------------------------------------------------------------------------
ts_lookup = nodes.set_index("txId")["time_step"]
src_ts = edges["source"].map(ts_lookup)
dst_ts = edges["target"].map(ts_lookup)
cross_ts_edges = int((src_ts != dst_ts).sum())
if cross_ts_edges != 0:
    raise RuntimeError(f"{cross_ts_edges} original edges cross a time-step boundary")
print("Cross-time-step edges in raw data:", cross_ts_edges, "(must be 0)")

# ---------------------------------------------------------------------------
# 3. CIOH-proxy entity clustering via per-time-step community detection
# ---------------------------------------------------------------------------
id_to_idx = {tx: i for i, tx in enumerate(nodes["txId"])}
row = edges["source"].map(id_to_idx).to_numpy()
col = edges["target"].map(id_to_idx).to_numpy()
n = len(nodes)

cluster_id = np.full(n, -1, dtype=np.int64)
next_cluster = 0
for ts, grp_idx in nodes.groupby("time_step").indices.items():
    idx_set = set(grp_idx.tolist())
    mask = np.isin(row, list(idx_set)) & np.isin(col, list(idx_set))
    G = nx.Graph()
    G.add_nodes_from(idx_set)
    G.add_edges_from(zip(row[mask].tolist(), col[mask].tolist()))
    communities = nx.algorithms.community.louvain_communities(G, seed=42)
    for comm in communities:
        for node_idx in comm:
            cluster_id[node_idx] = next_cluster
        next_cluster += 1

nodes["cioh_cluster_id"] = cluster_id
n_components = next_cluster

cluster_sizes = nodes["cioh_cluster_id"].value_counts()
hub_threshold = cluster_sizes.quantile(0.995)
vasp_like_clusters = set(cluster_sizes[cluster_sizes >= hub_threshold].index)
nodes["is_vasp_excluded_cluster"] = nodes["cioh_cluster_id"].isin(vasp_like_clusters).astype(int)
print(f"CIOH-proxy clusters: {n_components:,} total (median size "
      f"{int(cluster_sizes.median())}); {len(vasp_like_clusters)} flagged as "
      f"VASP-like hubs (excluded from peel-chain linking)")

# ---------------------------------------------------------------------------
# 4. Synthetic change-output detection on the ORIGINAL edges
# ---------------------------------------------------------------------------
synth_btc_value = RNG.lognormal(mean=-3.0, sigma=1.2, size=len(edges))
satoshis = np.round(synth_btc_value * 1e8).astype(np.int64)
is_round = (satoshis % 1_000_000 == 0)
same_cluster = (nodes["cioh_cluster_id"].to_numpy()[row] == nodes["cioh_cluster_id"].to_numpy()[col])
edges["synthetic_output_btc"] = np.round(synth_btc_value, 8)
edges["is_change_output"] = (same_cluster & ~is_round).astype(int)

change_recv = edges.groupby("target")["is_change_output"].max()
nodes["any_change_received"] = nodes["txId"].map(change_recv).fillna(0).astype(int)
print("Original edges flagged as synthetic change output:",
      int(edges["is_change_output"].sum()), "/", len(edges))

# ---------------------------------------------------------------------------
# 5. Synthetic wallet-reuse "peel chain" edges (address pooling)
# ---------------------------------------------------------------------------
existing_pairs = set(zip(edges["source"], edges["target"])) | set(zip(edges["target"], edges["source"]))
peel_rows = []
non_hub = nodes.loc[nodes["is_vasp_excluded_cluster"] == 0, ["txId", "cioh_cluster_id", "time_step"]]
for cid, grp in non_hub.groupby("cioh_cluster_id"):
    if len(grp) < 3:
        continue
    tx_ids = grp["txId"].tolist()
    for a, b in zip(tx_ids[:-1], tx_ids[1:]):
        if (a, b) in existing_pairs or (b, a) in existing_pairs:
            continue
        peel_rows.append((a, b))

peel_df = pd.DataFrame(peel_rows, columns=["source", "target"])
peel_df["edge_type"] = "heuristic_reuse"
peel_df["synthetic_output_btc"] = np.round(RNG.lognormal(-3.0, 1.2, size=len(peel_df)), 8)
peel_df["is_change_output"] = 1

peel_src_ts = peel_df["source"].map(ts_lookup)
peel_dst_ts = peel_df["target"].map(ts_lookup)
assert (peel_src_ts == peel_dst_ts).all(), "synthetic peel-chain edges crossed a time step!"
print(f"Synthetic peel-chain (wallet reuse) edges added: {len(peel_df):,}")

all_edges = pd.concat([edges, peel_df], ignore_index=True)

# ---------------------------------------------------------------------------
# 6. Synthetic OSINT telemetry
# ---------------------------------------------------------------------------
asn_categories = ["residential_isp", "datacenter_cloud", "mobile_carrier",
                   "high_risk_vpn", "tor_exit"]
asn_probs = [0.42, 0.28, 0.18, 0.08, 0.04]
port_categories = ["p_8333_mainnet", "p_8332_rpc", "p_18333_testnet",
                    "p_9050_tor_socks", "p_other_nonstandard"]
port_probs = [0.55, 0.15, 0.10, 0.10, 0.10]

n_nodes = len(nodes)
nodes["asn_category"] = RNG.choice(asn_categories, size=n_nodes, p=asn_probs)
nodes["port_category"] = RNG.choice(port_categories, size=n_nodes, p=port_probs)
nodes["is_tor_exit"] = (nodes["asn_category"] == "tor_exit").astype(int)
nodes["is_high_risk_vpn_asn"] = (nodes["asn_category"] == "high_risk_vpn").astype(int)

nodes["_synthetic_ip"] = [
    ".".join(str(x) for x in RNG.integers(1, 255, size=4)) for _ in range(n_nodes)
]

xtab = pd.crosstab(nodes["asn_category"], nodes["class"], normalize="columns")
print("\nASN-category share by class (columns should look alike -> no shortcut):")
print(xtab.round(3))

one_hot_asn = pd.get_dummies(nodes["asn_category"], prefix="asn").astype(int)
one_hot_port = pd.get_dummies(nodes["port_category"], prefix="port").astype(int)
nodes = pd.concat([nodes.drop(columns=["asn_category", "port_category", "_synthetic_ip"]),
                    one_hot_asn, one_hot_port], axis=1)

# ---------------------------------------------------------------------------
# 7. Final column ordering + numeric-only guarantee
# ---------------------------------------------------------------------------
feature_cols = [c for c in nodes.columns if c.startswith("feat_")]
osint_cols = [c for c in nodes.columns if c.startswith("asn_") or c.startswith("port_")] \
             + ["is_tor_exit", "is_high_risk_vpn_asn"]
heuristic_cols = ["cioh_cluster_id", "is_vasp_excluded_cluster", "any_change_received"]

ordered_cols = ["txId", "class", "time_step"] + feature_cols + heuristic_cols + osint_cols
nodes = nodes[ordered_cols]

non_numeric = nodes.drop(columns=["txId"]).select_dtypes(exclude=[np.number]).columns.tolist()
assert not non_numeric, f"non-numeric columns leaked into nodes.csv: {non_numeric}"

edge_cols = ["source", "target", "edge_type", "synthetic_output_btc", "is_change_output"]
all_edges = all_edges[edge_cols]

nodes.to_csv(OUT_NODES, index=False)
all_edges.to_csv(OUT_EDGES, index=False)

print(f"\nWrote {OUT_NODES}: {nodes.shape[0]:,} rows x {nodes.shape[1]} columns")
print(f"Wrote {OUT_EDGES}: {all_edges.shape[0]:,} rows "
      f"({(all_edges.edge_type=='original').sum():,} original + "
      f"{(all_edges.edge_type=='heuristic_reuse').sum():,} synthetic reuse)")