"""
ShadowTrace-XAI :: Pipeline Verification Script
================================================
Run this against nodes.csv / edges.csv to mathematically confirm:
  1. Column count exceeds 170 and every column (besides txId) is numeric.
  2. No target leakage: OSINT/port/ASN distributions are statistically
     similar across licit / illicit / unknown classes (chi-square test +
     proportion table), and Tor/high-risk-VPN flags are NOT exclusive to
     the illicit class.
  3. Every edge (original AND synthetic) sits inside a single time step --
     zero cross-time-step edges.
  4. Node/label counts match the published Elliptic spec.

Exit code is non-zero if any check fails, so this can be wired into CI.
"""
import sys
import numpy as np
import pandas as pd
from scipy.stats import chi2_contingency

# Corrected paths to point to the outputs folder
NODES_PATH = "outputs/nodes.csv"
EDGES_PATH = "outputs/edges.csv"
FAILURES = []


def check(label, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}" + (f" -- {detail}" if detail else ""))
    if not condition:
        FAILURES.append(label)


nodes = pd.read_csv(NODES_PATH)
edges = pd.read_csv(EDGES_PATH)

# ---------------------------------------------------------------------
# 1. Column count + numeric-only guarantee
# ---------------------------------------------------------------------
n_cols = nodes.shape[1]
check("nodes.csv has more than 170 columns", n_cols > 170, f"actual={n_cols}")

non_numeric = nodes.drop(columns=["txId"]).select_dtypes(exclude=[np.number]).columns.tolist()
check("all non-txId node columns are numeric", len(non_numeric) == 0,
      f"non-numeric cols={non_numeric}")

feat_cols = [c for c in nodes.columns if c.startswith("feat_")]
check("original per-node features preserved", len(feat_cols) >= 165,
      f"feature columns found={len(feat_cols)}")

# ---------------------------------------------------------------------
# 2. Target leakage checks on synthetic OSINT columns
# ---------------------------------------------------------------------
labeled = nodes[nodes["class"].isin([0, 1])].copy()

asn_cols = [c for c in nodes.columns if c.startswith("asn_")]
port_cols = [c for c in nodes.columns if c.startswith("port_")]

asn_cat = labeled[asn_cols].idxmax(axis=1)
port_cat = labeled[port_cols].idxmax(axis=1)

ct_asn = pd.crosstab(asn_cat, labeled["class"])
chi2_asn, p_asn, _, _ = chi2_contingency(ct_asn)
print("\nASN-category x class contingency table:\n", ct_asn)
print(f"chi2={chi2_asn:.2f}, p-value={p_asn:.4f}")

n_obs = ct_asn.values.sum()
cramers_v_asn = np.sqrt(chi2_asn / (n_obs * (min(ct_asn.shape) - 1)))
check("ASN category not target-leaking (Cramer's V < 0.05)", cramers_v_asn < 0.05,
      f"Cramer's V={cramers_v_asn:.4f}")

ct_port = pd.crosstab(port_cat, labeled["class"])
chi2_port, p_port, _, _ = chi2_contingency(ct_port)
n_obs_p = ct_port.values.sum()
cramers_v_port = np.sqrt(chi2_port / (n_obs_p * (min(ct_port.shape) - 1)))
print("\nPort-category x class contingency table:\n", ct_port)
check("Port category not target-leaking (Cramer's V < 0.05)", cramers_v_port < 0.05,
      f"Cramer's V={cramers_v_port:.4f}")

tor_illicit_share = labeled.loc[labeled["is_tor_exit"] == 1, "class"].mean()
tor_present_both = (labeled.loc[labeled["is_tor_exit"] == 1, "class"] == 0).any() and \
                    (labeled.loc[labeled["is_tor_exit"] == 1, "class"] == 1).any()
check("Tor-exit flag appears in BOTH licit and illicit classes", tor_present_both,
      f"mean(class | is_tor_exit=1)={tor_illicit_share:.3f} (1.0 would mean exclusivity)")

vpn_present_both = (labeled.loc[labeled["is_high_risk_vpn_asn"] == 1, "class"] == 0).any() and \
                    (labeled.loc[labeled["is_high_risk_vpn_asn"] == 1, "class"] == 1).any()
check("High-risk-VPN flag appears in BOTH licit and illicit classes", vpn_present_both)

mainnet_col = "port_p_8333_mainnet"
if mainnet_col in labeled.columns:
    mainnet_both = (labeled.loc[labeled[mainnet_col] == 1, "class"] == 0).any() and \
                   (labeled.loc[labeled[mainnet_col] == 1, "class"] == 1).any()
    check("Standard mainnet port (8333) appears in BOTH classes", mainnet_both)

# ---------------------------------------------------------------------
# 3. Temporal integrity: zero cross-time-step edges, across ALL edges
# ---------------------------------------------------------------------
ts_lookup = nodes.set_index("txId")["time_step"]
src_ts = edges["source"].map(ts_lookup)
dst_ts = edges["target"].map(ts_lookup)
cross_ts = int((src_ts != dst_ts).sum())
check("zero edges cross a time-step boundary (incl. synthetic edges)", cross_ts == 0,
      f"cross-time-step edge count={cross_ts}")

if "edge_type" in edges.columns:
    print("\nEdge type breakdown:\n", edges["edge_type"].value_counts())

# ---------------------------------------------------------------------
# 4. Structural spec checks
# ---------------------------------------------------------------------
check("node count == 203,769", len(nodes) == 203_769, f"actual={len(nodes)}")
check("original edge count == 234,355",
      (edges["edge_type"] == "original").sum() == 234_355 if "edge_type" in edges.columns
      else len(edges) == 234_355)
check("time steps == 49", nodes["time_step"].nunique() == 49,
      f"actual={nodes['time_step'].nunique()}")

vc = nodes["class"].value_counts()
check("illicit(1) count == 4,545", vc.get(1, 0) == 4545, f"actual={vc.get(1, 0)}")
check("licit(0) count == 42,019", vc.get(0, 0) == 42019, f"actual={vc.get(0, 0)}")
check("unknown(-1) count == 157,205", vc.get(-1, 0) == 157205, f"actual={vc.get(-1, 0)}")

print(f"\n{'='*60}")
if FAILURES:
    print(f"RESULT: {len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("RESULT: all checks PASSED")
    sys.exit(0)