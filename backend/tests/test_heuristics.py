import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shadowtrace.graph_builder import build_graph
from shadowtrace.synthetic import timestamp_from_time_step


def row(tx_id, inputs, outputs, input_amounts, output_amounts, second=0):
    return {
        "tx_id": tx_id,
        "label": "illicit",
        "timestamp": timestamp_from_time_step(1, second),
        "time_step": 1,
        "src_ip": f"185.220.101.{10 + second}",
        "dst_ip": "8.8.8.8",
        "src_port": 8333,
        "dst_port": 8333,
        "asn": "AS208323",
        "asn_description": "Tor Transit",
        "country": "DE",
        "input_addresses": inputs,
        "output_addresses": outputs,
        "input_amounts": input_amounts,
        "output_amounts": output_amounts,
        "features": {},
        "heuristics": {},
    }


def test_cioh_assigns_same_entity_to_common_inputs():
    rows = [row("tx_a", ["bc1qin1", "bc1qin2"], ["bc1qout1", "1pay"], [50_000, 50_000], [80_000, 10_000])]
    graph, _ = build_graph(rows)
    assert graph.nodes["bc1qin1"]["entity_id"] == graph.nodes["bc1qin2"]["entity_id"]
    assert rows[0]["heuristics"]["cioh_entity_ids"] == [graph.nodes["bc1qin1"]["entity_id"]]


def test_change_detection_prefers_script_continuity_and_decimal_pattern():
    rows = [row("tx_b", ["bc1qin"], ["1roundpay", "bc1qchange"], [100_000_000], [8_000_000, 91_990_123])]
    build_graph(rows)
    assert rows[0]["heuristics"]["change_address"] == "bc1qchange"


def test_change_detection_leaves_single_output_payment_unmarked():
    rows = [row("tx_single_output", ["bc1qin"], ["bc1qrecipient"], [100_000_000], [99_990_000])]
    graph, _ = build_graph(rows)
    assert rows[0]["heuristics"]["change_address"] is None
    assert graph.nodes["bc1qrecipient"]["type"] == "output"


def test_address_reuse_is_detected_even_when_change_candidate_differs():
    rows = [row("tx_reuse", ["bc1qin"], ["bc1qin", "bc1qchange"], [100_000_000], [8_000_000, 91_990_123])]
    build_graph(rows)
    assert rows[0]["heuristics"]["change_address"] == "bc1qchange"
    assert rows[0]["heuristics"]["address_reuse"] == ["bc1qin"]
    assert rows[0]["features"]["change_reuse"] == 1.0


def test_peel_chain_requires_topology_tight_time_and_repeated_small_amounts():
    rows = [
        row("tx_1", ["bc1qseed"], ["1pay1", "bc1qchange1"], [200_000_000], [8_000_000, 191_990_000], 0),
        row("tx_2", ["bc1qchange1"], ["1pay2", "bc1qchange2"], [191_990_000], [8_010_000, 183_970_000], 8),
        row("tx_3", ["bc1qchange2"], ["1pay3", "bc1qchange3"], [183_970_000], [7_990_000, 175_970_000], 16),
    ]
    build_graph(rows)
    assert all(item["heuristics"]["peel_chain"] for item in rows)
    assert rows[1]["features"]["neighbor_illicit_ratio"] == 1.0


def test_fan_out_and_fan_in_are_detected_from_address_counts():
    fan_out = row("fan_out", ["bc1qone"], [f"bc1qo{i}" for i in range(5)], [100_000_000], [10_000_000] * 5, 0)
    fan_in = row("fan_in", [f"bc1qi{i}" for i in range(5)], ["bc1qcashout"], [10_000_000] * 5, [49_900_000], 1)
    rows = [fan_out, fan_in]
    build_graph(rows)
    assert fan_out["heuristics"]["fan_out"] is True
    assert fan_in["heuristics"]["fan_in"] is True


def test_fan_patterns_require_rapid_context_when_linked():
    parent = row("parent", ["bc1qseed"], ["bc1qlink"], [100_000_000], [99_990_000], 0)
    stale_fan_out = row(
        "stale_fan_out",
        ["bc1qlink"],
        [f"bc1qstale{i}" for i in range(5)],
        [99_990_000],
        [10_000_000] * 5,
        90,
    )
    rows = [parent, stale_fan_out]
    build_graph(rows)
    assert stale_fan_out["heuristics"]["fan_out"] is False

    rapid_fan_out = row(
        "rapid_fan_out",
        ["bc1qlink2"],
        [f"bc1qrapid{i}" for i in range(5)],
        [99_990_000],
        [10_000_000] * 5,
        24,
    )
    rapid_parent = row("rapid_parent", ["bc1qseed2"], ["bc1qlink2"], [100_000_000], [99_990_000], 0)
    rows = [rapid_parent, rapid_fan_out]
    build_graph(rows)
    assert rapid_fan_out["heuristics"]["fan_out"] is True

    fan_in_inputs = [f"bc1qinlinked{i}" for i in range(5)]
    stale_parents = [
        row(f"stale_parent_{idx}", [f"bc1qseedstale{idx}"], [input_addr], [20_000_000], [19_990_000], idx)
        for idx, input_addr in enumerate(fan_in_inputs)
    ]
    stale_fan_in = row("stale_fan_in", fan_in_inputs, ["bc1qcashout"], [19_990_000] * 5, [99_000_000], 90)
    rows = stale_parents + [stale_fan_in]
    build_graph(rows)
    assert stale_fan_in["heuristics"]["fan_in"] is False

    rapid_fan_in_inputs = [f"bc1qinrapid{i}" for i in range(5)]
    rapid_parents = [
        row(f"rapid_parent_{idx}", [f"bc1qseedrapid{idx}"], [input_addr], [20_000_000], [19_990_000], idx)
        for idx, input_addr in enumerate(rapid_fan_in_inputs)
    ]
    rapid_fan_in = row("rapid_fan_in", rapid_fan_in_inputs, ["bc1qcashout2"], [19_990_000] * 5, [99_000_000], 24)
    rows = rapid_parents + [rapid_fan_in]
    build_graph(rows)
    assert rapid_fan_in["heuristics"]["fan_in"] is True


def test_exchange_wallet_outputs_are_marked_inline():
    rows = [row("tx_exchange", ["bc1qin"], ["1exchange", "bc1qchange"], [100_000_000], [8_000_000, 91_990_000])]
    rows[0]["heuristics"]["exchange_addresses"] = ["1exchange"]
    graph, _ = build_graph(rows)
    assert graph.nodes["1exchange"]["label"] == "WalletAddress"
    assert graph.nodes["1exchange"]["type"] == "exchange"
    assert rows[0]["heuristics"]["terminal_exchange"] is True
    assert rows[0]["features"]["terminal_exchange"] == 1.0


def test_wallet_role_preserves_change_output_when_later_spent():
    rows = [
        row("parent", ["bc1qseed"], ["1payment", "bc1qchange"], [100_000_000], [8_000_000, 91_990_000]),
        row("child", ["bc1qchange"], ["1nextpay", "bc1qnextchange"], [91_990_000], [8_000_000, 83_980_000], 8),
    ]

    graph, _ = build_graph(rows)

    assert rows[0]["heuristics"]["change_address"] == "bc1qchange"
    assert graph.nodes["bc1qchange"]["type"] == "change"
    assert graph.has_edge("parent", "bc1qchange")
    assert graph.has_edge("bc1qchange", "child")


def test_wallet_role_preserves_exchange_output_when_later_spent():
    rows = [
        row("cashout", ["bc1qseed"], ["1exchange", "bc1qchange"], [100_000_000], [8_000_000, 91_990_000]),
        row("exchange_sweep", ["1exchange"], ["bc1qinternal"], [8_000_000], [7_990_000], 8),
    ]
    rows[0]["heuristics"]["exchange_addresses"] = ["1exchange"]

    graph, _ = build_graph(rows)

    assert graph.nodes["1exchange"]["type"] == "exchange"
    assert graph.has_edge("cashout", "1exchange")
    assert graph.has_edge("1exchange", "exchange_sweep")
