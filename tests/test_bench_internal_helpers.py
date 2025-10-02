import types
from securitykit.bench import bench
from securitykit.hashing.policy_registry import get_policy_class
from securitykit.hashing.algorithm import Algorithm


def test_cartesian_empty_schema_returns_no_items():
    # _cartesian ska inte yield:a något om schema är tomt
    combos = list(bench._cartesian({}))
    assert combos == []


def test_format_policy_line_with_and_without_timing():
    Policy = get_policy_class("argon2")
    p = Policy(time_cost=2, memory_cost=65536, parallelism=1)
    keys = ["time_cost", "memory_cost", "parallelism"]

    line_plain = bench._format_policy_line(p, keys)
    assert "time_cost=2" in line_plain
    assert "→" not in line_plain

    line_timed = bench._format_policy_line(p, keys, ms=12.3456, delta_pct=5.4321)
    assert "→ 12.35 ms" in line_timed  # avrundning
    assert "Δ +5.4%" in line_timed
