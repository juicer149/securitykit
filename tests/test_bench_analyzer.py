from securitykit.bench.analyzer import ResultAnalyzer
from securitykit.bench.engine import BenchmarkResult


class DummyPolicy:
    def __init__(self, a, b):
        self.a = a
        self.b = b


def make_result(a, b, median, target):
    # times lista med ett värde -> median=det värdet
    return BenchmarkResult(DummyPolicy(a, b), [median], target)


def test_result_analyzer_filter_closest_balanced():
    schema = {"a": [1, 2], "b": [10, 20]}
    analyzer = ResultAnalyzer(schema)

    target = 100
    results = [
        make_result(1, 10, 90, target),
        make_result(2, 10, 105, target),
        make_result(1, 20, 98, target),
        make_result(2, 20, 140, target),
    ]

    near = analyzer.filter_near(results, target_ms=target, tolerance=0.15)
    assert all(100 * 0.85 <= r.median <= 100 * 1.15 for r in near)

    closest = analyzer.closest(results, target)
    assert closest.median == min(results, key=lambda r: abs(r.median - target)).median

    # balanced ska utvärdera spridnings-score; vi kallar bara och förväntar ett av resultaten
    balanced = analyzer.balanced(results)
    assert balanced in results
