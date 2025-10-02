from securitykit.bench.analyzer import ResultAnalyzer
from securitykit.bench.engine import BenchmarkResult

class P:
    def __init__(self, a, b):
        self.a = a
        self.b = b

def make_res(a, b, median, target):
    return BenchmarkResult(P(a, b), [median], target)

def test_balanced_handles_single_value_dimensions():
    schema = {
        "a": [1, 2, 3],
        "b": [10],   # single-value dimension
    }
    analyzer = ResultAnalyzer(schema)  # type: ignore
    target = 100
    results = [
        make_res(1, 10, 90, target),
        make_res(2, 10, 100, target),
        make_res(3, 10, 110, target),
    ]
    # near_all med bred tolerance → balanced gren används
    near = analyzer.filter_near(results, target, tolerance=0.2)
    chosen = analyzer.balanced(near)
    assert chosen in results  # inget undantag, korrekt retur
