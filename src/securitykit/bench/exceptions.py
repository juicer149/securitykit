# securitykit/bench/exceptions.py
"""
Custom exception hierarchy for benchmark-related errors in SecurityKit.
"""
from securitykit.exceptions import SecurityKitError


class BenchmarkError(SecurityKitError):
    """Base class for all benchmark-related errors."""


class MissingBenchSchemaError(BenchmarkError):
    """Raised when a policy lacks BENCH_SCHEMA and cannot be benchmarked."""
