# securitykit/algorithms/password.py
from securitykit.core.algorithm_registry import register_algorithm
from securitykit.core.interfaces import AlgorithmProtocol
from securitykit.policies.password import PasswordPolicy

@register_algorithm("password")
class PasswordAlgorithm(AlgorithmProtocol):
    """A no-op algorithm for testing password policy enforcement only."""

    def __init__(self, policy: PasswordPolicy | None = None) -> None:
        self.policy = policy or PasswordPolicy()

    def hash(self, password: str) -> str:
        # Not meaningful – just return the password itself
        return password

    def verify(self, stored_hash: str, password: str) -> bool:
        return stored_hash == password

    def __call__(self, password: str) -> str:
        return self.hash(password)
