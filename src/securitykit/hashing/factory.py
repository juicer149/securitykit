from __future__ import annotations

from typing import Any, Mapping

from securitykit import config
from securitykit.hashing.registry import load_all
from securitykit.hashing.algorithm import Algorithm
from securitykit.hashing.policy_registry import get_policy_class
from securitykit.hashing.interfaces import PolicyProtocol
from securitykit.utils.config_loader import ConfigLoader


class HashingFactory:
    """
    Factory for constructing hashing policies and algorithm façade instances.

    Characteristics:
      - Prefix-based configuration (e.g. ARGON2_TIME_COST) resolved via ConfigLoader
      - Lazy discovery of registered algorithms/policies (load_all())
      - Pure configuration mapping → objects (no mutation)
      - Pepper is *not* passed explicitly; pepper strategies read PEPPER_* keys
        internally through the same configuration mapping forwarded to Algorithm.
    """

    def __init__(self, config_map: Mapping[str, Any]):
        self._config_map = config_map
        self._loader = ConfigLoader(config_map)
        self._policy_cache: dict[str, PolicyProtocol] = {}

    def _resolve_variant(self) -> str:
        """
        Determine the active hash variant.
        Falls back to global defaults if HASH_VARIANT not provided.
        """
        return str(
            self._config_map.get("HASH_VARIANT", config.DEFAULTS["HASH_VARIANT"])
        ).lower()

    def get_policy(self, name: str) -> PolicyProtocol:
        """
        Build (or fetch cached) policy instance based on prefixed keys.
        Example: ARGON2_TIME_COST -> time_cost
        """
        load_all()
        key = name.lower()
        if key in self._policy_cache:
            return self._policy_cache[key]

        policy_cls = get_policy_class(name)
        policy = self._loader.build(
            policy_cls,
            prefix=f"{name.upper()}_",
            name=f"policy '{name}'",
        )
        self._policy_cache[key] = policy
        return policy

    def get_policy_dict(self, name: str) -> dict[str, Any]:
        """
        Return a serializable dict representation of the policy (using to_dict()
        if available; otherwise reflect public attributes).
        """
        policy = self.get_policy(name)
        if hasattr(policy, "to_dict"):
            return policy.to_dict()  # type: ignore[no-any-return]
        return {
            attr: getattr(policy, attr)
            for attr in dir(policy)
            if not attr.startswith("_")
            and not callable(getattr(policy, attr))
        }

    def get_algorithm(self) -> Algorithm:
        """
        Construct the Algorithm façade with the resolved policy.
        The entire configuration mapping is forwarded so the pepper pipeline
        and any future config-driven behaviors can access PEPPER_* and other keys.
        """
        variant = self._resolve_variant()
        policy = self.get_policy(variant)
        return Algorithm(variant=variant, policy=policy, config=self._config_map)
