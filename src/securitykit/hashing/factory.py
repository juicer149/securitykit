from typing import Any, Mapping

from securitykit import config
from securitykit.hashing.registry import load_all
from securitykit.hashing.algorithm import Algorithm
from securitykit.hashing.policy_registry import get_policy_class
from securitykit.hashing.interfaces import PolicyProtocol
from securitykit.utils.config_loader import ConfigLoader


class HashingFactory:
    """
    Generic factory for constructing hashing policies and algorithm wrappers.

    Egenskaper:
      - Prefix-baserad config (ARGON2_*, BCRYPT_*, osv) via ConfigLoader
      - Lazy discovery: load_all() kallas vid behov
      - Stöd för global PEPPER_VALUE
      - Ingen hårdkodning av policy-fält (all parsing sker via signatur + defaults)
    """

    def __init__(self, config_map: Mapping[str, Any]):
        self._config_map = config_map
        self._loader = ConfigLoader(config_map)
        self._policy_cache: dict[str, PolicyProtocol] = {}

    def _resolve_variant(self) -> str:
        return str(
            self._config_map.get("HASH_VARIANT", config.DEFAULTS["HASH_VARIANT"])
        ).lower()

    def get_policy(self, name: str) -> PolicyProtocol:
        """
        Bygger en policy-instans baserat på prefixad konfiguration.
        Ex: ARGON2_TIME_COST => time_cost
        """
        load_all()  # ensure policies & algorithms discovered
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
        policy = self.get_policy(name)
        if hasattr(policy, "to_dict"):
            return policy.to_dict()
        # fallback om policy saknar to_dict()
        return {
            attr: getattr(policy, attr)
            for attr in dir(policy)
            if not attr.startswith("_")
            and not callable(getattr(policy, attr))
        }

    def get_algorithm(self) -> Algorithm:
        variant = self._resolve_variant()
        policy = self.get_policy(variant)
        pepper = self._config_map.get("PEPPER_VALUE") or None
        return Algorithm(variant=variant, policy=policy, pepper=pepper)
