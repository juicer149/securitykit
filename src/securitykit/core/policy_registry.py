# securitykit/core/policy_registry.py
from securitykit import logger
from securitykit.core.registry import Registry
from securitykit.exceptions import UnknownPolicyError
from securitykit.core.interfaces import PolicyProtocol


def _validate_policy(cls: type) -> None:
    """
    Extra krav för policies:
    - Måste ha en BENCH_SCHEMA (även om tom dict).
    """
    # kanske även göra en egen exception här?
    if not hasattr(cls, "BENCH_SCHEMA"):
        raise TypeError(f"Policy {cls.__name__} must define BENCH_SCHEMA.")


# Skapa registry för policies
_policy_registry = Registry("policy", validator=_validate_policy)


def register_policy(name: str):
    return _policy_registry.register(name)


def get_policy_class(name: str) -> type[PolicyProtocol]:
    try:
        return _policy_registry.get(name)
    except KeyError as e:
        raise UnknownPolicyError(str(e))


def list_policies() -> list[str]:
    return _policy_registry.list()
