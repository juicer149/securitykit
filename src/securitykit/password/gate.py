# securitykit/password/gate.py
"""
PasswordGate
============

Fast, pre-authentication password screening component.

This module provides `PasswordGate`, a lightweight layer designed to
quickly reject invalid or non-compliant passwords *before* any database
lookups or hashing are performed.

Unlike `PasswordValidator`, which raises exceptions for detailed validation,
`PasswordGate` focuses on performance and returns a boolean decision:
True → password passes configured policy
False → password too weak or non-compliant

It can also return structured feedback if desired (for UX or metrics).

Typical use:
------------
from securitykit.password.gate import PasswordGate
from securitykit.password.policy import PasswordPolicy

policy = PasswordPolicy(min_length=12, complexity_rule=3)
gate = PasswordGate(policy)

if not gate.allow(password):
    return {"error": "Invalid password"}  # short-circuit before DB lookup
"""

from __future__ import annotations
from typing import Any, Dict

from securitykit.password.policy import PasswordPolicy
from securitykit.password.strength_evaluator import PasswordStrengthEvaluator
from securitykit.password.defaults import PASSWORD_BIT_INDEX
from securitykit.logging_config import logger


class PasswordGate:
    """
    Fast password pre-check and complexity enforcement gate.

    Used to reject invalid passwords early in login or registration flows.
    """

    __slots__ = ("policy", "evaluator", "_required_mask")

    def __init__(self, policy: PasswordPolicy):
        if not isinstance(policy, PasswordPolicy):
            raise TypeError("policy must be a PasswordPolicy instance")
        self.policy = policy
        self.evaluator = PasswordStrengthEvaluator(policy)
        self._required_mask = self._build_required_mask()

    # ------------------------------------------------------------------
    # Internal utilities
    # ------------------------------------------------------------------
    def _build_required_mask(self) -> int:
        """
        Compute a bitmask of required character-class features according to policy.

        NOTE:
        - We deliberately DO NOT require the 'min_length' complexity bit here.
          Hard length is enforced numerically against policy.min_length in allow().
          The complexity 'min_length' bit (based on policy.complexity_min_length)
          remains a soft factor that only influences the fulfilled count used by
          the complexity_rule check.
        """
        mask = 0
        for bit, name in PASSWORD_BIT_INDEX.items():
            if name == "min_length":
                # Do not include min_length bit in the required mask
                continue
            required_attr = f"require_{name}"
            if getattr(self.policy, required_attr, False):
                mask |= 1 << bit
        return mask

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------
    def allow(self, password: str) -> bool:
        """
        Return True if password passes all required policy constraints.

        This is a fast path version of PasswordValidator.validate()
        — it does not raise exceptions or log per-rule failures.
        """
        if not password:
            return False

        mask, _ = self.evaluator.compute_bitmask(password)

        # Hard bounds check (fast numeric compare)
        length_ok = self.policy.min_length <= len(password) <= self.policy.PASSWORD_MAX_LENGTH
        if not length_ok:
            return False

        # Ensure all required character-class bits are set
        if (mask & self._required_mask) != self._required_mask:
            return False

        # Soft complexity threshold (counts all fulfilled bits, including the
        # complexity length bit if complexity_min_length is met)
        fulfilled = bin(mask).count("1")
        if fulfilled < self.policy.complexity_rule:
            return False

        return True

    def reject_reason(self, password: str) -> Dict[str, Any]:
        """
        Return a structured reason for rejection.
        Useful for UX or telemetry.
        """
        mask, missing = self.evaluator.compute_bitmask(password)
        fulfilled = bin(mask).count("1")

        reasons = []
        if len(password) < self.policy.min_length:
            reasons.append(f"min_length<{self.policy.min_length}")
        if len(password) > self.policy.PASSWORD_MAX_LENGTH:
            reasons.append(f"max_length>{self.policy.PASSWORD_MAX_LENGTH}")
        # Report missing required character classes (min_length bit is not required here)
        if (mask & self._required_mask) != self._required_mask:
            missing_required = [
                name for bit, name in PASSWORD_BIT_INDEX.items()
                if name != "min_length"  # length handled numerically above
                and (self._required_mask & (1 << bit))
                and not (mask & (1 << bit))
            ]
            reasons.extend(missing_required)
        if fulfilled < self.policy.complexity_rule:
            reasons.append(f"complexity<{self.policy.complexity_rule}")

        return {
            "allowed": not reasons,
            "fulfilled": fulfilled,
            "required": bin(self._required_mask).count("1"),
            "missing": missing,
            "reasons": reasons,
        }

    def quick_strength(self, password: str) -> str:
        """
        Return only the human-readable strength level (Extremely Weak..Very Strong).
        """
        mask, _ = self.evaluator.compute_bitmask(password)
        fulfilled = bin(mask).count("1")
        return self.evaluator.describe_strength(fulfilled)

    # ------------------------------------------------------------------
    # Logging / diagnostics
    # ------------------------------------------------------------------
    def log_decision(self, password: str) -> None:
        """
        Log the decision (strength + allow result) without leaking password.
        """
        result = self.reject_reason(password)
        status = "ALLOW" if result["allowed"] else "DENY"
        logger.info(
            "PasswordGate decision=%s, fulfilled=%d/%d, reasons=%s",
            status,
            result["fulfilled"],
            result["required"],
            result["reasons"],
        )
