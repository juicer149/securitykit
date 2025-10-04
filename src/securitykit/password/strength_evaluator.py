import re
from typing import Any
from securitykit.logging_config import logger
from securitykit.password.defaults import PASSWORD_RULES, PASSWORD_BIT_INDEX


class PasswordStrengthEvaluator:
    """
    Central engine for password complexity evaluation.
    Provides granular rule checking, scoring, and structured feedback.
    """

    def __init__(self, policy):
        self.policy = policy

    # --- Subroutines ---------------------------------------------------

    def check_length_rule(self, password: str) -> tuple[int, list[str], int]:
        """Evaluate the minimum-length complexity rule."""
        mask = 0
        missing = []
        bit_index = 0

        if len(password) >= self.policy.complexity_min_length:
            mask |= 1 << bit_index
        else:
            missing.append(f"min_length>={self.policy.complexity_min_length}")

        return mask, missing, bit_index + 1

    def check_regex_rules(self, password: str, start_index: int = 1) -> tuple[int, list[str]]:
        """Evaluate regex-based rules (uppercase, lowercase, digit, special)."""
        mask = 0
        missing = []
        index = start_index

        for name, regex in PASSWORD_RULES.items():
            if re.search(regex, password):
                mask |= 1 << index
            else:
                missing.append(name)
            index += 1

        return mask, missing

    def compute_bitmask(self, password: str) -> tuple[int, list[str]]:
        """Compute global bitmask and missing list for all rules."""
        mask, missing, next_index = self.check_length_rule(password)
        regex_mask, regex_missing = self.check_regex_rules(password, start_index=next_index)
        return mask | regex_mask, missing + regex_missing

    # --- Static utility methods ---------------------------------------

    @classmethod
    def count_fulfilled(cls, mask: int) -> int:
        """Return number of fulfilled rules from bitmask."""
        return bin(mask).count("1")

    @classmethod
    def describe_strength(cls, fulfilled: int) -> str:
        """Return human-readable label for fulfilled count."""
        match fulfilled:
            case 0:
                return "Extremely Weak"
            case 1:
                return "Very Weak"
            case 2:
                return "Weak"
            case 3:
                return "Moderate"
            case 4:
                return "Strong"
            case _:
                return "Very Strong"

    @classmethod
    def describe_missing(cls, mask: int) -> list[str]:
        """Return names of missing rules from bitmask."""
        return [name for bit, name in PASSWORD_BIT_INDEX.items() if not (mask & (1 << bit))]

    # --- Main Evaluation Interface ------------------------------------

    def evaluate(self, password: str) -> dict[str, Any]:
        """
        Evaluate password strength and return structured feedback.
        """
        mask, missing = self.compute_bitmask(password)
        fulfilled = self.count_fulfilled(mask)
        strength = self.describe_strength(fulfilled)

        logger.info(
            "Password evaluated: strength=%s, fulfilled=%d/5, missing=%s",
            strength, fulfilled, missing,
        )

        return {
            "strength": strength,
            "fulfilled_rules": fulfilled,
            "missing": missing,
            "mask": mask,
        }

    # --- Alias for API usage ------------------------------------------

    def summarize(self, password: str) -> dict[str, Any]:
        """Alias for evaluate() — preserved for backward compatibility."""
        return self.evaluate(password)
