from __future__ import annotations

from securitykit.password.policy import PasswordPolicy
from securitykit.password.strength_evaluator import PasswordStrengthEvaluator
from securitykit.exceptions import PasswordValidationError


class PasswordValidator:
    """
    Enforces password complexity rules based on a given PasswordPolicy.

    Performs:
      1. Hard checks (length and required character classes)
      2. Soft complexity scoring via PasswordStrengthEvaluator
    """

    def __init__(self, policy: PasswordPolicy):
        if not isinstance(policy, PasswordPolicy):
            raise TypeError("policy must be an instance of PasswordPolicy")
        self.policy = policy
        self.evaluator = PasswordStrengthEvaluator(policy)

    # ------------------------------------------------------------------
    # Core validation
    # ------------------------------------------------------------------
    def validate(self, password: str) -> None:
        """
        Validate password against both hard and soft policy constraints.
        Raises PasswordValidationError if violation occurs.
        """
        # --- Hard bounds ---
        if len(password) < self.policy.min_length:
            raise PasswordValidationError(
                f"Password must be at least {self.policy.min_length} characters long."
            )

        if len(password) > self.policy.PASSWORD_MAX_LENGTH:
            raise PasswordValidationError( 
                f"Password too long (max {self.policy.PASSWORD_MAX_LENGTH} characters)."
            )

        # --- Evaluate complexity without logging noise ---
        # Useing compute_bitmask to avoid INFO logs on every validation
        mask, missing = self.evaluator.compute_bitmask(password)
        fulfilled = bin(mask).count("1")

        # --- Enforce explicit hard booleans ---
        # borde jag här skapa ett nytt undantag för att skilja på policyfel och valideringsfel?
        if self.policy.require_upper and "uppercase" in missing:
            raise PasswordValidationError("Password must contain at least one uppercase letter.")
        if self.policy.require_lower and "lowercase" in missing:
            raise PasswordValidationError("Password must contain at least one lowercase letter.")
        if self.policy.require_digit and "digit" in missing:
            raise PasswordValidationError("Password must contain at least one digit.")
        if self.policy.require_special and "special" in missing:
            raise PasswordValidationError("Password must contain at least one special character.")

        # --- Soft complexity threshold (1–5 rules fulfilled) ---
        if fulfilled < self.policy.complexity_rule:
            human_missing = [m for m in missing if not m.startswith("min_length")]
            raise PasswordValidationError( 
                f"Password complexity insufficient: requires ≥{self.policy.complexity_rule}/5 rules, "
                f"but only {fulfilled}/5 met. Missing: {', '.join(human_missing) or 'none'}"
            )

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------
    def strength_label(self, password: str) -> str:
        """Return a simple textual strength label for UX or logging."""
        result = self.evaluator.evaluate(password)
        return result["strength"]

    def feedback(self, password: str) -> dict[str, str]:
        """Return user-friendly feedback dict for UI frameworks."""
        result = self.evaluator.evaluate(password)
        missing = result["missing"]
        fulfilled = result["fulfilled_rules"]

        message = (
            f"Password strength: {result['strength']} "
            f"({fulfilled}/5 rules satisfied, missing: {', '.join(missing) or 'none'})"
        )

        return {
            "strength": result["strength"],
            "message": message,
            "missing": ", ".join(missing) or "none",
        }
