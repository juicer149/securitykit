"""
Default constants and regex rules for SecurityKit password system.
Centralized here for reuse across policy, validator, and evaluator.
"""

# --- Hard bounds ---
PASSWORD_MIN_LENGTH = 1
PASSWORD_MAX_LENGTH = 4096
PASSWORD_RECOMMENDED_MIN_LENGTH = 12
PASSWORD_UNUSUALLY_HIGH_MIN_LENGTH = 128

# --- Default policy values ---
DEFAULT_MIN_LENGTH = 8
DEFAULT_REQUIRE_UPPER = True
DEFAULT_REQUIRE_LOWER = True
DEFAULT_REQUIRE_DIGIT = True
DEFAULT_REQUIRE_SPECIAL = True

# --- Complexity evaluation defaults ---
DEFAULT_COMPLEXITY_RULE = 3
DEFAULT_COMPLEXITY_MIN_LENGTH = 12  # Minimum contributing to complexity score

# --- Regex rules ---
PASSWORD_RULES: dict[str, str] = {
    "uppercase": r"[A-Z]",
    "lowercase": r"[a-z]",
    "digit": r"\d",
    "special": r"[^A-Za-z0-9]",
}

# --- Bit index mapping for UX (0..4) ---
PASSWORD_BIT_INDEX: dict[int, str] = {
    0: "min_length",
    1: "uppercase",
    2: "lowercase",
    3: "digit",
    4: "special",
}
