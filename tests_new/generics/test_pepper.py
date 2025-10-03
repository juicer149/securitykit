import pytest
from ..common.helpers import VALID_PASSWORD, build_algorithm


@pytest.mark.parametrize(
    "pepper_cfg, label",
    [
        ({"PEPPER_MODE": "suffix", "PEPPER_SUFFIX": "_S3CRET"}, "suffix"),
        ({"PEPPER_MODE": "hmac", "PEPPER_HMAC_KEY": "supersecretkey"}, "hmac"),
    ],
)
def test_pepper_changes_hash_and_verification_behavior(algorithm_name, pepper_cfg, label):
    """
    Verify pepper integration for each registered algorithm and selected strategies.

    Assertions:
      - Hash differs when peppering is enabled (strategy vs plain)
      - Pepper-protected hash verifies only with the peppered algorithm instance
      - Plain hash verifies only with the plain algorithm instance
      - Cross verification fails in both directions
    """
    # Plain (no PEPPER_* keys)
    plain_algo = build_algorithm(algorithm_name)
    plain_hash = plain_algo.hash(VALID_PASSWORD)

    # Pepper-enabled (only PEPPER_* keys + variant implicit via façade arg)
    pepper_algo = build_algorithm(algorithm_name, config=pepper_cfg)
    pepper_hash = pepper_algo.hash(VALID_PASSWORD)

    assert plain_hash != pepper_hash, f"Pepper strategy '{label}' did not alter hash output"

    # Own verification succeeds
    assert plain_algo.verify(plain_hash, VALID_PASSWORD) is True
    assert pepper_algo.verify(pepper_hash, VALID_PASSWORD) is True

    # Cross verification must fail
    assert pepper_algo.verify(plain_hash, VALID_PASSWORD) is False
    assert plain_algo.verify(pepper_hash, VALID_PASSWORD) is False
