import importlib
import inspect

import securitykit.api as api


def test_api_exports_matches___all__():
    exported = set(api.__all__)
    # Kontroll att allt i __all__ faktiskt finns som attribut
    for name in exported:
        assert hasattr(api, name), f"Missing exported attribute: {name}"

    # Spot check på några centrala symboler
    expected_subset = {
        "Algorithm",
        "HashingFactory",
        "hash_password",
        "verify_password",
        "rehash_password",
        "Argon2Policy",
        "PasswordPolicy",
        "PasswordValidator",
        "list_algorithms",
        "list_policies",
    }
    assert expected_subset.issubset(exported)

    # __all__ ska bara innehålla strängar
    assert all(isinstance(x, str) for x in api.__all__)


def test_password_security_module_lazy_objects_recreated(monkeypatch):
    """
    Säkerställ att reload av password_security-modulen skapar nya instanser
    (dvs. förändring i env ger ny konfiguration).
    """
    import os
    import securitykit.api.password_security as ps

    first_algo_id = id(ps._algo)
    first_validator_id = id(ps._validator)

    # Ändra env (ex: time cost) och reloada
    monkeypatch.setenv("ARGON2_TIME_COST", "3")
    importlib.reload(ps)

    assert id(ps._algo) != first_algo_id
    assert id(ps._validator) != first_validator_id
