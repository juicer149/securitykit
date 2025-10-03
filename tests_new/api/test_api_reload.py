import importlib

def test_password_security_reload_configuration(monkeypatch):
    mod = importlib.import_module("securitykit.api.password_security")
    # Change environment and call reload
    new_cfg = {
        "HASH_VARIANT": "argon2",
        "ARGON2_TIME_COST": "2",
        "ARGON2_MEMORY_COST": str(64 * 1024),
        "ARGON2_PARALLELISM": "1",
        "ARGON2_HASH_LENGTH": "32",
        "ARGON2_SALT_LENGTH": "16",
        "PASSWORD_MIN_LENGTH": "8",
    }
    mod.reload_configuration(new_cfg)
    h = mod.hash_password("Aa1!abcd!")
    assert mod.verify_password("Aa1!abcd!", h)
