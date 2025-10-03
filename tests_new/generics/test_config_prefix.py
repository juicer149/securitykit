from securitykit import config

def test_build_clear_env_prefixes_contains_pepper_and_hashing():
    prefixes = config.build_clear_env_prefixes()
    assert "PEPPER_" in prefixes
    assert any(p.startswith("ARGON2") for p in prefixes)
