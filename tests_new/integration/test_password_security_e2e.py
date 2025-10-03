"""
End-to-end verification for password security API if present.
Skipped automatically if the module is not installed/available.
"""
import importlib
import pytest

VALID_PW = "Aa1!abcd!"


@pytest.mark.skipif(
    importlib.util.find_spec("securitykit.api.password_security") is None,
    reason="password_security API not present",
)
def test_password_security_e2e():
    import securitykit.api.password_security as ps
    importlib.reload(ps)
    h = ps.hash_password(VALID_PW)
    assert ps.verify_password(VALID_PW, h) is True
    assert ps.verify_password(VALID_PW + "x", h) is False
