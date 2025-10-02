import logging
import pytest
from securitykit.hashing.registry import Registry


def test_registry_duplicate_registration_logs(caplog):
    # Ensure we capture DEBUG messages from your library logger
    caplog.set_level(logging.DEBUG, logger="securitykit")

    reg = Registry("algo")

    @reg.register("demo")
    class Demo:
        pass

    # Second registration should be silently ignored (same class kept)
    @reg.register("demo")
    class Demo2:
        pass

    assert reg.get("demo") is Demo  # Confirms second registration did not overwrite

    # Confirm a debug log about duplicate registration was emitted
    messages = caplog.messages
    assert any("already registered" in m for m in messages)


def test_registry_unknown_key_raises():
    reg = Registry("policy")
    with pytest.raises(KeyError) as exc:
        reg.get("missing")
    assert "Unknown policy: missing" in str(exc.value)


def test_registry_items_and_list_are_copies():
    reg = Registry("algo")

    @reg.register("x")
    class X:
        pass

    items_copy = reg.items()
    list_copy = reg.list()

    # Mutera kopiorna och visa att original inte påverkas
    items_copy.pop("x")
    list_copy.remove("x")

    assert "x" in reg.items()
    assert "x" in reg.list()
