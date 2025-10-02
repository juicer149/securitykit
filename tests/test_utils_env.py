import os
from pathlib import Path

from securitykit.utils.env import export_env


def test_export_env_writes_file_and_logs(tmp_path, caplog):
    config = {
        "ARGON2_TIME_COST": "2",
        "PASSWORD_MIN_LENGTH": "12",
        "CUSTOM_FLAG": "true",
    }
    target = tmp_path / ".env.test"

    export_env(config, target)

    content = target.read_text().strip().splitlines()
    # Order is dict order (Python 3.7+ insertion ordered); we just check membership.
    for k, v in config.items():
        assert f"{k}={v}" in content

    assert target.exists()
    # At least one log entry referencing the path
    assert any(str(target) in r.message for r in caplog.records)


def test_export_env_overwrites_existing(tmp_path):
    target = tmp_path / ".env.test"
    target.write_text("OLD=1\n")

    cfg = {"NEW_KEY": "VALUE"}
    export_env(cfg, target)

    text = target.read_text().strip()
    assert text == "NEW_KEY=VALUE"
