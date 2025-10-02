from dataclasses import dataclass
from securitykit.utils.config_loader import export_schema


def test_schema_includes_required_and_defaults():
    @dataclass
    class Flags:
        enabled: bool
        level: int = 2

    schema = export_schema(Flags, prefix="FLAGS_")
    item_by_key = {row["config_key"]: row for row in schema}
    assert item_by_key["FLAGS_ENABLED"]["required"] is True
    assert item_by_key["FLAGS_LEVEL"]["required"] is False
    assert item_by_key["FLAGS_LEVEL"]["default"] == 2
