from dataclasses import dataclass
from securitykit.utils.config_loader.schema import export_schema


def test_export_schema():
    @dataclass
    class P:
        a: int
        b: int = 5
        c: str = "x"

    schema = export_schema(P, prefix="P_")
    # Convert list to dict by config_key
    by_key = {row["config_key"]: row for row in schema}
    assert "P_A" in by_key
    assert by_key["P_A"]["required"] is True
    assert by_key["P_B"]["default"] == 5
    assert by_key["P_C"]["type"] in ("str", "typing.Any")  # depends on Python version/hints
