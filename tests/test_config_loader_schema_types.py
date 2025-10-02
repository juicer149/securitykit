from dataclasses import dataclass
from typing import List
from securitykit.utils.config_loader import export_schema


def test_schema_with_generic_list_type():
    @dataclass
    class Demo:
        items: List[int]
    schema = export_schema(Demo, prefix="DEMO_")
    row = next(r for r in schema if r["param"] == "items")
    assert "items" in row["param"]
    # type field should be something like 'list' or 'typing.List[int]' depending on Python version
    assert "list" in row["type"].lower()
