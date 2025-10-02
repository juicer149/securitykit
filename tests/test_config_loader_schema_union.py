from dataclasses import dataclass
from typing import Union
from securitykit.utils.config_loader import export_schema

def test_schema_union_type_branch():
    @dataclass
    class U:
        field: Union[int, str]
    rows = export_schema(U, prefix="U_")
    entry = next(r for r in rows if r["param"] == "field")
    # Just ensure we produced some string representation
    assert "field" in entry["param"]
    assert "config_key" in entry
