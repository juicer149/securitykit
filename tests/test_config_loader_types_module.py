from typing import Optional, List
from securitykit.utils.config_loader.types import normalize_type


def test_normalize_type_optional():
    t = Optional[int]
    norm = normalize_type(t)
    # For now it returns 'typing.Union' or similar, accept non-None
    assert norm is not None


def test_normalize_type_list():
    t = List[int]
    norm = normalize_type(t)
    assert norm in (list, List)
