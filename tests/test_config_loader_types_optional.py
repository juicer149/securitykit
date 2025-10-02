from typing import Optional
from securitykit.utils.config_loader.types import normalize_type

def test_normalize_type_optional_union():
    t = Optional[int]
    norm = normalize_type(t)
    assert norm is not None
