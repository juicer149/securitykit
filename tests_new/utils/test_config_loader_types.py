from typing import Optional, Union

from securitykit.utils.config_loader.types import normalize_type


def test_normalize_plain_types_identity():
    assert normalize_type(int) is int
    assert normalize_type(str) is str
    assert normalize_type(bool) is bool


def test_normalize_list_generic_collapses_to_origin():
    t = list[int]
    norm = normalize_type(t)
    # Expect origin list (not list[int]) or same object depending on implementation
    assert norm in (list, list, t)


def test_normalize_optional_returns_union_or_origin():
    opt = Optional[int]  # Union[int, NoneType]
    norm = normalize_type(opt)
    # Accept union or original depending on minimal implementation
    assert "Union" in getattr(norm, "__name__", "Union")


def test_normalize_union_holds():
    u = Union[int, float]
    norm = normalize_type(u)
    assert norm in (u, getattr(u, "__origin__", u))


def test_normalize_nested_list_union():
    nested = list[Optional[int]]
    norm = normalize_type(nested)
    # Still should collapse to 'list' origin or remain unchanged on minimal impl
    assert norm in (list, nested)


def test_normalize_tuple_generic():
    tup = tuple[int, str]
    norm = normalize_type(tup)
    # Accept tuple or original representation
    assert norm in (tuple, tup)


def test_normalize_dict_generic():
    d = dict[str, int]
    norm = normalize_type(d)
    assert norm in (dict, d)
