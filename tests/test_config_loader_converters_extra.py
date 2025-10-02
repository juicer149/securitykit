from securitykit.utils.config_loader.converters import default_parse


def test_default_parse_float_precision():
    assert default_parse("3.1415") == 3.1415


def test_default_parse_semicolon_list():
    assert default_parse("a;b;c") == ["a", "b", "c"]


def test_default_parse_size_suffix_megabytes():
    assert default_parse("5M") == 5 * 1024 * 1024
