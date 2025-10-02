from securitykit.utils.config_loader.converters import default_parse

def test_default_parse_size_suffix_byte_and_plain_size():
    assert default_parse("1024") == 1024      # plain size (suffix '')
    assert default_parse("512B") == 512       # 'B' suffix path

def test_default_parse_negative_float():
    assert default_parse("-7.50") == -7.50

def test_default_parse_semicolon_list():
    assert default_parse("a;b;c") == ["a", "b", "c"]
