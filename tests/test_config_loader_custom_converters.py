from dataclasses import dataclass
from securitykit.utils.config_loader import ConfigLoader, ConverterRegistry


@dataclass
class Demo:
    value: int
    tag: str = "x"


def test_custom_converter_front_executes_first():
    calls = []

    def plus_one(v):
        calls.append("front")
        if isinstance(v, str) and v.isdigit():
            return str(int(v) + 1)
        return v

    reg = ConverterRegistry()
    reg.register_front(plus_one)

    cfg = {"DEMO_VALUE": "4"}
    loader = ConfigLoader(cfg, converters=reg)
    demo = loader.build(Demo, prefix="DEMO_", name="Demo")
    # plus_one makes "4" -> "5", default_parse turns "5" -> int(5)
    assert demo.value == 5
    assert calls == ["front"]


def test_custom_converter_back_executes_last():
    calls = []

    def annotate(v):
        calls.append("back")
        if isinstance(v, int):
            return v * 10
        return v

    reg = ConverterRegistry()
    reg.register_back(annotate)

    cfg = {"DEMO_VALUE": "3"}
    loader = ConfigLoader(cfg, converters=reg)
    demo = loader.build(Demo, prefix="DEMO_", name="Demo")
    # default_parse makes "3" -> 3, annotate multiplies -> 30
    assert demo.value == 30
    assert calls == ["back"]
