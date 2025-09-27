from __future__ import annotations

from typing import Any, Mapping
import os

from .core.factory import SecurityFactory
from .config.providers import EnvConfigProvider, DictConfigProvider, LayeredConfigProvider
from .bench.argon2_calibrate import calibrate_argon2

_factory_ref: SecurityFactory | None = None
_calibration_result: dict[str, Any] | None = None

def configure(
    overrides: Mapping[str, Any] | None = None,
    *,
    use_env: bool = True,
    auto_calibrate: bool | None = None,
    force_calibration: bool | None = None,
) -> None:
    """
    Konfigurera default factory. Kan auto-kalibrera om:
      - variant är argon2
      - inga explicita variant-parametrar finns
      - SECURITYKIT_CALIBRATE=1 (default) och ej overrides
    """
    global _factory_ref, _calibration_result

    if auto_calibrate is None:
        auto_calibrate = os.environ.get("SECURITYKIT_CALIBRATE", "1") not in ("0", "false")

    if force_calibration is None:
        force_calibration = os.environ.get("SECURITYKIT_FORCE_CALIBRATION", "0") in ("1", "true")

    providers = []
    if overrides:
        providers.append(DictConfigProvider(overrides))
    if use_env:
        providers.append(EnvConfigProvider())

    if not providers:
        providers.append(DictConfigProvider({}))

    provider = LayeredConfigProvider(*providers)

    # Auto-kalibrering endast om variant argon2 och param ej specificerade
    # här hårdkodas argon2
    variant = provider.get("HASH_VARIANT", "argon2").lower()

    argon2_params_present = any(
        provider.get(key) is not None
        # här hårdkodas argon2
        for key in (
            "ARGON2_TIME_COST",
            "ARGON2_MEMORY_COST",
            "ARGON2_PARALLELISM",
        )
    )

    if (
        # även här hårdkodas argon2
        variant == "argon2"
        and auto_calibrate
        and not argon2_params_present
    ):
        # kör kalibrering (om inte redan)
        result = calibrate_argon2(
            force=force_calibration,
            allow_cache=True,
        )
        _calibration_result = {
            "variant": variant,
            "result": result,
        }
        # injicera som överstyrningar
        # här är den kopplad till argon2, borde man inte kunna ha ett register för policy på samma sätt som för algoritmer? och hämta policy beroende på variant, skriva över med kalibrering, etc och därmed inte hårdkoda argon2 här?
        cal_overrides = {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": str(result.time_cost),
            "ARGON2_MEMORY_COST": str(result.memory_cost),
            "ARGON2_PARALLELISM": str(result.parallelism),
        }
        provider = LayeredConfigProvider(DictConfigProvider(cal_overrides), *providers)

    _factory_ref = SecurityFactory(provider)


def get_factory() -> SecurityFactory:
    global _factory_ref
    if _factory_ref is None:
        configure()
    return _factory_ref  # type: ignore[return-value]


def get_calibration_result():
    return _calibration_result

