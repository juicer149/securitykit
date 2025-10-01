# securitykit/bench/utils.py
from pathlib import Path
from securitykit.logging_config import logger


def export_env(config: dict[str, str], filepath: str | Path) -> None:
    """
    Write benchmark results to a .env file.

    Args:
        config: Dict of environment variables to write.
        filepath: Path to the file to create/overwrite.
    """
    lines = [f"{k}={v}" for k, v in config.items()]
    Path(filepath).write_text("\n".join(lines) + "\n")
    logger.info("Exported benchmark config → %s", filepath)
