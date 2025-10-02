from pathlib import Path

def write_env_file(path: Path, config: dict):
    """Write a dictionary of env vars to a .env-style file."""
    lines = [f"{k}={v}" for k, v in config.items()]
    path.write_text("\n".join(lines))
