"""Configuration loader."""

import os
from pathlib import Path

import yaml


_config = None


def load_config(path: str = None) -> dict:
    """Load config from YAML file."""
    global _config
    if _config is not None and path is None:
        return _config

    if path is None:
        path = os.environ.get(
            "BBTRS_CONFIG",
            str(Path(__file__).parent.parent.parent / "config" / "config.yml"),
        )

    with open(path) as f:
        _config = yaml.safe_load(f)

    return _config


def get_config() -> dict:
    """Get the loaded config, loading defaults if needed."""
    if _config is None:
        return load_config()
    return _config
