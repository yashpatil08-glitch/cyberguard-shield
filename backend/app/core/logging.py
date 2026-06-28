"""Centralised logging setup."""
from __future__ import annotations

import logging
import sys

from .config import settings


def configure_logging() -> None:
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    root = logging.getLogger()
    if root.handlers:
        # Avoid duplicate handlers when uvicorn reloads.
        for h in list(root.handlers):
            root.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    root.addHandler(handler)
    root.setLevel(level)
    # Quiet noisy libs
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("whois").setLevel(logging.WARNING)