"""
**File:** ``test_package_init.py``
**Region:** ``tests/test_package_init``

Package initialization tests.

Covers:
- Version resolution from VERSION.txt and fallback behavior.
- Public export surface via __all__.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import ds_protocol_http_py_lib as pkg


def test_version_is_read_from_version_file() -> None:
    """
    It reads VERSION.txt at import time when present.
    """

    assert isinstance(pkg.__version__, str)
    assert pkg.__version__ != "0.0.0"


def test_version_falls_back_when_version_file_is_missing(monkeypatch) -> None:
    """
    It falls back to 0.0.0 when VERSION.txt is not found.
    """

    monkeypatch.setattr(Path, "exists", lambda self: False)
    sys.modules.pop("ds_protocol_http_py_lib", None)
    reloaded = importlib.import_module("ds_protocol_http_py_lib")
    assert reloaded.__version__ == "0.0.0"


def test_package_exports_are_available() -> None:
    """
    It exposes documented public exports via __all__.
    """

    for name in pkg.__all__:
        assert hasattr(pkg, name)
