"""
HTTP configuration tests.

Covers:
- RetryConfig default policy and immutability.
- HttpConfig default construction and embedded RetryConfig initialization.
"""

from __future__ import annotations

import dataclasses

import pytest

from ds_protocol_http_py_lib.utils.http.config import HttpConfig, RetryConfig


def test_retry_config_has_expected_defaults() -> None:
    """
    It exposes stable defaults suitable for retrying common transient failures.
    """

    cfg = RetryConfig()
    assert cfg.total == 3
    assert cfg.backoff_factor == 0.2
    assert 429 in cfg.status_forcelist
    assert "GET" in cfg.allowed_methods
    assert cfg.raise_on_status is False
    assert cfg.respect_retry_after_header is True


def test_retry_config_is_frozen() -> None:
    """
    It is immutable to prevent accidental mutation at runtime.
    """

    cfg = RetryConfig()
    dataclasses.replace(cfg, total=5)

    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.total = 5


def test_http_config_defaults_are_constructed() -> None:
    """
    It constructs default headers and retry config via factories.
    """

    cfg = HttpConfig()
    assert isinstance(cfg.headers, dict)
    assert cfg.timeout_seconds == 10
    assert cfg.user_agent == "Http/1.0"
    assert isinstance(cfg.retry, RetryConfig)
