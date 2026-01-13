"""
**File:** ``conftest.py``
**Region:** ``tests/conftest``

Pytest shared fixtures.

Covers:
- Token payload fixtures used by linked service authentication tests.
- Deterministic time control for TokenBucket unit tests.
"""

from __future__ import annotations

import time
from typing import Any, Protocol

import pytest


class Clock(Protocol):
    """
    Minimal callable clock used in TokenBucket tests.
    """

    def __call__(self, value: float) -> None: ...

    @property
    def slept(self) -> list[float]: ...


@pytest.fixture
def token_payloads() -> dict[str, Any]:
    """
    Provide representative JSON payloads with token-like keys in various shapes.
    """

    return {
        "flat_access_token": {"access_token": "t1"},
        "flat_accessToken": {"accessToken": "t2"},
        "flat_token": {"token": "t3"},
        "nested": {"auth": {"data": {"access_token": "t4"}}},
        "list_nested": [{"x": 1}, {"auth": {"token": "t5"}}],
        "non_string_value": {"token": 123},
    }


@pytest.fixture
def fake_clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """
    Patch time.perf_counter and time.sleep for deterministic TokenBucket tests.
    """

    state = {"now": 0.0, "slept": []}

    def _set_now(value: float) -> None:
        state["now"] = float(value)

    def _perf_counter() -> float:
        return float(state["now"])

    def _sleep(seconds: float) -> None:
        state["slept"].append(float(seconds))
        state["now"] = float(state["now"]) + float(seconds)

    monkeypatch.setattr(time, "perf_counter", _perf_counter)
    monkeypatch.setattr(time, "sleep", _sleep)

    _set_now(0.0)

    class _Clock:
        def __call__(self, value: float) -> None:
            _set_now(value)

        @property
        def slept(self) -> list[float]:
            return state["slept"]

    return _Clock()
