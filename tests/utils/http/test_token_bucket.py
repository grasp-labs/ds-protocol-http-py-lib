"""
Token bucket rate limiter tests.

Covers:
- Immediate acquisition when tokens are available.
- Sleep-based throttling behavior when depleted.
- Capacity fallback logic when capacity is provided as a falsy value.
"""

from __future__ import annotations

from ds_protocol_http_py_lib.utils.http.token_bucket import TokenBucket


def test_token_bucket_acquire_consumes_token_without_sleep(fake_clock) -> None:
    """
    It decrements tokens immediately when capacity is available.
    """

    fake_clock(0.0)
    bucket = TokenBucket(rps=10.0, capacity=2)
    start_tokens = bucket.tokens
    bucket.acquire()
    assert bucket.tokens == start_tokens - 1.0
    assert fake_clock.slept == []


def test_token_bucket_acquire_sleeps_when_depleted(fake_clock) -> None:
    """
    It sleeps for the computed duration when no token is available.
    """

    fake_clock(0.0)
    bucket = TokenBucket(rps=10.0, capacity=1)
    bucket.tokens = 0.0
    bucket.last = 0.0
    bucket.acquire()
    assert fake_clock.slept == [0.1]
    assert bucket.tokens == 0.0


def test_token_bucket_capacity_falls_back_when_zero_capacity_provided(fake_clock) -> None:
    """
    It falls back to a capacity derived from RPS when capacity is falsy.
    """

    fake_clock(0.0)
    bucket = TokenBucket(rps=7.0, capacity=0)
    assert bucket.capacity == 14
