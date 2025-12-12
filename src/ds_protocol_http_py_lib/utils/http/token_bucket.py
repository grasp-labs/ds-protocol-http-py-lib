"""
Token Bucket Rate Limiter

This module implements a cooperative token bucket algorithm for rate limiting HTTP requests.
A token bucket maintains a reservoir of tokens that are consumed when requests are made.
Tokens are replenished at a constant rate (tokens per second), providing smooth rate limiting
that allows burst traffic while maintaining an overall rate cap.

Key features:
- Thread-safe using threading.Lock
- Configurable requests per second (RPS) rate
- Adjustable capacity for burst handling
- Cooperative design that works well with threading.Lock
- Global RPS cap across all concurrent operations
"""

import threading
import time


class TokenBucket:
    """
    Token Bucket Rate Limiter

    Implements the classic token bucket algorithm for controlling request rates in threading environments.
    Each request consumes one token from the bucket. If no tokens are available, the request waits
    until tokens are replenished based on the configured rate.

    The bucket starts full and refills continuously at the specified RPS rate. This allows for
    burst traffic (up to the bucket capacity) while maintaining the overall rate limit.

    :param rps: Target requests per second rate. Determines token refill rate.
    :param capacity: Maximum number of tokens the bucket can hold. Defaults to 2x RPS.
    :return: None

    Example:
        # Limit to 10 requests per second with burst capacity of 20
        limiter = TokenBucket(rps=10.0, capacity=20)

        # Acquire permission for a request
        limiter.acquire()
        # Make your HTTP request here
    """

    def __init__(
        self,
        rps: float = 10.0,
        capacity: int = 20,
    ) -> None:
        """
        Initialize the TokenBucket.
        :param rps: Target requests per second rate. Determines token refill rate.
        :param capacity: Maximum number of tokens the bucket can hold. Defaults to 2x RPS.
        :return: None
        """
        self.rps = float(rps)
        self.capacity = int(capacity) if capacity else int(self.rps * 2)
        self.tokens = float(self.capacity)
        self.last = time.perf_counter()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """
        Acquire a token from the bucket, waiting if necessary.
        :return: None
        """
        with self._lock:
            now = time.perf_counter()
            self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rps)
            self.last = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            wait = (1.0 - self.tokens) / self.rps
        time.sleep(wait)
