"""Exponential backoff with jitter for network retries."""
from __future__ import annotations

import random
import time
from typing import Callable, Iterable, Type, TypeVar

T = TypeVar("T")


def retry(
    func: Callable[[], T],
    *,
    attempts: int = 5,
    base_delay: float = 2.0,
    max_delay: float = 60.0,
    retry_on: Iterable[Type[BaseException]] = (Exception,),
    sleep: Callable[[float], None] = time.sleep,
    on_error: Callable[[int, BaseException, float], None] | None = None,
) -> T:
    """Call ``func`` up to ``attempts`` times with exponential backoff.

    Delay after failure *n* (1-indexed) is ``base_delay * 2**(n-1)`` capped at
    ``max_delay``, plus up to 25% random jitter to avoid thundering herds. The
    last attempt does not sleep; its exception propagates to the caller.
    """
    retry_on = tuple(retry_on)
    last_exc: BaseException | None = None
    for n in range(1, attempts + 1):
        try:
            return func()
        except retry_on as exc:  # noqa: PERF203 - retry loop is intentional
            last_exc = exc
            if n == attempts:
                break
            delay = min(base_delay * (2 ** (n - 1)), max_delay)
            delay += random.uniform(0, delay * 0.25)
            if on_error is not None:
                on_error(n, exc, delay)
            sleep(delay)
    assert last_exc is not None
    raise last_exc
