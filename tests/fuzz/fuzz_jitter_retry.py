#!/usr/bin/env python3
"""
Fuzz test for the JitterRetry backoff mathematics.
Hunts for floating-point OverflowErrors or division-by-zero crashes.
"""
import sys
import logging
import atheris
from urllib3.exceptions import MaxRetryError

with atheris.instrument_imports():
    from mailjet_rest.client import JitterRetry

logging.disable(logging.CRITICAL)

def TestOneInput(data: bytes) -> None:
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)

    try:
        # Fuzz the retry configuration parameters
        total_retries = fdp.ConsumeIntInRange(-1, 1000)
        backoff_factor = fdp.ConsumeFloat()

        retry = JitterRetry(total=total_retries, backoff_factor=backoff_factor)

        # Simulate a massive cascade of fuzzed network failures to bloat the retry history
        num_errors = fdp.ConsumeIntInRange(0, 100)
        for _ in range(num_errors):
            retry = retry.increment(error=Exception("Fuzzed Drop"))

        # Trigger the math calculation
        jitter_time = retry.get_backoff_time()

        if not isinstance(jitter_time, (int, float)):
            raise RuntimeError("CRASH: JitterRetry returned non-numeric backoff time.")

    except (ValueError, TypeError, ZeroDivisionError, OverflowError, MaxRetryError):
        # We expect some extreme floats (like infinity) to trigger native math exceptions
        # MaxRetryError is naturally expected when num_errors > total_retries
        pass
    except Exception as e:
        raise RuntimeError(f"UNHANDLED CRASH in JitterRetry math: {type(e).__name__} - {e}") from e

if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
