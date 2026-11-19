"""Atheris fuzzing target for MOD-03 helpers (verify_webhook_signature and MockMailjetClient)."""

from __future__ import annotations

import hashlib
import hmac
import sys
import time
import warnings
from typing import Any

import atheris


warnings.simplefilter("ignore", UserWarning)

with atheris.instrument_imports(include=["mailjet_rest"]):
    from mailjet_rest.errors import ApiError
    from mailjet_rest.testing import MockMailjetClient, MockResponse
    from mailjet_rest.webhooks import verify_webhook_signature


def TestOneInput(data: bytes) -> None:
    if len(data) < 6:
        return

    fdp = atheris.FuzzedDataProvider(data)
    mode = fdp.ConsumeIntInRange(0, 2)

    try:
        if mode == 0:
            payload = fdp.ConsumeBytes(96)
            secret = fdp.ConsumeUnicodeNoSurrogates(32)
            raw_sig = fdp.ConsumeUnicodeNoSurrogates(80)
            now_ts = int(time.time())
            ts: int | None = None
            if fdp.ConsumeBool():
                ts = now_ts + fdp.ConsumeIntInRange(-600, 600)
            verify_webhook_signature(
                payload,
                raw_sig,
                secret,
                timestamp_unix=ts,
                max_age_seconds=fdp.ConsumeIntInRange(-5, 600),
            )
            return

        if mode == 1:
            payload = fdp.ConsumeBytes(96)
            raw_secret = fdp.ConsumeUnicodeNoSurrogates(24)
            if not raw_secret.strip():
                try:
                    verify_webhook_signature(payload, "0" * 64, raw_secret)
                except ValueError:
                    pass
                else:
                    msg = "Empty or whitespace webhook_secret must raise ValueError"
                    raise AssertionError(msg)
            secret = raw_secret if raw_secret.strip() else "fuzz_secret"
            digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
            header = f"sha256={digest.upper()}" if fdp.ConsumeBool() else f"  {digest}  "
            now_ts = int(time.time())
            delta = fdp.ConsumeIntInRange(-500, 500)
            max_age = fdp.ConsumeIntInRange(0, 400)
            matched = verify_webhook_signature(
                payload,
                header,
                secret,
                timestamp_unix=now_ts + delta,
                max_age_seconds=max_age,
            )
            if abs(delta) > max_age + 2 and matched:
                msg = "Replay window check accepted expired webhook signature"
                raise AssertionError(msg)
            if abs(delta) + 2 <= max_age and not matched:
                msg = "Valid HMAC-SHA256 webhook signature within replay window was falsely rejected"
                raise AssertionError(msg)
            return

        status = fdp.PickValueInList([200, 201, 204, 400, 401, 404, 429, 500, 503])
        with MockMailjetClient(default_status=status) as mock_client:
            payload_dict: dict[str, Any] = {
                "CustomID": fdp.ConsumeUnicodeNoSurrogates(24),
                "Subject": fdp.ConsumeUnicodeNoSurrogates(32),
            }
            mock_client.create(data=payload_dict)
            ep_name = fdp.ConsumeUnicodeNoSurrogates(24) or "send_v31"
            ep = getattr(mock_client, ep_name)
            resp = ep.create(data=payload_dict, filters={"Limit": fdp.ConsumeIntInRange(1, 100)})
            _ = resp.json()
            if isinstance(resp, MockResponse):
                resp.raise_for_status()
    except (ValueError, TypeError, AttributeError, ApiError):
        # Expected validation, type, or HTTP status error on fuzzed inputs.
        return


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
