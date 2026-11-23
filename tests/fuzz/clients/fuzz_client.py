"""Advanced Atheris fuzzing target for the Mailjet SDK Builders.
Stresses JSON Recursion, Attachment Chunks, and Structural Integrity.
"""

import logging
import sys
import warnings
from types import SimpleNamespace
from unittest.mock import patch

import atheris


warnings.simplefilter("ignore", UserWarning)
logging.disable(logging.CRITICAL)

with atheris.instrument_imports(include=["mailjet_rest"]):
    from mailjet_rest.builders import MessageBuilder, TemplateContentBuilder
    from mailjet_rest.client import Client
    from mailjet_rest.config import Config
    from mailjet_rest.errors import ApiError, ValidationError


_base_client = Client(auth=("fuzz_pub_key", "fuzz_priv_key"), max_retries=0)


def TestOneInput(data: bytes) -> None:
    if len(data) < 5:
        return
    fdp = atheris.FuzzedDataProvider(data)

    # ==========================================
    # BLOCK 1: Message Builder Stateful Fuzzing
    # ==========================================
    try:
        builder = MessageBuilder()
        builder.set_sender(
            email=fdp.PickValueInList(["fuzz-sender@example.com", fdp.ConsumeUnicodeNoSurrogates(32)]),
            name=fdp.ConsumeUnicodeNoSurrogates(32) if fdp.ConsumeBool() else None,
        )

        num_ops = fdp.ConsumeIntInRange(1, 6)
        for _ in range(num_ops):
            op = fdp.ConsumeIntInRange(0, 4)
            if op == 0:
                # Target primary recipients
                builder.add_recipient(
                    email=fdp.PickValueInList(["fuzz-rcpt@example.com", fdp.ConsumeUnicodeNoSurrogates(20)]),
                    name=fdp.ConsumeUnicodeNoSurrogates(20) if fdp.ConsumeBool() else None,
                )
            elif op == 1:
                # Target CC/BCC structural bounds
                if fdp.ConsumeBool():
                    builder.add_cc(email=fdp.ConsumeUnicodeNoSurrogates(20))
                else:
                    builder.add_bcc(email=fdp.ConsumeUnicodeNoSurrogates(20))
            elif op == 2:
                # Fuzz deep recursive variables/structures
                builder.set_subject(fdp.ConsumeUnicodeNoSurrogates(64))
            elif op == 3:
                if fdp.ConsumeBool():
                    builder.attach_file(
                        file_path=fdp.ConsumeUnicodeNoSurrogates(16),
                        content_type=fdp.ConsumeUnicodeNoSurrogates(16),
                    )
                else:
                    builder.attach_inline(
                        file_path=fdp.ConsumeUnicodeNoSurrogates(16),
                        content_type=fdp.ConsumeUnicodeNoSurrogates(16),
                        content_id=fdp.ConsumeUnicodeNoSurrogates(16),
                    )
            elif op == 4:
                # Gate >5MB stress strings to ~1% of iterations to preserve fuzzing throughput.
                if fdp.ConsumeIntInRange(0, 99) == 0:
                    content = fdp.ConsumeUnicodeNoSurrogates(100) * fdp.ConsumeIntInRange(1, 60000)
                else:
                    content = fdp.ConsumeUnicodeNoSurrogates(1024)
                if fdp.ConsumeBool():
                    builder.set_content(html=content)
                else:
                    builder.set_content(text=content)

        builder.build()
    except (ValueError, TypeError, ValidationError, KeyError, OSError):
        # Expected validation/fuzzing error; ignore so the fuzzer can continue.
        pass

    # ==========================================
    # BLOCK 2: Template Content Builder
    # ==========================================
    try:
        t_builder = TemplateContentBuilder()
        t_builder.set_meta(author=fdp.ConsumeUnicodeNoSurrogates(20), name=fdp.ConsumeUnicodeNoSurrogates(20))
        t_builder.set_content(
            text=fdp.ConsumeUnicodeNoSurrogates(50) if fdp.ConsumeBool() else None,
            html=fdp.ConsumeUnicodeNoSurrogates(50) if fdp.ConsumeBool() else None,
            mjml=fdp.ConsumeUnicodeNoSurrogates(50) if fdp.ConsumeBool() else None,
        )

        headers = {}
        for _ in range(fdp.ConsumeIntInRange(0, 3)):
            headers[fdp.ConsumeUnicodeNoSurrogates(16)] = fdp.ConsumeUnicodeNoSurrogates(32)
        t_builder.set_headers(headers)

        t_builder.build()

    except (ValueError, TypeError, ValidationError, KeyError, OSError):
        # Expected validation/fuzzing error; ignore so the fuzzer can continue.  # noqa: S110
        pass
    except RecursionError:
        raise RuntimeError("CRASH: Builder JSON Serialization hit Recursion Depth limit.")

    # ==========================================
    # BLOCK 3: Sync Client Auth, Dry-Run, PATCH & Mocked Dispatch
    # ==========================================
    try:
        if fdp.ConsumeIntInRange(0, 19) == 0:
            cfg = Config(
                version=fdp.PickValueInList(["v3", "v3.1", "v1", "v4"]),
                dry_run=fdp.ConsumeBool(),
                auto_idempotency_mode=fdp.PickValueInList(["fingerprint", "uuid4", "off"]),
                max_retries=0,
            )
            auth = (fdp.ConsumeUnicodeNoSurrogates(24), fdp.ConsumeUnicodeNoSurrogates(24))
            _ = Client(auth=auth, config=cfg)

        _base_client.config.version = fdp.PickValueInList(["v3", "v3.1", "v1", "v4"])
        _base_client.config.dry_run = fdp.ConsumeBool()
        _base_client.config.auto_idempotency_mode = fdp.PickValueInList(["fingerprint", "uuid4", "off"])
        _ = _base_client.available_endpoints
        fake_resp = SimpleNamespace(
            status_code=fdp.PickValueInList([200, 201, 204, 400, 404, 429, 500]),
            text=fdp.ConsumeUnicodeNoSurrogates(128),
            headers={"Content-Type": "application/json"},
            is_redirect=False,
            json=lambda: {"Count": 0, "Data": []},
            raise_for_status=lambda: None,
        )
        with patch.object(_base_client.session, "request", return_value=fake_resp):
            method = fdp.PickValueInList(["GET", "POST", "PUT", "PATCH", "DELETE"])
            _base_client.api_call(
                method,
                "https://api.mailjet.com/v3/REST/contact",
                data={"Email": fdp.ConsumeUnicodeNoSurrogates(24)} if method != "GET" else None,
                headers={"X-Fuzz": fdp.ConsumeUnicodeNoSurrogates(16)},
            )
    except (ValueError, TypeError, ValidationError, ApiError):
        # Expected SDK validation and error-handling rejections on malformed fuzz input.
        pass
    except Exception as e:
        raise RuntimeError(f"UNHANDLED CRASH in Builder execution: {type(e).__name__} - {e}") from e


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
