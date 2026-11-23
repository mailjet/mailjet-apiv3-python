#!/usr/bin/env python3
"""Atheris fuzzing target for Mailjet sanitized telemetry extraction and debug response logging."""

from __future__ import annotations

import logging
import sys
import warnings
from typing import Any

import atheris


warnings.simplefilter("ignore")
logging.disable(logging.CRITICAL)

with atheris.instrument_imports(include=["mailjet_rest"]):
    from mailjet_rest.errors import MAX_ERROR_LOG_CHARS, sanitize_error_text
    from mailjet_rest.utils.guardrails import RedactingFilter
    from mailjet_rest.utils.telemetry import extract_telemetry, log_api_response, record_debug_telemetry


class _MemoryLogHandler(logging.Handler):
    """In-memory log handler bounded per fuzz iteration."""

    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(self.format(record))


class _FakeResponse:
    """Slotted response container for log_api_response and record_debug_telemetry fuzzing."""

    __slots__ = ("status_code", "text")

    def __init__(self, status_code: Any, text: Any) -> None:
        self.status_code = status_code
        self.text = text


class _BrokenStr:
    """Slotted adversarial object whose __str__ raises unconditionally."""

    __slots__ = ()

    def __str__(self) -> str:
        msg = "broken __str__"
        raise ValueError(msg)


_TELEMETRY_LOGGER = logging.getLogger("mailjet_rest.fuzz_telemetry_isolated")
_TELEMETRY_LOGGER.propagate = False
_TELEMETRY_LOGGER.setLevel(logging.DEBUG)
_MEMORY_HANDLER = _MemoryLogHandler()
_TELEMETRY_LOGGER.handlers.clear()
_TELEMETRY_LOGGER.addFilter(RedactingFilter())
_TELEMETRY_LOGGER.addHandler(_MEMORY_HANDLER)


def _build_fuzzed_payload(fdp: atheris.FuzzedDataProvider) -> Any:
    shape = fdp.ConsumeIntInRange(0, 4)
    custom_id = fdp.ConsumeUnicodeNoSurrogates(32)
    template_id = fdp.ConsumeUnicodeNoSurrogates(16)
    if shape == 0:
        return {
            "CustomID": custom_id,
            "TemplateID": template_id,
            "Messages": [{"CustomID": f"nested\r\n{custom_id}\x00", "TemplateID": 12345}],
        }
    if shape == 1:
        return [{"CustomID": f"list\x1b[31m{custom_id}", "TemplateID": template_id}]
    if shape == 2:
        return {"Messages": [], "CustomID": custom_id, "Extra": fdp.ConsumeUnicodeNoSurrogates(24)}
    if shape == 3:
        return {"Messages": "not-a-list", "CustomID": 999}
    return fdp.ConsumeUnicodeNoSurrogates(24)


def _fuzz_extract_telemetry(fdp: atheris.FuzzedDataProvider) -> None:
    payload = _build_fuzzed_payload(fdp)
    headers: dict[str, str | None] | None = (
        {"X-Fuzz": fdp.ConsumeUnicodeNoSurrogates(20), "Optional": None} if fdp.ConsumeBool() else None
    )
    trace_str, structured = extract_telemetry(payload, headers)
    if not isinstance(trace_str, str) or not isinstance(structured, dict):
        msg = "extract_telemetry must return (str, dict[str, str])"
        raise AssertionError(msg)

    for text_item in (trace_str, *structured.values()):
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in text_item):
            msg = f"Control character leaked into sanitized telemetry output: {text_item!r}"
            raise AssertionError(msg)


def _fuzz_sanitize_error_text(fdp: atheris.FuzzedDataProvider) -> None:
    max_chars = fdp.ConsumeIntInRange(0, 200)
    raw_choice = fdp.ConsumeIntInRange(0, 3)
    if raw_choice == 0:
        raw: Any = fdp.ConsumeUnicodeNoSurrogates(256)
    elif raw_choice == 1:
        raw = fdp.ConsumeBytes(64)
    elif raw_choice == 2:
        raw = _BrokenStr()
    else:
        raw = {"ErrorMessage": fdp.ConsumeUnicodeNoSurrogates(64)}

    sanitized = sanitize_error_text(raw, max_chars=max_chars)
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in sanitized):
        msg = f"Control character escaped sanitize_error_text: {sanitized!r}"
        raise AssertionError(msg)
    max_bounded_len = max_chars + len("...[truncated]")
    if len(sanitized) > max_bounded_len:
        msg = f"sanitize_error_text exceeded bound max_chars={max_chars}: len={len(sanitized)}"
        raise AssertionError(msg)


def _fuzz_logging_and_redaction(fdp: atheris.FuzzedDataProvider) -> None:
    status = fdp.PickValueInList([200, 201, 204, 400, 401, 404, 429, 500, None])
    probe_marker = "probe_val_" + fdp.ConsumeUnicodeNoSurrogates(12).replace(" ", "x")
    body = f"api_secret={probe_marker} " + fdp.ConsumeUnicodeNoSurrogates(80)  # pragma: allowlist secret
    resp = _FakeResponse(status, body)
    payload = _build_fuzzed_payload(fdp)
    max_chars = fdp.ConsumeIntInRange(10, MAX_ERROR_LOG_CHARS)

    _MEMORY_HANDLER.messages.clear()
    prev_disable = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    try:
        trace_suffix, _ = extract_telemetry(payload, None)
        log_api_response(
            _TELEMETRY_LOGGER,
            fdp.PickValueInList(["GET", "POST", "PUT", "DELETE"]),
            "https://api.mailjet.com/v3.1/send",
            resp,
            trace_suffix,
            max_chars=max_chars,
        )
        record_debug_telemetry(
            _TELEMETRY_LOGGER,
            "POST",
            "https://api.mailjet.com/v3.1/send",
            resp,
            payload,
            {"Authorization": f"Bearer {probe_marker}"},  # pragma: allowlist secret
        )
    finally:
        logging.disable(prev_disable)
        captured = list(_MEMORY_HANDLER.messages)
        _MEMORY_HANDLER.messages.clear()

    if len(probe_marker) > len("probe_val_") and isinstance(status, int) and status >= 400:
        for msg_line in captured:
            if f"api_secret={probe_marker}" in msg_line:  # pragma: allowlist secret
                msg = "RedactingFilter failed to scrub api_secret from telemetry error log"
                raise AssertionError(msg)


def TestOneInput(data: bytes) -> None:
    """Execute one Atheris iteration across telemetry extraction, sanitization, and log redaction."""
    if len(data) < 6:
        return

    fdp = atheris.FuzzedDataProvider(data)
    mode = fdp.ConsumeIntInRange(0, 2)
    try:
        if mode == 0:
            _fuzz_extract_telemetry(fdp)
        elif mode == 1:
            _fuzz_sanitize_error_text(fdp)
        else:
            _fuzz_logging_and_redaction(fdp)
    except (ValueError, TypeError):
        # Expected rejection on malformed fuzzed telemetry inputs.
        return
    except Exception as exc:
        msg = f"UNHANDLED CRASH in fuzz_telemetry: {type(exc).__name__} - {exc}"
        raise RuntimeError(msg) from exc


def main() -> None:
    """Run Atheris fuzzing loop for Mailjet telemetry helpers."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
