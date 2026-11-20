#!/usr/bin/env python3
"""Atheris fuzzing target for Mailjet versioning utilities and PEP 562 lazy package exports."""

from __future__ import annotations

import logging
import sys
import warnings

import atheris


warnings.simplefilter("ignore")
logging.disable(logging.CRITICAL)

with atheris.instrument_imports(include=["mailjet_rest"]):
    import mailjet_rest
    from mailjet_rest.utils.version import VERSION, clean_version, get_version, parse_semver_triplet


def _fuzz_version_parsing(fdp: atheris.FuzzedDataProvider) -> None:
    preset_candidates = (
        "",
        "1.10.0",
        "1.10.0rc2",
        "2.3.4.post1",
        "0.0.0.dev7+g1234",
        "v1.2.3",
        "1.2",
        "١.٢.٣",
        "².1.0",
        "-1.2.3",
    )
    raw = fdp.PickValueInList(preset_candidates) if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(48)

    cleaned = clean_version(raw)
    if not (isinstance(cleaned, tuple) and len(cleaned) == 3 and all(isinstance(part, int) for part in cleaned)):
        msg = f"clean_version must return 3-int tuple, got {cleaned!r}"
        raise AssertionError(msg)

    try:
        triplet = parse_semver_triplet(raw)
    except ValueError:
        # Expected rejection when input lacks a valid numeric X.Y.Z leading triplet.
        return

    if cleaned != triplet:
        msg = f"clean_version({raw!r})={cleaned!r} diverged from parse_semver_triplet={triplet!r}"
        raise AssertionError(msg)

    rendered = get_version(triplet)
    if rendered != f"{triplet[0]}.{triplet[1]}.{triplet[2]}":
        msg = f"Unexpected get_version formatting: {rendered!r}"
        raise AssertionError(msg)

    if all(part >= 0 for part in triplet) and parse_semver_triplet(rendered) != triplet:
        msg = f"Semver round-trip failed for {rendered!r}"
        raise AssertionError(msg)


def _fuzz_get_version_tuples(fdp: atheris.FuzzedDataProvider) -> None:
    if fdp.ConsumeBool():
        default_ver = get_version(None)
        if default_ver != get_version(VERSION):
            msg = "get_version(None) must match get_version(VERSION)"
            raise AssertionError(msg)
        return

    length = fdp.ConsumeIntInRange(0, 6)
    parts = tuple(fdp.ConsumeIntInRange(-10, 9999) for _ in range(length))
    try:
        rendered = get_version(parts)
    except ValueError:
        if length == 3:
            msg = f"get_version rejected valid 3-tuple {parts!r}"
            raise AssertionError(msg) from None
        return

    if length != 3:
        msg = f"get_version accepted non-3-tuple {parts!r}"
        raise AssertionError(msg)
    if rendered != f"{parts[0]}.{parts[1]}.{parts[2]}":
        msg = f"get_version returned mismatched string {rendered!r} for {parts!r}"
        raise AssertionError(msg)


def _fuzz_lazy_exports(fdp: atheris.FuzzedDataProvider) -> None:
    if fdp.ConsumeBool():
        export_name = fdp.PickValueInList([*mailjet_rest.__all__, "__version__"])
        resolved = getattr(mailjet_rest, export_name)
        if resolved is None:
            msg = f"Allowlisted export mailjet_rest.{export_name} resolved to None"
            raise AssertionError(msg)
        return

    raw_name = fdp.ConsumeUnicodeNoSurrogates(36)
    if not raw_name or raw_name in mailjet_rest.__all__ or raw_name == "__version__":
        return
    if hasattr(mailjet_rest, raw_name):
        # Loaded submodule/stdlib globals are fine; non-allowlisted names must not invent exports.
        return

    try:
        getattr(mailjet_rest, raw_name)
    except AttributeError:
        # Expected AttributeError on unknown attribute via PEP 562 __getattr__.
        return
    except Exception as exc:
        msg = f"Unexpected exception looking up unknown export {raw_name!r}: {type(exc).__name__}"
        raise AssertionError(msg) from exc

    dir_entries = dir(mailjet_rest)
    if "__version__" not in dir_entries:
        msg = "dir(mailjet_rest) must advertise '__version__'"
        raise AssertionError(msg)


def TestOneInput(data: bytes) -> None:
    """Execute one Atheris iteration across versioning and PEP 562 export paths."""
    if len(data) < 4:
        return

    fdp = atheris.FuzzedDataProvider(data)
    mode = fdp.ConsumeIntInRange(0, 2)
    try:
        if mode == 0:
            _fuzz_version_parsing(fdp)
        elif mode == 1:
            _fuzz_get_version_tuples(fdp)
        else:
            _fuzz_lazy_exports(fdp)
    except (ValueError, TypeError, AttributeError):
        # Expected rejections on malformed fuzzed inputs.
        return
    except Exception as exc:
        msg = f"UNHANDLED CRASH in fuzz_version_and_exports: {type(exc).__name__} - {exc}"
        raise RuntimeError(msg) from exc


def main() -> None:
    """Run Atheris fuzzing loop for version utilities and package exports."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
