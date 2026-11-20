"""Regression tests for tilde (~) home-directory expansion in Config.verify."""

from __future__ import annotations

from pathlib import Path

import pytest

from mailjet_rest.config import Config
from mailjet_rest.utils.guardrails import SecurityGuard
from mailjet_rest.utils.transport_security import resolve_tls_verify


@pytest.mark.parametrize(
    "bad_verify_path",
    [
        "~nonexistent_mailjet_user_99999/ca-bundle.pem",
        "~",
    ],
)
def test_resolve_tls_verify_unresolvable_tilde_raises_value_error(
    bad_verify_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ensure Path.expanduser() RuntimeError is converted into ValueError."""
    if bad_verify_path == "~":
        monkeypatch.delenv("HOME", raising=False)
        monkeypatch.delenv("USERPROFILE", raising=False)

    with pytest.raises(ValueError, match="Invalid CA bundle path|Custom CA bundle path"):
        Config(verify=bad_verify_path)

    with pytest.raises(ValueError, match="Invalid CA bundle path|Custom CA bundle path"):
        SecurityGuard.resolve_tls_verify(bad_verify_path)

    with pytest.raises(ValueError, match="Invalid CA bundle path|Custom CA bundle path"):
        resolve_tls_verify(bad_verify_path)


def test_fuzz_config_tilde_crash_replay() -> None:
    """Replay any saved Atheris crash units if present in the repository root."""
    crash_files = sorted(Path().glob("crash-*"))
    if not crash_files:
        pytest.skip("No crash artifacts present on disk.")

    atheris = pytest.importorskip("atheris")
    from tests.fuzz.fuzz_config import TestOneInput

    for crash_file in crash_files:
        TestOneInput(crash_file.read_bytes())
    assert atheris is not None
