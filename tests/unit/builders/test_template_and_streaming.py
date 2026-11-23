"""Unit tests for TemplateContentBuilder, SpamGuard HTML analysis, and ChunkedStreamer."""

from __future__ import annotations

import base64
import errno
import os
import stat
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mailjet_rest.builders import ChunkedStreamer, MessageBuilder, SendPayloadBuilder, TemplateContentBuilder
from mailjet_rest.errors import ValidationError
from mailjet_rest.utils.filesystem_security import check_file_size, validate_attachment_path, validate_multipart_files
from mailjet_rest.utils.guardrails import SecurityGuard
from mailjet_rest.utils.html_guard import _inspect_starttag, analyze_html_safety, build_spam_guard_parser
from mailjet_rest.utils.routing import external_stacklevel, resolve_dynamic_route


class _BytesPath:
    """PathLike returning bytes from __fspath__ to exercise TypeError paths."""

    def __fspath__(self) -> bytes:
        return b"/tmp/ca.pem"


def test_template_content_builder_mapping() -> None:
    """Verify correct payload assembly for templates."""
    builder = TemplateContentBuilder()
    builder.set_content(text="Hello", html="<b>Hello</b>", mjml="<mjml></mjml>")
    builder.set_headers({"X-Custom": "Value"})
    res = builder.build()
    assert res["Text-part"] == "Hello"
    assert res["Html-part"] == "<b>Hello</b>"
    assert res["Headers"]["X-Custom"] == "Value"


def test_template_content_builder_partial_data() -> None:
    """Verify partial content insertion."""
    builder = TemplateContentBuilder()
    builder.set_content(text="Only Text")
    res = builder.build()
    assert "Html-part" not in res
    assert res["Text-part"] == "Only Text"


def test_template_content_builder_validation_fails() -> None:
    """Verify empty template structures are blocked."""
    builder = TemplateContentBuilder()

    with pytest.warns(PendingDeprecationWarning, match="At least one of text, html, or mjml content is required"):
        builder.build()


def test_template_content_builder_empty_build() -> None:
    """Verify empty template structures are rejected cleanly."""
    builder = TemplateContentBuilder()

    with pytest.warns(PendingDeprecationWarning, match="At least one of text, html, or mjml"):
        builder.build()


def test_template_content_builder_partial_content() -> None:
    """Verify partial builds render safely."""
    builder1 = TemplateContentBuilder().set_content(text="text")
    assert "Text-part" in builder1.build()

    builder2 = TemplateContentBuilder().set_content(html="html")
    assert "Html-part" in builder2.build()


def test_spam_guard_html_analysis(monkeypatch: pytest.MonkeyPatch) -> None:
    """Coverage: Enable spam guard analysis in MessageBuilder."""
    builder = MessageBuilder()

    # Use monkeypatch to modify the ClassVar since __slots__ prevents instance mutation
    monkeypatch.setattr(MessageBuilder, "ENABLE_SPAM_GUARD", True)

    # Mock the security guard to return a "not safe" analysis,
    # simulating a deliverability warning without throwing a hard security exception.
    monkeypatch.setattr(
        "mailjet_rest.builders.SecurityGuard.analyze_html_safety",
        lambda html: {"is_safe": False, "issues": ["Mocked deliverability issue"]},
    )

    with pytest.warns(UserWarning, match="Deliverability Warning"):
        builder.set_content(html="<div>Mocked HTML</div>")


def test_template_content_builder_full() -> None:
    """Coverage: Test TemplateContentBuilder meta and mjml properties."""
    builder = TemplateContentBuilder()
    builder.set_meta(author="Author Name", name="Template Name", locale="en-US")
    builder.set_content(mjml="<mjml><mjml-body></mjml-body></mjml>")
    res = builder.build()
    assert res["Author"] == "Author Name"
    assert res["Name"] == "Template Name"
    assert res["Locale"] == "en-US"
    assert res["MJMLContent"] == "<mjml><mjml-body></mjml-body></mjml>"


def test_template_content_builder_meta_branches() -> None:
    """Coverage: Test isolated template builder meta properties."""
    b1 = TemplateContentBuilder().set_meta(author="A")
    assert b1._payload["Author"] == "A"
    b2 = TemplateContentBuilder().set_meta(name="N")
    assert b2._payload["Name"] == "N"
    b3 = TemplateContentBuilder().set_meta(locale="L")
    assert b3._payload["Locale"] == "L"


def test_html_guard_endtag_comment_limits_and_script_inspection() -> None:
    """Cover handle_endtag, handle_comment, max_html_size, max_tag_count, and executable tags."""
    parser_cls = build_spam_guard_parser()
    report = analyze_html_safety("<div>hello</div><!-- note -->", parser_factory=parser_cls)
    assert report == {"is_safe": True, "issues": []}

    with pytest.raises(ValueError, match="exceeds maximum safe length"):
        analyze_html_safety("a" * 50, parser_factory=parser_cls, max_html_size=10)

    with pytest.raises(ValidationError, match="maximum tag limit"):
        analyze_html_safety("<p>a</p><p>b</p>", parser_factory=parser_cls, max_tag_count=2)

    parser = parser_cls()
    _inspect_starttag(parser, "script", [("src", "x")])
    assert parser.has_script is True
    assert parser.is_safe is False
    assert parser.issues == ["Blocked executable tag: <script>"]


def test_builders_filesystem_html_and_routing_edges(tmp_path: Path) -> None:
    """Cover ChunkedStreamer TOCTOU size guard, SpamGuard warnings, routing stacklevel, and dynamic routes."""
    big_file = tmp_path / "grew.bin"
    big_file.write_bytes(b"A" * 64)
    fake_stat = MagicMock(st_mode=0o100644, st_size=10)
    with patch("os.fstat", return_value=fake_stat):
        with pytest.raises(ValueError, match="exceeds safe threshold"):
            ChunkedStreamer.encode_file(big_file, chunk_size=12, safe_base_dir=tmp_path, max_bytes=20)

    # Second attach_file reuses existing Attachments list; missing content raises ValueError
    att1 = tmp_path / "a.txt"
    att2 = tmp_path / "b.txt"
    att1.write_text("one", encoding="utf-8")
    att2.write_text("two", encoding="utf-8")
    mb = (
        MessageBuilder()
        .set_sender("a@example.com")
        .add_recipient("b@example.com")
        .attach_file(att1, base_dir=tmp_path)
        .attach_file(att2, base_dir=tmp_path)
    )
    with pytest.raises(ValueError, match="TextPart, HTMLPart, or TemplateID is required"):
        mb.build()
    mb.set_tracking(opens="enabled", clicks=None)

    with patch.object(SecurityGuard, "analyze_html_safety", return_value={"is_safe": False, "issues": ["warn"]}):
        old_msg_flag = MessageBuilder.ENABLE_SPAM_GUARD
        old_tpl_flag = TemplateContentBuilder.ENABLE_SPAM_GUARD
        MessageBuilder.ENABLE_SPAM_GUARD = True
        TemplateContentBuilder.ENABLE_SPAM_GUARD = True
        try:
            with pytest.warns(UserWarning, match="Deliverability Warning"):
                MessageBuilder().set_content(html="<p>hello</p>")
            with pytest.warns(UserWarning, match="Deliverability Warning"):
                TemplateContentBuilder().set_content(html="<p>hello</p>")
        finally:
            MessageBuilder.ENABLE_SPAM_GUARD = old_msg_flag
            TemplateContentBuilder.ENABLE_SPAM_GUARD = old_tpl_flag

    spb = SendPayloadBuilder()
    spb._messages = [{"From": {"Email": "a@example.com"}, "To": [], "Subject": "s"}] * 51  # type: ignore[assignment]
    with pytest.raises(ValueError, match="at most 50 messages"):
        spb.build()

    # filesystem_security non-regular file and invalid multipart entries
    with pytest.raises(ValueError, match="not a regular file"):
        check_file_size(tmp_path)
    assert validate_attachment_path(os.fsencode(att1), safe_base_dir=tmp_path) == att1.resolve()  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="Null byte"):
        validate_attachment_path(b"bad\x00path", safe_base_dir=tmp_path)  # type: ignore[arg-type]
    validate_multipart_files("not-a-mapping", header_sanitizer=dict)
    validate_multipart_files([("bad_arity",)], header_sanitizer=dict)
    validate_multipart_files({"f": "scalar-spec"}, header_sanitizer=dict)

    # html_guard handle_comment tag budget
    parser = build_spam_guard_parser()(max_tags=1)
    parser.feed("<!-- one -->")
    with pytest.raises(ValidationError, match="exceeds maximum tag limit"):
        parser.feed("<!-- two -->")

    # routing stacklevel & dynamic routes
    with patch("sys._getframe", side_effect=ValueError("no frame")):
        assert external_stacklevel() == 2

    fake_frame = types.SimpleNamespace(f_globals={"__name__": "mailjet_rest.sub"}, f_back=None)
    with patch("sys._getframe", return_value=fake_frame):
        assert external_stacklevel() == 2

    assert resolve_dynamic_route("send", "send", ["send"], "https://api.mailjet.com", "v3", None, None) == (
        "https://api.mailjet.com/v3/send",
        None,
        None,
    )
    assert resolve_dynamic_route(
        "batchjob_csvdata",
        "batchjob",
        ["batchjob", "csvdata"],
        "https://api.mailjet.com",
        "v3",
        None,
        "extra",
    ) == ("https://api.mailjet.com/v3/DATA/batchjob", None, "extra")


def test_shared_sibling_fingerprint_and_self_closing_spamguard() -> None:
    """Backtracking fingerprint distinguishes shared sibling dicts from cycles; self-closing tags are checked."""
    shared = {"email": "user@example.com"}
    p_shared = {"a": shared, "b": shared}
    p_distinct = {"a": {"email": "user@example.com"}, "b": {"email": "user@example.com"}}
    assert SecurityGuard.generate_payload_fingerprint(p_shared) == SecurityGuard.generate_payload_fingerprint(
        p_distinct
    )

    with pytest.raises(ValueError, match="blocked script/event execution tags|executable Javascript/XSS"):
        SecurityGuard.analyze_html_safety("<img src='cid:logo' onerror='x'/>")


def test_attachment_symlink_and_chunked_streamer_safeguards(tmp_path: Path) -> None:
    """Symlinks, missing tempdir files, and query/fragment delimiters are rejected."""
    secret_target = tmp_path / "real.txt"
    secret_target.write_bytes(b"hello world")
    symlink_path = tmp_path / "link.txt"
    symlink_path.symlink_to(secret_target)

    with pytest.raises(ValueError, match="Symlinks are strictly forbidden"):
        SecurityGuard.validate_attachment_path(symlink_path, safe_base_dir=tmp_path)

    with pytest.raises(ValueError, match="Symlinks are strictly forbidden"):
        ChunkedStreamer.encode_file(symlink_path, safe_base_dir=tmp_path)

    with pytest.raises(ValueError, match="Null byte"):
        SecurityGuard.validate_attachment_path("bad\x00path.txt", safe_base_dir=tmp_path)

    missing_temp = Path(tmp_path) / "nonexistent.txt"
    with pytest.raises(FileNotFoundError):
        SecurityGuard.validate_attachment_path(missing_temp)

    # Lossless base64 ASCII encoding via pinned fd
    b64 = ChunkedStreamer.encode_file(secret_target, chunk_size=4, safe_base_dir=tmp_path)
    assert base64.b64decode(b64) == b"hello world"

    # Directory & oversize limits fail closed
    with pytest.raises(FileNotFoundError):
        ChunkedStreamer.encode_file(tmp_path, safe_base_dir=tmp_path.parent)

    with pytest.raises(ValueError, match="exceeds safe threshold"):
        ChunkedStreamer.encode_file(secret_target, safe_base_dir=tmp_path, max_bytes=4)

    with patch("os.open", side_effect=OSError(errno.ELOOP, "Too many levels of symbolic links")):
        with pytest.raises(ValueError, match="Symlinks are strictly forbidden"):
            ChunkedStreamer.encode_file(secret_target, safe_base_dir=tmp_path)


def test_chunked_streamer_boundaries_and_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise ChunkedStreamer.encode_file validation, chunk sizing, O_NOFOLLOW, and fstat guards."""
    sample = tmp_path / "payload.bin"
    raw_bytes = b"abcdefghij"  # 10 bytes
    sample.write_bytes(raw_bytes)

    for bad_chunk in (True, False, 0, -3, "3"):
        with pytest.raises(ValueError) as exc_info:
            ChunkedStreamer.encode_file(sample, chunk_size=bad_chunk, safe_base_dir=tmp_path)  # type: ignore[arg-type]
        assert str(exc_info.value) == "chunk_size must be a strictly positive integer."

    for bad_max in (True, False, 0, -1, "10"):
        with pytest.raises(ValueError) as exc_info:
            ChunkedStreamer.encode_file(sample, max_bytes=bad_max, safe_base_dir=tmp_path)  # type: ignore[arg-type]
        assert str(exc_info.value) == "max_bytes must be a strictly positive integer."

    # chunk_size=1 uses step=max(3, 0)=3 across multiple base64 chunks
    encoded_small = ChunkedStreamer.encode_file(sample, chunk_size=1, safe_base_dir=tmp_path, max_bytes=len(raw_bytes))
    assert encoded_small == base64.b64encode(raw_bytes).decode("ascii")

    # chunk_size=6 (two 6-byte / 4-byte reads) also matches standard base64
    assert ChunkedStreamer.encode_file(sample, chunk_size=6, safe_base_dir=tmp_path) == base64.b64encode(
        raw_bytes
    ).decode("ascii")

    with pytest.raises(ValueError) as cap_exc:
        ChunkedStreamer.encode_file(sample, safe_base_dir=tmp_path, max_bytes=len(raw_bytes) - 1)
    assert str(cap_exc.value) == "Security Violation: File 'payload.bin' exceeds safe threshold."

    # Simulate O_NOFOLLOW ELOOP on os.open directly
    def raise_eloop(*args: object, **kwargs: object) -> int:
        raise OSError(errno.ELOOP, "Too many symbolic links encountered")

    monkeypatch.setattr("mailjet_rest.builders.os.open", raise_eloop)
    with pytest.raises(ValueError) as sym_exc:
        ChunkedStreamer.encode_file(sample, safe_base_dir=tmp_path)
    assert str(sym_exc.value) == "Security Violation (CWE-22): Symlinks are strictly forbidden for attachments."

    # Non-ELOOP OSError propagates directly
    def raise_eacces(*args: object, **kwargs: object) -> int:
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr("mailjet_rest.builders.os.open", raise_eacces)
    with pytest.raises(PermissionError):
        ChunkedStreamer.encode_file(sample, safe_base_dir=tmp_path)
    monkeypatch.undo()

    # Non-regular fd reported by fstat raises ValueError and closes fd
    monkeypatch.setattr(
        "mailjet_rest.builders.os.fstat",
        lambda _fd: os.stat_result((stat.S_IFIFO | 0o600, 0, 0, 0, 0, 0, 0, 0, 0, 0)),
    )
    with pytest.raises(ValueError) as fifo_exc:
        ChunkedStreamer.encode_file(sample, safe_base_dir=tmp_path)
    assert "Path is not a regular file:" in str(fifo_exc.value)
