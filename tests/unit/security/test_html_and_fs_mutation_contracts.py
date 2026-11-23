"""Mutation-killing contract tests for html_guard, filesystem_security, guardrails, and transport_security."""

from __future__ import annotations

import logging
import os
import ssl
import sys
import warnings
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

from mailjet_rest.client import _httpx2
from mailjet_rest.errors import ValidationError
from mailjet_rest.utils.filesystem_security import (
    _validate_zero_trust_path,
    check_file_size,
    validate_attachment_path,
    validate_multipart_files,
)
from mailjet_rest.utils.guardrails import RedactingFilter, SecurityGuard, _deep_strip_volatile
from mailjet_rest.utils.html_guard import (
    analyze_html_safety,
    build_spam_guard_parser,
)
from mailjet_rest.utils.transport_security import (
    SecretAuth,
    _cached_ssl_context,
    _new_secure_ssl_context,
    build_httpx2_transport,
    build_ssl_context_with_cert,
    coerce_httpx2_timeout,
    get_secure_ssl_context,
)


if TYPE_CHECKING:
    from pathlib import Path


# ==========================================
# html_guard.py mutation contracts
# ==========================================


def test_spam_guard_parser_slots_default_limit_and_starttag_vectors() -> None:
    """Verify _SpamGuardParser __slots__, default max_tags=10000, and all blocked starttag vectors."""
    parser_cls = build_spam_guard_parser()
    parser = parser_cls()
    for slot_name in ("has_script", "is_safe", "issues", "max_tags", "tag_count"):
        assert slot_name in parser_cls.__slots__
        assert slot_name not in parser.__dict__
    assert parser.max_tags == 10000
    assert parser.has_script is False
    assert parser.is_safe is True

    # Directly verify all blocked executable tags & event handler attributes inside HTMLParser
    for blocked_tag in ("script", "IFRAME", "Object", "embed", "ApPlEt"):
        p = parser_cls()
        p.feed(f"<{blocked_tag}>body</{blocked_tag}>")
        assert p.has_script is True
        assert p.is_safe is False
        assert p.issues == [f"Blocked executable tag: <{blocked_tag.lower()}>"]

    ev_parser = parser_cls()
    ev_parser.feed('<img onclick="evil()" src="x.png">')
    assert ev_parser.has_script is True
    assert ev_parser.is_safe is False
    assert ev_parser.issues == ["Blocked event handler: onclick"]

    # LazyHtmlGuardMeta caches _SpamGuardParser and rejects unknown attributes with exact error
    cached_cls_a = SecurityGuard._SpamGuardParser
    cached_cls_b = SecurityGuard._SpamGuardParser
    assert cached_cls_a is cached_cls_b
    with pytest.raises(AttributeError, match="has no attribute 'MissingAttr'"):
        _ = getattr(SecurityGuard, "MissingAttr")


def test_analyze_html_safety_boundaries_audit_and_custom_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify analyze_html_safety exact size/tag boundaries, audit events, and custom parser_factory."""
    audit_calls: list[tuple[str, tuple[object, ...]]] = []

    def _capture_audit(event: str, *args: object) -> None:
        audit_calls.append((event, args))

    monkeypatch.setattr(sys, "audit", _capture_audit)

    # Whitespace and empty inputs return canonical safe dict shape
    assert analyze_html_safety("   \t\n", parser_factory=build_spam_guard_parser()) == {
        "is_safe": True,
        "issues": [],
    }

    # Exact max_html_size boundary: == max_html_size passes, +1 raises and audits HTMLPart
    exact_html = "a" * 32
    assert analyze_html_safety(exact_html, parser_factory=build_spam_guard_parser(), max_html_size=32) == {
        "is_safe": True,
        "issues": [],
    }
    with pytest.raises(ValueError, match="HTML payload exceeds maximum safe length"):
        analyze_html_safety(exact_html + "b", parser_factory=build_spam_guard_parser(), max_html_size=32)
    assert ("mailjet.security.resource_exhaustion", ("HTMLPart",)) in audit_calls

    # XSS regex and parser event-handler paths both emit exact HTMLPart xss_attempt audits
    audit_calls.clear()
    with pytest.raises(ValueError, match="executable Javascript/XSS vectors"):
        analyze_html_safety("<svg></svg>", parser_factory=build_spam_guard_parser())
    assert audit_calls == [("mailjet.security.xss_attempt", ("HTMLPart",))]

    audit_calls.clear()
    with pytest.raises(ValueError, match="blocked script/event execution tags"):
        analyze_html_safety('<div onclick="alert(1)">hi</div>', parser_factory=build_spam_guard_parser())
    assert audit_calls == [("mailjet.security.xss_attempt", ("HTMLPart",))]

    # Exact tag boundary and custom parser_factory (has_script=False with is_safe=False)
    tag_ok = "<b></b>" * 2  # 4 tags (2 start + 2 end)
    assert analyze_html_safety(tag_ok, parser_factory=build_spam_guard_parser(), max_tag_count=4)["is_safe"] is True
    with pytest.raises(ValidationError, match="maximum tag limit"):
        analyze_html_safety(tag_ok + "<i>", parser_factory=build_spam_guard_parser(), max_tag_count=4)

    class _UnsafeWithoutScript:
        def __init__(self) -> None:
            self.max_tags = 10000
            self.has_script = False
            self.is_safe = False
            self.issues = ["suspicious markup"]

        def feed(self, _html: str) -> None:
            pass

        def close(self) -> None:
            pass

    res = analyze_html_safety("<p>ok</p>", parser_factory=_UnsafeWithoutScript)
    assert res == {"is_safe": False, "issues": ["suspicious markup"]}


# ==========================================
# filesystem_security.py mutation contracts
# ==========================================


def test_zero_trust_path_fail_closed_roots_components_and_audits(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Verify zero-trust path checks fail closed if tempdir fails and enforce roots, components, and audits."""
    audit_calls: list[tuple[str, tuple[object, ...]]] = []
    monkeypatch.setattr(sys, "audit", lambda ev, *args: audit_calls.append((ev, args)))

    # 1. Valid non-temp file outside tempfile.gettempdir kills inverted `not in forbidden_components` mutant
    non_temp_root = os.path.abspath(os.path.join(os.sep, "home", "non_tmp_sandbox", "invoice.pdf"))
    with patch("tempfile.gettempdir", return_value=str(tmp_path / "isolated_tmp")):
        _validate_zero_trust_path(non_temp_root, type(tmp_path)(non_temp_root))

        # Every forbidden root and nested forbidden component must raise ValueError
        class _FakeTarget:
            __slots__ = ("_raw", "parts")

            def __init__(self, raw: str) -> None:
                self._raw = raw
                self.parts = ()

            def is_relative_to(self, _other: object) -> bool:
                return False

            def __str__(self) -> str:
                return self._raw

        for root_prefix in (
            "/etc/passwd",
            "/var/log/syslog",
            "/root/.ssh/id_rsa",
            "/boot/vmlinuz",
            "C:\\Windows\\win.ini",
            "C:\\System32\\cmd.exe",
        ):
            fake_target = _FakeTarget(root_prefix)
            with pytest.raises(ValueError, match="sensitive OS system directories"):
                _validate_zero_trust_path(root_prefix, fake_target)  # type: ignore[arg-type]

        for comp in ("etc", "sys", "proc", "dev", "windows", "system32", "root", "boot"):
            fake_nested = type(tmp_path)(os.path.join(os.sep, "app", comp, "payload.bin"))
            with pytest.raises(ValueError, match="sensitive OS system directories"):
                _validate_zero_trust_path(str(fake_nested), fake_nested)

    # 2. Fail-closed when tempfile.gettempdir() raises
    with patch("tempfile.gettempdir", side_effect=OSError("no tempdir")):
        etc_path = type(tmp_path)("/etc/passwd")
        with pytest.raises(ValueError, match="sensitive OS system directories"):
            _validate_zero_trust_path("/etc/passwd", etc_path)

    # 3. Symlink and outside-base traversal emit exact sys.audit events, missing file has exact message
    target_file = tmp_path / "real.txt"
    target_file.write_text("ok", encoding="utf-8")
    link_file = tmp_path / "link.txt"
    link_file.symlink_to(target_file)
    with pytest.raises(ValueError, match="Symlinks are strictly forbidden"):
        validate_attachment_path(link_file, safe_base_dir=tmp_path)
    assert ("mailjet.security.path_traversal", (str(link_file),)) in audit_calls

    base_sub = tmp_path / "allowed"
    base_sub.mkdir()
    audit_calls.clear()
    with pytest.raises(ValueError, match="Traversal detected"):
        validate_attachment_path(target_file, safe_base_dir=base_sub)
    assert ("mailjet.security.path_traversal", (str(target_file.resolve()),)) in audit_calls

    missing_file = base_sub / "missing.txt"
    with pytest.raises(FileNotFoundError, match=f"Attachment not found or is not a file: {missing_file.resolve()}"):
        validate_attachment_path(missing_file, safe_base_dir=base_sub)


def test_file_size_exact_threshold_and_multipart_audits(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Verify exact check_file_size boundary and 1/3/4-tuple multipart metadata validation."""
    audit_calls: list[tuple[str, tuple[object, ...]]] = []
    monkeypatch.setattr(sys, "audit", lambda ev, *args: audit_calls.append((ev, args)))

    sample = tmp_path / "sized.bin"
    sample.write_bytes(b"12345")
    check_file_size(sample, max_size_bytes=5)
    with pytest.raises(ValueError, match="exceeds safe threshold"):
        check_file_size(sample, max_size_bytes=4)

    # 1-tuple filename-only spec must still validate CRLF/NUL in filename
    validate_multipart_files([("file", ("clean.txt",))], header_sanitizer=SecurityGuard.sanitize_headers)
    with pytest.raises(ValueError, match="Multipart file filename"):
        validate_multipart_files([("file", ("bad\r\n.txt",))], header_sanitizer=SecurityGuard.sanitize_headers)
    assert ("mailjet.security.header_injection", ("filename",)) in audit_calls

    audit_calls.clear()
    with pytest.raises(ValueError, match="Multipart file content_type"):
        validate_multipart_files(
            [("file", ("clean.txt", b"x", b"text/plain\r\nX: y"))],
            header_sanitizer=SecurityGuard.sanitize_headers,
        )
    assert ("mailjet.security.header_injection", ("content_type",)) in audit_calls

    audit_calls.clear()
    with pytest.raises(ValueError, match="Multipart file field_name"):
        validate_multipart_files(
            [("bad\nfield", ("clean.txt", b"x", "text/plain"))],
            header_sanitizer=SecurityGuard.sanitize_headers,
        )
    assert ("mailjet.security.header_injection", ("field_name",)) in audit_calls


# ==========================================
# guardrails.py & transport_security.py mutation contracts
# ==========================================


def test_guardrails_depth_proxy_url_idn_timeout_and_canonical_json_contracts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify exact depth-50, proxy, IDN rpartition/label-63, timeout, and audit contracts."""
    audit_calls: list[tuple[str, tuple[object, ...]]] = []
    monkeypatch.setattr(sys, "audit", lambda ev, *args: audit_calls.append((ev, args)))

    # 1. _deep_strip_volatile exact depth 50 vs 51 and circular lists
    shallow_node: Any = {"leaf": "ok"}
    for _ in range(49):
        shallow_node = {"k": shallow_node}
    stripped = _deep_strip_volatile(shallow_node, frozenset())
    assert isinstance(stripped, dict)

    deep_node: Any = {"leaf": "too_deep"}
    for _ in range(50):
        deep_node = {"k": deep_node}
    with pytest.raises(ValueError, match="Security Violation: Payload exceeds maximum safe nesting depth."):
        _deep_strip_volatile(deep_node, frozenset())

    circ_list: list[Any] = []
    circ_list.append(circ_list)
    assert _deep_strip_volatile(circ_list, frozenset()) == ["[Circular]"]

    # 2. URL hostname / fragment / credentials / proxy validation
    SecurityGuard.validate_config_url("https://sub.custom.example/", allowed_root_domain="custom.example")
    with pytest.raises(ValueError, match="custom.example"):
        SecurityGuard.validate_config_url("https://api.mailjet.com/", allowed_root_domain="custom.example")

    SecurityGuard.check_request_security({"proxies": "socks5://proxy.internal:1080"})
    SecurityGuard.check_request_security({"proxies": "socks5h://proxy.internal:1080"})
    with pytest.warns(UserWarning, match="Security Warning: Unencrypted HTTP proxy detected."):
        SecurityGuard.check_request_security({"proxies": "HTTP://proxy.internal:8080"})
    with pytest.raises(ValueError, match="Invalid or unsupported proxy scheme"):
        SecurityGuard.check_request_security({"proxies": "ftp://proxy.internal:21"})

    # 3. IDN domain boundaries: multiple '@' uses rpartition; 63-char vs 64-char label
    label_63 = "a" * 63
    assert SecurityGuard.normalize_domain(f"{label_63}.com") == f"{label_63}.com"
    with pytest.raises(ValueError, match="^Invalid IDN:"):
        SecurityGuard.normalize_domain(f"{'b' * 64}.com")
    with pytest.raises(ValueError, match="^Invalid IDN in email:"):
        SecurityGuard.normalize_domain('"user@name"@' + ("c" * 64) + ".com")

    # 4. Segment sanitization uppercase %2E, safe="", and SSTI markers
    assert SecurityGuard.sanitize_segment("a.b c") == "a%2Eb%20c"
    for bad_seg in ("%7B%7B7*7%7D%7D", "%7D%7D", "%7B%25"):
        with pytest.raises(ValueError, match="Template injection"):
            SecurityGuard.sanitize_segment(bad_seg)
    with pytest.raises(ValueError, match="Query or fragment delimiters"):
        SecurityGuard.sanitize_segment("item?x=1")

    # 5. Control char / timeout / header audits and exact warnings
    audit_calls.clear()
    with pytest.raises(ValueError, match="Unprintable control character detected in 'custom_field'"):
        SecurityGuard.check_control_characters("custom_field", "bad\x01val")
    assert ("mailjet.security.control_characters", ("custom_field",)) in audit_calls

    with pytest.warns(DeprecationWarning, match="Timeout set to None"):
        assert SecurityGuard.validate_timeout(None) is None

    audit_calls.clear()
    assert SecurityGuard.validate_timeout(86400.0) == 86400.0
    assert audit_calls == []
    with pytest.raises(ValueError, match="exceeds maximum allowed limit"):
        SecurityGuard.validate_timeout(86401.0)
    with pytest.raises(ValueError, match="cannot be Infinity or NaN"):
        SecurityGuard.validate_timeout(float("inf"))
    assert ("mailjet.security.resource_exhaustion", ("inf",)) in audit_calls

    # 6. RedactingFilter depth, NamedTuple, model_dump, and standard attrs
    rf = RedactingFilter()
    rec = logging.LogRecord("mailjet_rest.test", logging.INFO, __file__, 1, "clean message", None, None)
    assert rf.filter(rec) is True
    redacted_ns = rf._redact_object(SimpleNamespace(secret="val"), depth=0)  # pragma: allowlist secret
    assert redacted_ns["secret"] == "********"

    class _PydanticLike:
        def model_dump(self) -> dict[str, str]:
            return {"api_key": "redaction-fixture", "note": "plain"}  # pragma: allowlist secret

    dumped = rf._redact_object(_PydanticLike(), depth=0)
    assert dumped == {"api_key": "********", "note": "plain"}  # pragma: allowlist secret
    tuple_redacted = rf._redact_tuple(("Authorization: Bearer fixture_xyz_12345",), depth=0)
    assert tuple_redacted == ("Authorization: Bearer ********",)


def test_transport_security_ssl_cache_httpx2_transport_and_secret_auth(tmp_path: Path) -> None:
    """Verify SSL context caching args, httpx2 transport construction, and SecretAuth space/hash contracts."""
    # Space (ord == 32) is valid in API key/secret; control chars (< 32 or 127) are forbidden
    auth_with_space = SecretAuth(("user key", "secret val"))
    assert "Authorization" in auth_with_space(SimpleNamespace(headers={})).headers  # type: ignore[arg-type]
    assert hash(auth_with_space) == hash(("user key", "secret val"))
    assert hash(SecretAuth(("user key", "secret val"))) == hash(auth_with_space)
    assert hash(SecretAuth(("other", "secret val"))) != hash(auth_with_space)
    with pytest.raises(ValueError, match="2-tuple"):
        SecretAuth(("only_one",))
    with pytest.raises(TypeError, match="must be strings"):
        SecretAuth(("k", 123))

    # _new_secure_ssl_context & get_secure_ssl_context exact cache key forwarding
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("dummy", encoding="utf-8")
    with patch("mailjet_rest.utils.transport_security._cached_ssl_context") as mock_cache:
        get_secure_ssl_context(None)
        mock_cache.assert_called_with(None, 0, 0)
        st = ca_file.stat()
        get_secure_ssl_context(str(ca_file))
        mock_cache.assert_called_with(str(ca_file), st.st_mtime_ns, st.st_size)
    _cached_ssl_context.cache_clear()

    # build_httpx2_transport forwards ssl_ctx, limits, retries=0, cert
    mock_httpx2 = MagicMock()
    sentinel_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with patch(
        "mailjet_rest.utils.transport_security.build_ssl_context_with_cert", return_value=sentinel_ctx
    ) as m_cert:
        build_httpx2_transport(
            mock_httpx2,
            str(ca_file),
            pool_connections=12,
            pool_maxsize=34,
            cert=("c.pem", "k.pem"),
        )
    m_cert.assert_called_once_with(str(ca_file), ("c.pem", "k.pem"))
    mock_httpx2.Limits.assert_called_once_with(max_connections=34, max_keepalive_connections=12)
    _, transport_kw = mock_httpx2.AsyncHTTPTransport.call_args
    assert transport_kw["verify"] is sentinel_ctx
    assert transport_kw["retries"] == 0

    with patch("mailjet_rest.utils.transport_security.get_secure_ssl_context", return_value=sentinel_ctx) as m_ssl:
        build_httpx2_transport(mock_httpx2, str(ca_file), pool_connections=5, pool_maxsize=6, cert=None)
    m_ssl.assert_called_once_with(str(ca_file))

    if _httpx2 is not None:
        real_to = coerce_httpx2_timeout(_httpx2, 7.5)
        assert getattr(real_to, "read", None) == 7.5
        _ = build_ssl_context_with_cert(None, None)
        _ = _new_secure_ssl_context(None)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            assert len(SecurityGuard._canonical_json_bytes({"b": 1, "a": 2})) > 0

    with patch("mailjet_rest.utils.guardrails._orjson", None):
        assert SecurityGuard._canonical_json_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert SecurityGuard._canonical_json_bytes({1: "a"}) == b'{"1":"a"}'
