"""Unit tests for Wave 4: stream() bounds & errors, RFC 8058 builders, CID/102KB/batch caps, semver, and OPT-08."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mailjet_rest.builders import MessageBuilder, SendPayloadBuilder, TemplateContentBuilder
from mailjet_rest.client import Client
from mailjet_rest.errors import MailjetApiError
from mailjet_rest.utils.guardrails import SecurityGuard
from mailjet_rest.utils.version import clean_version, parse_semver_triplet


def test_semver_prerelease_triplet_parsing() -> None:
    """Verify HIGH-07: prerelease digits are not concatenated into patch."""
    assert parse_semver_triplet("1.9.1rc2") == (1, 9, 1)
    assert parse_semver_triplet("1.10.0post3") == (1, 10, 0)
    assert parse_semver_triplet("2.0.15.dev4") == (2, 0, 15)
    assert clean_version("1.9.1rc2") == (1, 9, 1)
    assert clean_version("1.10.0post3") == (1, 10, 0)
    assert clean_version("invalid") == (0, 0, 0)

    with pytest.raises(ValueError, match="Expected X.Y.Z"):
        parse_semver_triplet("1.2")
    with pytest.raises(ValueError, match="Invalid patch component"):
        parse_semver_triplet("1.2.rc1")


def test_stream_bool_negative_max_items_and_bad_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify HIGH-04 bool/negative guards, max_items limit, and MailjetApiError on invalid JSON."""
    with Client(auth=("pub", "priv")) as client:
        with pytest.raises(ValueError, match="strictly positive integer"):
            next(client.contact.stream(chunk_size=True))  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="Offset filter must be an integer"):
            next(client.contact.stream(filters={"Offset": True}))

        with pytest.raises(ValueError, match="non-negative integer"):
            next(client.contact.stream(filters={"Offset": -1}))

        with pytest.raises(ValueError, match="max_items"):
            next(client.contact.stream(max_items=True))  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="max_items"):
            next(client.contact.stream(max_items=-5))

        calls = 0

        def mock_request(method: str, url: str, **kwargs: object) -> MagicMock:
            nonlocal calls
            calls += 1
            resp = MagicMock()
            resp.status_code = 200
            resp.text = '{"Data": []}'
            if calls == 1:
                resp.json.return_value = {"Data": [{"ID": 1}, {"ID": 2}]}
            elif calls == 2:
                resp.json.return_value = {"Data": [{"ID": 3}, {"ID": 4}]}
            return resp

        monkeypatch.setattr(client.session, "request", mock_request)

        # max_items == 0 performs zero HTTP calls
        assert list(client.contact.stream(chunk_size=2, max_items=0)) == []
        assert calls == 0

        # max_items == 3 stops cleanly after item 3
        items = list(client.contact.stream(chunk_size=2, max_items=3))
        assert [item["ID"] for item in items] == [1, 2, 3]
        assert calls == 2

        # Malformed JSON raises MailjetApiError
        bad_json_resp = MagicMock()
        bad_json_resp.status_code = 502
        bad_json_resp.text = "bad gateway"
        bad_json_resp.json.side_effect = ValueError("No JSON")
        monkeypatch.setattr(client.session, "request", MagicMock(return_value=bad_json_resp))
        with pytest.raises(MailjetApiError, match="Malformed JSON"):
            next(client.contact.stream())

        # Non-dict JSON body raises MailjetApiError
        list_resp = MagicMock()
        list_resp.status_code = 200
        list_resp.text = "[]"
        list_resp.json.return_value = []
        monkeypatch.setattr(client.session, "request", MagicMock(return_value=list_resp))
        with pytest.raises(MailjetApiError, match="Expected JSON object"):
            next(client.contact.stream())

        # Non-list 'Data' raises MailjetApiError
        bad_data_resp = MagicMock()
        bad_data_resp.status_code = 200
        bad_data_resp.text = '{"Data": 123}'
        bad_data_resp.json.return_value = {"Data": 123}
        monkeypatch.setattr(client.session, "request", MagicMock(return_value=bad_data_resp))
        with pytest.raises(MailjetApiError, match="Expected 'Data' list"):
            next(client.contact.stream())


def test_rfc8058_unsubscribe_tracking_and_deepcopy() -> None:
    """Verify RFC 8058 headers, tracking/custom_id validation, and deep copy isolation."""
    mb = (
        MessageBuilder()
        .set_sender("sender@example.com", "Sender")
        .add_recipient("to@example.com")
        .set_subject("Hello")
        .set_content(text="plain body")
        .set_custom_id("order-123")
        .set_event_payload('{"order":123}')
        .set_tracking(opens="enabled", clicks="disabled")
        .set_variables({"nested": {"k": "v"}})
        .set_list_unsubscribe("https://example.com/unsub?t=abc", mailto_address="unsub@example.com")
    )
    built = mb.build()
    assert built["Headers"]["List-Unsubscribe"] == "<https://example.com/unsub?t=abc>, <mailto:unsub@example.com>"
    assert built["Headers"]["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click"
    assert built["CustomID"] == "order-123"
    assert built["TrackOpens"] == "enabled"
    assert built["TrackClicks"] == "disabled"

    # Mutating built result does not mutate internal builder state
    built["Variables"]["nested"]["k"] = "mutated"
    built["To"].append({"Email": "extra@example.com"})
    rebuilt = mb.build()
    assert rebuilt["Variables"]["nested"]["k"] == "v"
    assert len(rebuilt["To"]) == 1

    # Non-HTTPS and CRLF rejected
    with pytest.raises(ValueError, match="https://"):
        mb.set_list_unsubscribe("http://example.com/unsub")
    with pytest.raises(ValueError, match="CWE-93"):
        mb.set_list_unsubscribe("https://example.com/unsub\r\nX-Evil: 1")
    with pytest.raises(ValueError, match="TrackOpens"):
        mb.set_tracking(opens="invalid")  # type: ignore[arg-type]


def test_inline_cid_and_gmail_102kb_warning(tmp_path: Path) -> None:
    """Verify inline ContentID, missing CID warning, and 102 KB Gmail clipping warning."""
    logo = tmp_path / "logo.png"
    logo.write_bytes(b"\x89PNG\r\n\x1a\nlogo")

    # Matching ContentID emits zero warning
    clean_builder = (
        MessageBuilder()
        .set_sender("sender@example.com")
        .add_recipient("to@example.com")
        .attach_inline(logo, content_type="image/png", base_dir=tmp_path, content_id="logo-cid")
        .set_content(html='<img src="cid:logo-cid">')
    )
    clean_msg = clean_builder.build()
    assert clean_msg["InlinedAttachments"][0]["ContentID"] == "logo-cid"

    # Missing CID reference warns
    missing_cid = (
        MessageBuilder()
        .set_sender("sender@example.com")
        .add_recipient("to@example.com")
        .set_content(html='<img src="cid:missing-cid">')
    )
    with pytest.warns(UserWarning, match="missing-cid"):
        missing_cid.build()

    # >102 KB HTML warns about Gmail clipping
    large_html = (
        MessageBuilder()
        .set_sender("sender@example.com")
        .add_recipient("to@example.com")
        .set_content(html="<p>" + ("a" * (110 * 1024)) + "</p>")
    )
    with pytest.warns(UserWarning, match="102 KB"):
        large_html.build()


def test_send_payload_and_template_batch_limits() -> None:
    """Verify SendPayloadBuilder 50-message limit, 15MB cap, and TemplateContentBuilder deepcopy."""
    msg = (
        MessageBuilder()
        .set_sender("sender@example.com")
        .add_recipient("to@example.com")
        .set_content(text="hi")
        .build()
    )

    batch = SendPayloadBuilder()
    for _ in range(50):
        batch.add_message(msg)
    built_batch = batch.build()
    assert len(built_batch["Messages"]) == 50

    with pytest.raises(ValueError, match="at most 50"):
        batch.add_message(msg)

    # 15MB total payload limit check
    huge_text = "x" * (4 * 1024 * 1024)
    big_msg = (
        MessageBuilder()
        .set_sender("sender@example.com")
        .add_recipient("to@example.com")
        .set_content(text=huge_text)
        .build()
    )
    oversize_batch = SendPayloadBuilder()
    for _ in range(4):
        oversize_batch.add_message(big_msg)
    with pytest.raises(ValueError, match="15MB"):
        oversize_batch.build()

    tb = TemplateContentBuilder().set_meta(author="Alice").set_content(text="body").set_headers({"X-A": "1"})
    t_payload = tb.build()
    t_payload["Headers"]["X-A"] = "mutated"
    assert tb.build()["Headers"]["X-A"] == "1"


def test_normalize_domain_ascii_fast_path_and_bounds() -> None:
    """Verify OPT-08 ASCII fast path, lowercase normalization, and RFC 1035 label bounds."""
    assert SecurityGuard.normalize_domain("User@Example.COM") == "User@example.com"
    assert SecurityGuard.normalize_domain("sub.MAILJET.com") == "sub.mailjet.com"
    assert SecurityGuard.normalize_domain("info@münchen.de") == "info@xn--mnchen-3ya.de"

    with pytest.raises(ValueError, match="Invalid IDN in email"):
        SecurityGuard.normalize_domain("user@" + ("a" * 64) + ".com")
    with pytest.raises(ValueError, match="Invalid IDN"):
        SecurityGuard.normalize_domain(".".join(["a" * 50] * 6))
