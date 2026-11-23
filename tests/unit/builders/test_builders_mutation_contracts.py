"""Mutation-killing contract tests for MessageBuilder, SendPayloadBuilder, TemplateContentBuilder, and ChunkedStreamer."""

from __future__ import annotations

import base64
import json
import os
import warnings
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import patch

import pytest

from mailjet_rest.builders import (
    ChunkedStreamer,
    MessageBuilder,
    SendPayloadBuilder,
    TemplateContentBuilder,
    _estimate_json_char_upper_bound,
)


if TYPE_CHECKING:
    from pathlib import Path


def test_clone_message_payload_and_recipient_variants_isolation(tmp_path: Path) -> None:
    """Verify Cc/Bcc-only recipients, CID matching warnings, and complete deepcopy isolation across build()."""
    logo = tmp_path / "logo.png"
    logo.write_bytes(b"png-bytes")

    # Valid message with Cc-only or Bcc-only (no To required)
    cc_only = cast(
        "dict[str, Any]",
        (
            MessageBuilder()
            .set_sender("sender@example.com", "Sender")
            .add_cc("cc@example.com", "CC User")
            .set_reply_to("reply@example.com", "Reply")
            .set_content(text="plain")
            .build()
        ),
    )
    assert cc_only["Cc"] == [{"Email": "cc@example.com", "Name": "CC User"}]
    assert cc_only["ReplyTo"] == {"Email": "reply@example.com", "Name": "Reply"}

    bcc_builder = (
        MessageBuilder()
        .set_sender("sender@example.com")
        .add_cc("cc@example.com")
        .add_bcc("bcc@example.com", "BCC User")
        .set_reply_to("reply@example.com", "Reply Name")
        .set_headers({"X-Keep": "1"})
        .set_variables({"nested": {"k": "v"}})
        .attach_file(logo, base_dir=tmp_path)
        .attach_inline(logo, base_dir=tmp_path, content_id="LOGO")
        .set_content(html="<img src='CID:MISSING'><img src='cid:LOGO'>")
    )
    with pytest.warns(UserWarning, match=r"\['MISSING'\]"):
        built_a = cast("dict[str, Any]", bcc_builder.build())

    # Mutating every nested container on built_a must NOT leak into subsequent build()
    built_a["From"]["Email"] = "mutated@example.com"
    built_a["Cc"][0]["Email"] = "mutated@example.com"
    built_a["Bcc"][0]["Email"] = "mutated@example.com"
    built_a["ReplyTo"]["Email"] = "mutated@example.com"
    built_a["Headers"]["X-Keep"] = "mutated"
    built_a["Variables"]["nested"]["k"] = "mutated"
    built_a["Attachments"][0]["Filename"] = "mutated.png"
    built_a["InlinedAttachments"][0]["ContentID"] = "mutated"

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        built_b = cast("dict[str, Any]", bcc_builder.build())

    assert built_b["From"]["Email"] == "sender@example.com"
    assert built_b["Cc"][0]["Email"] == "cc@example.com"
    assert built_b["Bcc"][0]["Email"] == "bcc@example.com"
    assert built_b["ReplyTo"]["Email"] == "reply@example.com"
    assert built_b["Headers"]["X-Keep"] == "1"
    assert built_b["Variables"]["nested"]["k"] == "v"
    assert built_b["Attachments"][0]["Filename"] == "logo.png"
    assert built_b["InlinedAttachments"][0]["ContentID"] == "LOGO"


def test_chunked_streamer_bounds_o_nofollow_and_builder_size_boundaries(tmp_path: Path) -> None:
    """Verify ChunkedStreamer bounds, O_NOFOLLOW flag, and exact size-limit boundaries across builders."""
    assert ChunkedStreamer._validate_encode_bounds(6, 1) == 6
    assert ChunkedStreamer._validate_encode_bounds(4, 1) == 3

    data_file = tmp_path / "payload.bin"
    raw = b"HelloWorld123456"
    data_file.write_bytes(raw)

    observed_flags: list[int] = []
    real_open = os.open

    def _spy_open(path: str | bytes, flags: int, *args: Any, **kwargs: Any) -> int:
        observed_flags.append(flags)
        return real_open(path, flags, *args, **kwargs)

    with patch("os.open", side_effect=_spy_open):
        encoded = ChunkedStreamer.encode_file(data_file, chunk_size=6, safe_base_dir=tmp_path, max_bytes=len(raw))
    assert base64.b64decode(encoded) == raw
    expected_flag = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    assert observed_flags == [expected_flag]

    with pytest.raises(ValueError, match="exceeds safe threshold"):
        ChunkedStreamer.encode_file(data_file, chunk_size=6, safe_base_dir=tmp_path, max_bytes=len(raw) - 1)

    # TemplateContentBuilder individual content keys emit no PendingDeprecationWarning
    for kw in ({"text": "plain"}, {"html": "<p>hi</p>"}, {"mjml": "<mjml></mjml>"}):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", PendingDeprecationWarning)
            res = TemplateContentBuilder().set_content(**kw).build()
        assert not caught
        assert res

    with pytest.warns(PendingDeprecationWarning, match="At least one of text, html, or mjml"):
        _ = TemplateContentBuilder().build()

    # SendPayloadBuilder globals deep isolation & default SandboxMode omission
    base_msg = MessageBuilder().set_sender("a@b.com").add_recipient("c@d.com").set_content(text="hi").build()
    spb = SendPayloadBuilder().add_message(base_msg).set_globals({"nested": {"env": "prod"}})
    root_a = spb.build()
    assert "SandboxMode" not in root_a
    root_a["Globals"]["nested"]["env"] = "corrupted"  # type: ignore[index]
    root_b = spb.build()
    assert root_b["Globals"]["nested"]["env"] == "prod"  # type: ignore[index]

    # Exact Variables 1MB boundary and exact MAX_PART_SIZE / MAX_TOTAL_BYTES boundaries
    exact_1mb_val = "x" * (1024 * 1024 - len('{"v": ""}'))
    mb_var = MessageBuilder().set_sender("a@b.com").add_recipient("c@d.com").set_content(text="ok")
    assert len(json.dumps({"v": exact_1mb_val})) == 1024 * 1024
    mb_var.set_variables({"v": exact_1mb_val}).build()
    mb_var.set_variables({"v": exact_1mb_val + "z"})
    with pytest.raises(ValueError, match="Variables payload too large"):
        mb_var.build()

    # Exact MAX_PART_SIZE boundary (patch GMAIL_CLIP_BYTES & MAX_PART_SIZE to keep test millisecond-fast)
    with patch.object(MessageBuilder, "GMAIL_CLIP_BYTES", 200), patch.object(MessageBuilder, "MAX_PART_SIZE", 64):
        mb_html = MessageBuilder().set_sender("a@b.com").add_recipient("c@d.com").set_content(html="h" * 64)
        mb_html.build()
        mb_html.set_content(html="h" * 65)
        with pytest.raises(ValueError, match="HTMLPart exceeds 5MB safe limit"):
            mb_html.build()

        mb_txt = MessageBuilder().set_sender("a@b.com").add_recipient("c@d.com").set_content(text="t" * 64)
        mb_txt.build()
        mb_txt.set_content(text="t" * 65)
        with pytest.raises(ValueError, match="TextPart exceeds 5MB safe limit"):
            mb_txt.build()

    # Exact _estimate_json_char_upper_bound > MAX_TOTAL_BYTES // 6 trigger
    assert _estimate_json_char_upper_bound({"k": ["v", 123]}) == (2 + 1 * 2) + (1 + 2) + (2 + 2) + (1 + 2) + 24
    with patch.object(SendPayloadBuilder, "MAX_TOTAL_BYTES", 240):
        tiny_msg = MessageBuilder().set_sender("a@b.com").add_recipient("c@d.com").set_content(text="x" * 20).build()
        spb_ok = SendPayloadBuilder().add_message(tiny_msg)
        assert len(json.dumps(spb_ok.build()).encode("utf-8")) <= 240
        big_msg = MessageBuilder().set_sender("a@b.com").add_recipient("c@d.com").set_content(text="x" * 220).build()
        with pytest.raises(ValueError, match="Batch payload exceeds 15MB limit"):
            SendPayloadBuilder().add_message(big_msg).build()
