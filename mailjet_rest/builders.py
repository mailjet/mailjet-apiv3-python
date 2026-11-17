"""Module for constructing complex Mailjet API payloads."""

from __future__ import annotations

import base64
import copy
import errno
import json
import os
import re
import stat
import sys
import warnings
from typing import TYPE_CHECKING, Any, ClassVar, Final
from urllib.parse import urlsplit


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from mailjet_rest.utils.guardrails import SecurityGuard


if TYPE_CHECKING:
    from pathlib import Path

    from mailjet_rest.types import SendV31Message, SendV31Payload, TrackingMode


_CRLF_CONTROL_RE: Final = re.compile(r"[\r\n\x00]")
_SAFE_CID_RE: Final = re.compile(r"^[A-Za-z0-9._@-]{1,255}$")
_CID_REF_RE: Final = re.compile(r"""cid:([^\s"'<>]+)""", re.IGNORECASE)
_TRACKING_MODES: Final[frozenset[str]] = frozenset({"enabled", "disabled"})


def _assert_no_crlf(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        msg = f"Invalid type for {field_name}: expected str, got {type(value).__name__}"
        raise TypeError(msg)
    if _CRLF_CONTROL_RE.search(value):
        msg = f"Security Violation (CWE-93): {field_name} contains forbidden control characters."
        raise ValueError(msg)
    return value


def _validate_email_input(email: str, field_name: str) -> str:
    clean = _assert_no_crlf(email, field_name).strip()
    if "@" not in clean or " " in clean or clean.startswith("@") or clean.endswith("@"):
        msg = f"Invalid email address for {field_name}: {email!r}"
        raise ValueError(msg)
    return SecurityGuard.normalize_domain(clean)


def _sanitize_cid(raw_cid: str) -> str:
    stripped = _assert_no_crlf(raw_cid, "content_id").strip()
    if stripped.startswith("<") and stripped.endswith(">"):
        stripped = stripped[1:-1].strip()
    if not _SAFE_CID_RE.fullmatch(stripped):
        msg = f"Invalid Content-ID value: {raw_cid!r}"
        raise ValueError(msg)
    return stripped


class ChunkedStreamer:
    """Generator for encoding large file attachments."""

    __slots__ = ()

    @staticmethod
    def encode_file(
        path: str | Path,
        chunk_size: int = 512 * 1024,
        *,
        safe_base_dir: str | Path | None = None,
        max_bytes: int = 15 * 1024 * 1024,
    ) -> str:
        """Read and encode a file in chunks without loading it entirely into RAM.

        Validates the path, rejects symlinks cleanly via O_NOFOLLOW when available,
        pins the open file descriptor with fstat, and enforces size limits.

        Returns:
            str: The fully base64-encoded file representation.
        """
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
            msg = "chunk_size must be a strictly positive integer."
            raise ValueError(msg)
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
            msg = "max_bytes must be a strictly positive integer."
            raise ValueError(msg)

        validated = SecurityGuard.validate_attachment_path(path, safe_base_dir=safe_base_dir)
        step = max(3, (chunk_size // 3) * 3)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)

        try:
            fd = os.open(os.fspath(validated), flags)
        except OSError as e:
            if e.errno == errno.ELOOP:
                msg = "Security Violation (CWE-22): Symlinks are strictly forbidden for attachments."
                raise ValueError(msg) from e
            raise

        fd_owned = True
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                msg = f"Security Alert (CWE-400): Path is not a regular file: {validated}"
                raise ValueError(msg)
            if st.st_size > max_bytes:
                msg = f"Security Violation: File '{validated.name}' exceeds safe threshold."
                raise ValueError(msg)

            encoded_chunks: list[str] = []
            total_read = 0
            with os.fdopen(fd, "rb") as f:
                fd_owned = False
                while chunk := f.read(step):
                    total_read += len(chunk)
                    if total_read > max_bytes:
                        msg = f"Security Violation: File '{validated.name}' exceeds safe threshold."
                        raise ValueError(msg)
                    encoded_chunks.append(base64.b64encode(chunk).decode("ascii"))
            return "".join(encoded_chunks)
        finally:
            if fd_owned:
                os.close(fd)


class _BaseContentBuilder:
    """Internal base class providing shared content and header configurations."""

    __slots__ = ("_payload",)

    MAX_PART_SIZE: ClassVar[int] = 5 * 1024 * 1024  # 5MB cap
    GMAIL_CLIP_BYTES: ClassVar[int] = 102 * 1024  # Gmail clips HTML bodies > 102 KB

    # Default to False for high-throughput batching.
    ENABLE_SPAM_GUARD: ClassVar[bool] = False

    def __init__(self) -> None:
        """Initialize the base builder instance and an empty payload."""
        self._payload: dict[str, Any] = {}

    def set_headers(self, headers: dict[str, str]) -> Self:
        """Sets the Headers JSON object structure crossing the ingress gate.

        Args:
            headers (dict[str, str]): Custom key-value structural protocol attributes.

        Returns:
            Self: The builder instance for method chaining.
        """
        sanitized = SecurityGuard.sanitize_headers(headers)
        clean_headers: dict[str, str] = {}
        for key, value in sanitized.items():
            clean_key = _assert_no_crlf(key, "header name")
            if value is None:
                msg = f"Header '{clean_key}' value must be str, got None"
                raise TypeError(msg)
            clean_headers[clean_key] = _assert_no_crlf(value, f"header '{clean_key}'")
        self._payload["Headers"] = clean_headers
        return self


class MessageBuilder(_BaseContentBuilder):
    """Fluent builder for individual Mailjet Send API v3.1 message objects."""

    __slots__ = ()

    def __init__(self) -> None:
        """Initialize an empty message payload."""
        super().__init__()

    @staticmethod
    def _build_recipient(email: str, name: str | None, field_name: str) -> dict[str, str]:
        entry = {"Email": _validate_email_input(email, field_name)}
        if name:
            entry["Name"] = _assert_no_crlf(name, f"{field_name} name")
        return entry

    def set_sender(self, email: str, name: str | None = None) -> Self:
        """Set a sender.

        Returns:
            Self: The builder instance for method chaining.
        """
        self._payload["From"] = self._build_recipient(email, name, "sender")
        return self

    def add_recipient(self, email: str, name: str | None = None) -> Self:
        """Add a recipient.

        Returns:
            Self: The builder instance for method chaining.
        """
        if "To" not in self._payload:
            self._payload["To"] = []
        self._payload["To"].append(self._build_recipient(email, name, "recipient"))
        return self

    def add_cc(self, email: str, name: str | None = None) -> Self:
        """Add a CC recipient.

        Returns:
            Self: The builder instance for method chaining.
        """
        if "Cc" not in self._payload:
            self._payload["Cc"] = []
        self._payload["Cc"].append(self._build_recipient(email, name, "cc"))
        return self

    def add_bcc(self, email: str, name: str | None = None) -> Self:
        """Add a BCC recipient.

        Returns:
            Self: The builder instance for method chaining.
        """
        if "Bcc" not in self._payload:
            self._payload["Bcc"] = []
        self._payload["Bcc"].append(self._build_recipient(email, name, "bcc"))
        return self

    def set_reply_to(self, email: str, name: str | None = None) -> Self:
        """Set the Reply-To address.

        Returns:
            Self: The builder instance for method chaining.
        """
        self._payload["ReplyTo"] = self._build_recipient(email, name, "reply_to")
        return self

    def set_subject(self, subject: str) -> Self:
        """Set the message subject.

        Returns:
            Self: The builder instance for method chaining.
        """
        self._payload["Subject"] = _assert_no_crlf(subject, "subject")
        return self

    def set_custom_id(self, custom_id: str) -> Self:
        """Set the Mailjet CustomID tracking identifier safely without CRLF injection.

        Returns:
            Self: The builder instance for method chaining.
        """
        self._payload["CustomID"] = _assert_no_crlf(custom_id, "CustomID")
        return self

    def set_event_payload(self, event_payload: str) -> Self:
        """Set the Mailjet EventPayload webhook correlation string.

        Returns:
            Self: The builder instance for method chaining.
        """
        self._payload["EventPayload"] = _assert_no_crlf(event_payload, "EventPayload")
        return self

    def set_tracking(
        self,
        *,
        opens: TrackingMode | None = None,
        clicks: TrackingMode | None = None,
    ) -> Self:
        """Configure per-message open and click tracking overrides.

        Returns:
            Self: The builder instance for method chaining.
        """
        if opens is not None:
            if opens not in _TRACKING_MODES:
                msg = f"Invalid TrackOpens mode {opens!r}; expected 'enabled' or 'disabled'."
                raise ValueError(msg)
            self._payload["TrackOpens"] = opens
        if clicks is not None:
            if clicks not in _TRACKING_MODES:
                msg = f"Invalid TrackClicks mode {clicks!r}; expected 'enabled' or 'disabled'."
                raise ValueError(msg)
            self._payload["TrackClicks"] = clicks
        return self

    def set_list_unsubscribe(
        self,
        unsubscribe_url: str,
        mailto_address: str | None = None,
        *,
        one_click: bool = True,
    ) -> Self:
        """Attach RFC 8058 List-Unsubscribe and optional List-Unsubscribe-Post headers.

        Returns:
            Self: The builder instance for method chaining.
        """
        clean_url = _assert_no_crlf(unsubscribe_url, "unsubscribe_url").strip()
        if "<" in clean_url or ">" in clean_url:
            msg = "Invalid RFC 8058 unsubscribe URL: angle brackets are forbidden."
            raise ValueError(msg)
        parsed = urlsplit(clean_url)
        if parsed.scheme.lower() != "https" or not parsed.netloc:
            msg = "RFC 8058 unsubscribe URL must use https:// with a valid host."
            raise ValueError(msg)

        parts = [f"<{clean_url}>"]
        if mailto_address is not None:
            clean_mailto = _validate_email_input(mailto_address, "mailto_address")
            parts.append(f"<mailto:{clean_mailto}>")

        existing = dict(self._payload.get("Headers", {}))
        existing["List-Unsubscribe"] = ", ".join(parts)
        if one_click:
            existing["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
        self._payload["Headers"] = existing
        return self

    def set_content(self, text: str | None = None, html: str | None = None) -> Self:
        """Sets the content blocks for the message. Uses Send API v3.1 specific casing (TextPart/HTMLPart).

        Does not support direct MJML input; use set_template() instead.

        Args:
            text (str | None): Plain text part component.
            html (str | None): Rendered raw HTML layout sequence.

        Returns:
            Self: The builder instance for method chaining.
        """
        if text:
            self._payload["TextPart"] = text

        if html:
            if self.ENABLE_SPAM_GUARD:
                analysis = SecurityGuard.analyze_html_safety(html)
                if not analysis["is_safe"]:
                    warnings.warn(f"Deliverability Warning: {analysis['issues']}", UserWarning, stacklevel=2)
            self._payload["HTMLPart"] = html

        return self

    def set_template(self, template_id: int, language_active: bool = True) -> Self:
        """Use a Mailjet template ID.

        Returns:
            Self: The builder instance for method chaining.
        """
        self._payload["TemplateID"] = template_id
        self._payload["TemplateLanguage"] = language_active
        return self

    def set_variables(self, variables: dict[str, Any]) -> Self:
        """Set dynamic template variables.

        Returns:
            Self: The builder instance for method chaining.
        """
        self._payload["Variables"] = copy.deepcopy(variables)
        return self

    def attach_file(
        self, file_path: str | Path, content_type: str | None = None, base_dir: Path | str | None = None
    ) -> Self:
        """Safely attach a file from disk using memory-efficient chunking.

        Returns:
            Self: The builder instance for method chaining.
        """
        target = SecurityGuard.validate_attachment_path(file_path, base_dir)
        SecurityGuard.check_file_size(target)

        if content_type is not None:
            ctype = content_type
        else:
            import mimetypes  # ruff: ignore[import-outside-top-level]

            ctype = mimetypes.guess_type(target)[0] or "application/octet-stream"

        if "Attachments" not in self._payload:
            self._payload["Attachments"] = []

        self._payload["Attachments"].append(
            {
                "ContentType": ctype,
                "Filename": target.name,
                "Base64Content": ChunkedStreamer.encode_file(target, safe_base_dir=base_dir),
            }
        )
        return self

    def attach_inline(
        self,
        file_path: str | Path,
        content_type: str | None = None,
        base_dir: Path | str | None = None,
        content_id: str | None = None,
    ) -> Self:
        """Safely attach an inline file from disk using memory-efficient chunking.

        Returns:
            Self: The builder instance for method chaining.
        """
        target = SecurityGuard.validate_attachment_path(file_path, base_dir)
        SecurityGuard.check_file_size(target)
        clean_cid = _sanitize_cid(content_id if content_id is not None else target.name)

        if content_type is not None:
            ctype = content_type
        else:
            import mimetypes  # ruff: ignore[import-outside-top-level]

            ctype = mimetypes.guess_type(target)[0] or "application/octet-stream"

        if "InlinedAttachments" not in self._payload:
            self._payload["InlinedAttachments"] = []

        self._payload["InlinedAttachments"].append(
            {
                "ContentType": ctype,
                "Filename": target.name,
                "ContentID": clean_cid,
                "Base64Content": ChunkedStreamer.encode_file(target, safe_base_dir=base_dir),
            }
        )
        return self

    def _warn_html_deliverability(self, html_part: str, html_bytes_len: int) -> None:
        if html_bytes_len > self.GMAIL_CLIP_BYTES:
            warnings.warn(
                "Deliverability Warning: HTMLPart exceeds Gmail 102 KB clip threshold.",
                UserWarning,
                stacklevel=3,
            )

        cid_refs = set(_CID_REF_RE.findall(html_part))
        if cid_refs:
            attached_cids = {
                str(item["ContentID"])
                for item in self._payload.get("InlinedAttachments", ())
                if isinstance(item, dict) and item.get("ContentID") is not None
            }
            missing = sorted(cid_refs - attached_cids)
            if missing:
                warnings.warn(
                    f"Inline CID references missing matching InlinedAttachments ContentID: {missing}",
                    UserWarning,
                    stacklevel=3,
                )

    def build(self) -> SendV31Message:
        """Validate and return the message payload.

        Returns:
            SendV31Message: The validated dictionary matching the Mailjet Send V3.1 JSON schema.

        Raises:
            ValueError: If structural validation (like missing Sender) fails.
        """
        if "From" not in self._payload:
            msg = "Message validation failed: Sender (From) is required."
            raise ValueError(msg)

        if not self._payload.get("To") and not self._payload.get("Cc") and not self._payload.get("Bcc"):
            msg = "Message validation failed: At least one recipient (To, Cc, or Bcc) is required."
            raise ValueError(msg)

        if not any(k in self._payload for k in ("TextPart", "HTMLPart", "TemplateID")):
            msg = "Message validation failed: TextPart, HTMLPart, or TemplateID is required."
            raise ValueError(msg)

        # OOM Guards
        # Use default=str to prevent crash if variables contain non-serializable objects (like datetime or UUID)
        if "Variables" in self._payload and len(json.dumps(self._payload["Variables"], default=str)) > 1024 * 1024:
            msg = "Security Violation: Variables payload too large (exceeds 1MB)."
            raise ValueError(msg)

        # Apply strict payload size limits to major content vectors
        html_part = self._payload.get("HTMLPart")
        html_bytes_len = len(html_part.encode("utf-8", errors="ignore")) if isinstance(html_part, str) else 0
        if html_bytes_len > self.MAX_PART_SIZE:
            msg = "Security Violation: HTMLPart exceeds 5MB safe limit."
            raise ValueError(msg)

        text_part = self._payload.get("TextPart")
        if isinstance(text_part, str) and len(text_part.encode("utf-8", errors="ignore")) > self.MAX_PART_SIZE:
            msg = "Security Violation: TextPart exceeds 5MB safe limit."
            raise ValueError(msg)

        if isinstance(html_part, str):
            self._warn_html_deliverability(html_part, html_bytes_len)

        return copy.deepcopy(self._payload)  # type: ignore[return-value]


class SendPayloadBuilder:
    """Fluent builder for the root Send API v3.1 payload wrapper.

    This builder encapsulates the Messages array and root-level configurations
    such as SandboxMode and Globals.
    """

    __slots__ = ("_globals", "_messages", "_sandbox")

    MAX_MESSAGES: ClassVar[int] = 50
    MAX_TOTAL_BYTES: ClassVar[int] = 15 * 1024 * 1024

    def __init__(self) -> None:
        """Initialize an empty Send API payload structure."""
        self._messages: list[SendV31Message] = []
        self._sandbox: bool = False
        self._globals: dict[str, Any] | None = None

    def add_message(self, message: SendV31Message | MessageBuilder) -> Self:
        """Append a message to the payload's Messages array.

        Args:
            message: A built SendV31Message dictionary or an active MessageBuilder instance.

        Returns:
            Self: The builder instance for method chaining.
        """
        if len(self._messages) >= self.MAX_MESSAGES:
            msg = f"Payload validation failed: Send v3.1 allows at most {self.MAX_MESSAGES} messages per request."
            raise ValueError(msg)

        if isinstance(message, MessageBuilder):
            self._messages.append(message.build())
        else:
            self._messages.append(copy.deepcopy(message))
        return self

    def set_sandbox_mode(self, active: bool) -> Self:
        """Enable API Sandbox mode at the root level (no real dispatch).

        Returns:
            Self: The builder instance for method chaining.
        """
        self._sandbox = active
        return self

    def set_globals(self, globals_dict: dict[str, Any]) -> Self:
        """Set global properties to be applied across all messages in the payload.

        Returns:
            Self: The builder instance for method chaining.
        """
        self._globals = copy.deepcopy(globals_dict)
        return self

    def build(self) -> SendV31Payload:
        """Validate and construct the final root JSON payload for the Send API v3.1.

        Returns:
            SendV31Payload: The validated root payload.

        Raises:
            ValueError: If no messages are included or batch limits are exceeded.
        """
        if not self._messages:
            msg = "Payload validation failed: At least one message is required."
            raise ValueError(msg)

        if len(self._messages) > self.MAX_MESSAGES:
            msg = f"Payload validation failed: Send v3.1 allows at most {self.MAX_MESSAGES} messages per request."
            raise ValueError(msg)

        payload: dict[str, Any] = {"Messages": copy.deepcopy(self._messages)}

        if self._sandbox:
            payload["SandboxMode"] = True

        if self._globals is not None:
            payload["Globals"] = copy.deepcopy(self._globals)

        if len(json.dumps(payload, default=str).encode("utf-8")) > self.MAX_TOTAL_BYTES:
            msg = "Payload validation failed: Batch payload exceeds 15MB limit."
            raise ValueError(msg)

        return payload  # type: ignore[return-value]


class TemplateContentBuilder(_BaseContentBuilder):
    """Fluent builder for the Template, Newsletter, and Campaign Draft Content APIs.

    These endpoints share a legacy v3 payload schema structure.
    """

    __slots__ = ()

    def set_meta(self, author: str | None = None, name: str | None = None, locale: str | None = None) -> Self:
        """Sets metadata for the template.

        Args:
            author (str | None): Optional author identifier name.
            name (str | None): Optional unique template layout identifier name.
            locale (str | None): Language and country locale definition.

        Returns:
            Self: The builder instance for method chaining.
        """
        if author:
            self._payload["Author"] = _assert_no_crlf(author, "author")
        if name:
            self._payload["Name"] = _assert_no_crlf(name, "name")
        if locale:
            self._payload["Locale"] = _assert_no_crlf(locale, "locale")
        return self

    def set_content(self, text: str | None = None, html: str | None = None, mjml: str | None = None) -> Self:
        """Sets the content blocks for the template using Kebab-case formatting (Text-part/Html-part).

        Args:
            text (str | None): Plain text part component.
            html (str | None): Rendered raw HTML layout sequence.
            mjml (str | None): Semantic responsive MJML markup representation.

        Returns:
            Self: The builder instance for method chaining.
        """
        if text:
            self._payload["Text-part"] = text

        if html:
            if self.ENABLE_SPAM_GUARD:
                analysis = SecurityGuard.analyze_html_safety(html)
                if not analysis["is_safe"]:
                    warnings.warn(f"Deliverability Warning: {analysis['issues']}", UserWarning, stacklevel=2)
            self._payload["Html-part"] = html

        if mjml:
            self._payload["MJMLContent"] = mjml

        return self

    def build(self) -> dict[str, Any]:
        """Validate and return the completed templates engine schema dictionary.

        Returns:
            dict[str, Any]: Fully validated parsed dynamic payload mapping.
        """
        if not any(k in self._payload for k in ("Text-part", "Html-part", "MJMLContent")):
            warnings.warn(
                "Template validation: At least one of text, html, or mjml content is required. "
                "This will escalate to a fatal ValueError in SDK v2.0.0.",
                PendingDeprecationWarning,
                stacklevel=2,
            )

        # Return a deep copy to preserve builder state immutability across nested fields
        return copy.deepcopy(self._payload)
