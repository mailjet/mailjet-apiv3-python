"""Module for constructing complex Mailjet API payloads."""

from __future__ import annotations

import base64
import json
import mimetypes
import sys
import warnings
from typing import TYPE_CHECKING, Any, ClassVar


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from mailjet_rest.utils.guardrails import SecurityGuard


if TYPE_CHECKING:
    from pathlib import Path

    from mailjet_rest.types import SendV31Message, SendV31Payload


class ChunkedStreamer:
    """Generator for encoding large file attachments."""

    @staticmethod
    def encode_file(path: Path, chunk_size: int = 512 * 1024) -> str:
        """Read and encode a file in chunks without loading it entirely into RAM.

        Returns:
            str: The fully base64-encoded file representation.
        """
        # ENFORCE multiple of 3 to prevent Base64 padding corruption mid-stream
        chunk_size = max(3, (chunk_size // 3) * 3)
        encoded_chunks = []
        with path.open("rb") as f:
            while chunk := f.read(chunk_size):
                encoded_chunks.append(base64.b64encode(chunk).decode("utf-8"))
        return "".join(encoded_chunks)


class _BaseContentBuilder:
    """Internal base class providing shared content and header configurations."""

    __slots__ = ("_payload",)

    MAX_PART_SIZE: ClassVar[int] = 5 * 1024 * 1024  # 5MB cap

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
        self._payload["Headers"] = headers
        return self


class MessageBuilder(_BaseContentBuilder):
    """Fluent builder for individual Mailjet Send API v3.1 message objects."""

    __slots__ = ()

    def __init__(self) -> None:
        """Initialize an empty message payload."""
        super().__init__()

    def set_sender(self, email: str, name: str | None = None) -> Self:
        """Set a sender.

        Returns:
            Self: The builder instance for method chaining.
        """
        self._payload["From"] = {"Email": email}
        if name:
            self._payload["From"]["Name"] = name
        return self

    def add_recipient(self, email: str, name: str | None = None) -> Self:
        """Add a recipient.

        Returns:
            Self: The builder instance for method chaining.
        """
        if "To" not in self._payload:
            self._payload["To"] = []
        recipient = {"Email": SecurityGuard.normalize_domain(email)}
        if name:
            recipient["Name"] = name
        self._payload["To"].append(recipient)
        return self

    def add_cc(self, email: str, name: str | None = None) -> Self:
        """Add a CC recipient.

        Returns:
            Self: The builder instance for method chaining.
        """
        if "Cc" not in self._payload:
            self._payload["Cc"] = []
        recipient = {"Email": SecurityGuard.normalize_domain(email)}
        if name:
            recipient["Name"] = name
        self._payload["Cc"].append(recipient)
        return self

    def add_bcc(self, email: str, name: str | None = None) -> Self:
        """Add a BCC recipient.

        Returns:
            Self: The builder instance for method chaining.
        """
        if "Bcc" not in self._payload:
            self._payload["Bcc"] = []
        recipient = {"Email": SecurityGuard.normalize_domain(email)}
        if name:
            recipient["Name"] = name
        self._payload["Bcc"].append(recipient)
        return self

    def set_reply_to(self, email: str, name: str | None = None) -> Self:
        """Set the Reply-To address.

        Returns:
            Self: The builder instance for method chaining.
        """
        self._payload["ReplyTo"] = {"Email": SecurityGuard.normalize_domain(email)}
        if name:
            self._payload["ReplyTo"]["Name"] = name
        return self

    def set_subject(self, subject: str) -> Self:
        """Set the message subject.

        Returns:
            Self: The builder instance for method chaining.
        """
        self._payload["Subject"] = subject
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
        self._payload["Variables"] = variables
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

        ctype = content_type or mimetypes.guess_type(target)[0] or "application/octet-stream"

        if "Attachments" not in self._payload:
            self._payload["Attachments"] = []

        self._payload["Attachments"].append(
            {
                "ContentType": ctype,
                "Filename": target.name,
                "Base64Content": ChunkedStreamer.encode_file(target),
            }
        )
        return self

    def attach_inline(
        self, file_path: str | Path, content_type: str | None = None, base_dir: Path | str | None = None
    ) -> Self:
        """Safely attach an inline file from disk using memory-efficient chunking.

        Returns:
            Self: The builder instance for method chaining.
        """
        target = SecurityGuard.validate_attachment_path(file_path, base_dir)
        SecurityGuard.check_file_size(target)

        ctype = content_type or mimetypes.guess_type(target)[0] or "application/octet-stream"

        if "InlinedAttachments" not in self._payload:
            self._payload["InlinedAttachments"] = []

        self._payload["InlinedAttachments"].append(
            {
                "ContentType": ctype,
                "Filename": target.name,
                "Base64Content": ChunkedStreamer.encode_file(target),
            }
        )
        return self

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
        if (
            "HTMLPart" in self._payload
            and len(self._payload["HTMLPart"].encode("utf-8", errors="ignore")) > self.MAX_PART_SIZE
        ):
            msg = "Security Violation: HTMLPart exceeds 5MB safe limit."
            raise ValueError(msg)

        if (
            "TextPart" in self._payload
            and len(self._payload["TextPart"].encode("utf-8", errors="ignore")) > self.MAX_PART_SIZE
        ):
            msg = "Security Violation: TextPart exceeds 5MB safe limit."
            raise ValueError(msg)

        return self._payload.copy()  # type: ignore[return-value]


class SendPayloadBuilder:
    """Fluent builder for the root Send API v3.1 payload wrapper.

    This builder encapsulates the Messages array and root-level configurations
    such as SandboxMode and Globals.
    """

    __slots__ = ("_globals", "_messages", "_sandbox")

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
        if isinstance(message, MessageBuilder):
            self._messages.append(message.build())
        else:
            self._messages.append(message)
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
        self._globals = globals_dict
        return self

    def build(self) -> SendV31Payload:
        """Validate and construct the final root JSON payload for the Send API v3.1.

        Returns:
            SendV31Payload: The validated root payload.

        Raises:
            ValueError: If no messages are included.
        """
        if not self._messages:
            msg = "Payload validation failed: At least one message is required."
            raise ValueError(msg)

        payload: dict[str, Any] = {"Messages": self._messages}

        if self._sandbox:
            payload["SandboxMode"] = True

        if self._globals is not None:
            payload["Globals"] = self._globals

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
            self._payload["Author"] = author
        if name:
            self._payload["Name"] = name
        if locale:
            self._payload["Locale"] = locale
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

        # Return a copy to preserve builder state immutability
        return self._payload.copy()
