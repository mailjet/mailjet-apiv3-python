"""Module for constructing complex Mailjet API payloads."""

from __future__ import annotations

import base64
import json
import mimetypes
import sys
from typing import TYPE_CHECKING, Any


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from mailjet_rest.utils.guardrails import SecurityGuard


if TYPE_CHECKING:
    from pathlib import Path

    from mailjet_rest.types import SendV31Message


class MessageBuilder:
    """Fluent builder for Mailjet Send API v3.1 payloads."""

    __slots__ = ("_msg",)

    def __init__(self) -> None:
        """Initialize an empty message payload."""
        self._msg: dict[str, Any] = {}

    def set_sender(self, email: str, name: str | None = None) -> Self:
        """Set a sender.

        Returns:
            The builder instance for method chaining.
        """
        self._msg["From"] = {"Email": email}
        if name:
            self._msg["From"]["Name"] = name
        return self

    def add_recipient(self, email: str, name: str | None = None) -> Self:
        """Add a recipient.

        Returns:
            The builder instance for method chaining.
        """
        if "To" not in self._msg:
            self._msg["To"] = []
        recipient = {"Email": email}
        if name:
            recipient["Name"] = name
        self._msg["To"].append(recipient)
        return self

    def add_cc(self, email: str, name: str | None = None) -> Self:
        """Add a Carbon Copy (Cc) recipient.

        Returns:
            The builder instance for method chaining.
        """
        if "Cc" not in self._msg:
            self._msg["Cc"] = []
        recipient = {"Email": email}
        if name:
            recipient["Name"] = name
        self._msg["Cc"].append(recipient)
        return self

    def add_bcc(self, email: str, name: str | None = None) -> Self:
        """Add a Blind Carbon Copy (Bcc) recipient.

        Returns:
            The builder instance for method chaining.
        """
        if "Bcc" not in self._msg:
            self._msg["Bcc"] = []
        recipient = {"Email": email}
        if name:
            recipient["Name"] = name
        self._msg["Bcc"].append(recipient)
        return self

    def set_reply_to(self, email: str, name: str | None = None) -> Self:
        """Set the Reply-To address.

        Returns:
            The builder instance for method chaining.
        """
        self._msg["ReplyTo"] = {"Email": email}
        if name:
            self._msg["ReplyTo"]["Name"] = name
        return self

    def set_subject(self, subject: str) -> Self:
        """Set the email subject line.

        Returns:
            The builder instance for method chaining.
        """
        self._msg["Subject"] = subject
        return self

    def set_content(self, text: str | None = None, html: str | None = None) -> Self:
        """Set TextPart or HTMLPart content.

        Returns:
            The builder instance for method chaining.
        """
        if text is not None:
            self._msg["TextPart"] = text
        if html is not None:
            self._msg["HTMLPart"] = html
        return self

    def set_headers(self, headers: dict[str, str]) -> Self:
        """Set custom headers (e.g., Reply-To, X-Custom).

        Args:
            headers (dict[str, str]): Custom key-value string pairs.

        Returns:
            Self: The builder instance for method chaining.
        """
        self._msg["Headers"] = headers
        return self

    def set_template(self, template_id: int, enable_language: bool = True) -> Self:
        """Use a pre-defined Mailjet Template.

        Returns:
            The builder instance for method chaining.
        """
        self._msg["TemplateID"] = template_id
        self._msg["TemplateLanguage"] = enable_language
        return self

    def set_variables(self, variables: dict[str, Any]) -> Self:
        """Inject template variables.

        Returns:
            The builder instance for method chaining.
        """
        self._msg["Variables"] = variables
        return self

    def attach_file(self, file_path: str | Path, safe_base_dir: str | Path | None = None) -> Self:
        """Safely read, encode, and attach a local file.

        Args:
            file_path: The target file to attach.
            safe_base_dir: Jails the path resolution to prevent CWE-22 Path Traversal.

        Returns:
            The builder instance for method chaining.
        """
        # 1. Security Check: Path Traversal & Existence
        path = SecurityGuard.validate_attachment_path(file_path, safe_base_dir)

        # 2. Security Check: Resource Exhaustion (OOM Prevention)
        SecurityGuard.check_file_size(path)

        mime_type, _ = mimetypes.guess_type(path)
        b64_content = base64.b64encode(path.read_bytes()).decode("utf-8")

        if "Attachments" not in self._msg:
            self._msg["Attachments"] = []

        self._msg["Attachments"].append(
            {
                "ContentType": mime_type or "application/octet-stream",
                "Filename": path.name,
                "Base64Content": b64_content,
            }
        )
        return self

    def build(self) -> SendV31Message:
        """Validate and return the message payload.

        Returns:
            SendV31Message message payload.
        """
        if "From" not in self._msg:
            msg = "Message validation failed: Sender (From) is required."
            raise ValueError(msg)
        if not self._msg.get("To"):
            msg = "Message validation failed: At least one recipient (To) is required."
            raise ValueError(msg)
        if "TextPart" not in self._msg and "HTMLPart" not in self._msg and "TemplateID" not in self._msg:
            msg = "Message validation failed: TextPart, HTMLPart, or TemplateID is required."
            raise ValueError(msg)
        if "Variables" in self._msg and len(json.dumps(self._msg["Variables"])) > 1024 * 1024:
            msg = "Security Violation: Variables payload too large."
            raise ValueError(msg)

        return self._msg  # type: ignore[return-value]


class TemplateContentBuilder:
    """Builder for /template/{id}/contents API payloads."""

    __slots__ = ("_data",)

    def __init__(self) -> None:
        """Initialize an empty template contents data payload descriptor."""
        self._data: dict[str, Any] = {}

    def set_meta(self, author: str | None = None, name: str | None = None, locale: str = "en_US") -> Self:
        """Set core template identity and structural configuration attributes.

        Args:
            author (str | None): Optional author identifier name.
            name (str | None): Optional unique template layout identifier name.
            locale (str): Language and country locale definition (default: "en_US").

        Returns:
            Self: The builder instance for method chaining.
        """
        if author:
            self._data["Author"] = author
        if name:
            self._data["Name"] = name
        self._data["Locale"] = locale
        return self

    def set_content(self, text: str | None = None, html: str | None = None, mjml: str | None = None) -> Self:
        """Set content keys as per API documentation.

        Args:
            text (str | None): Plain text part component.
            html (str | None): Rendered raw HTML layout sequence.
            mjml (str | None): Semantic responsive MJML markup representation.

        Returns:
            Self: The builder instance for method chaining.
        """
        if text:
            self._data["TextPart"] = text
        if html:
            self._data["HTMLPart"] = html
        if mjml:
            self._data["MJMLContent"] = mjml
        return self

    def set_headers(self, headers: dict[str, str]) -> Self:
        """Sets the Headers JSON object structure crossing the ingress gate.

        Args:
            headers (dict[str, str]): Custom key-value structural protocol attributes.

        Returns:
            Self: The builder instance for method chaining.
        """
        self._data["Headers"] = headers
        return self

    def build(self) -> dict[str, Any]:
        """Validate and return the completed templates engine schema dictionary.

        Returns:
            dict[str, Any]: Fully validated parsed dynamic payload payload mapping.

        Raises:
            ValueError: If no valid text, html or mjml boundary tokens are passed.
        """
        if not any(k in self._data for k in ("TextPart", "HTMLPart", "MJMLContent")):
            msg = "Template validation failed: At least one of text, html, or mjml content is required."
            raise ValueError(msg)

        return self._data
