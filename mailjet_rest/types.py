"""Type definitions and constants for the Mailjet SDK."""

from __future__ import annotations

import sys
from types import MappingProxyType
from typing import Any, Final, Literal, TypeAlias, TypedDict


if sys.version_info >= (3, 11):
    from typing import NotRequired
else:
    from typing_extensions import NotRequired


__all__ = [
    # Constants
    "_ALLOWED_TRACE_FIELDS",
    "_DEFAULT_TIMEOUT",
    "_JSON_HEADERS",
    "_TEXT_HEADERS",
    "Attachment",
    "EmailAddress",
    "HttpMethod",
    "PayloadType",
    "SendV31Message",
    "SendV31Payload",
    "TimeoutType",
]

# ==========================================
# Types & Constants
# ==========================================

TimeoutType: TypeAlias = int | float | tuple[float, float] | None
PayloadType: TypeAlias = dict[str, Any] | list[Any] | str | None
HttpMethod: TypeAlias = Literal["GET", "POST", "PUT", "DELETE"]

_DEFAULT_TIMEOUT: Final[int] = 60
_JSON_HEADERS: Final = MappingProxyType({"Content-Type": "application/json"})
_TEXT_HEADERS: Final = MappingProxyType({"Content-Type": "text/plain"})
_ALLOWED_TRACE_FIELDS: Final[set[str]] = {"CustomID", "TemplateID"}


class EmailAddress(TypedDict):
    """Schema for Mailjet email addresses."""

    Email: str
    Name: NotRequired[str]


class Attachment(TypedDict):
    """Represents a file attachment in a message."""

    ContentType: str
    Filename: str
    Base64Content: str


class SendV31Message(TypedDict):
    """Represents the complete structure of a single Mailjet v3.1 message."""

    From: EmailAddress
    To: list[EmailAddress]
    Cc: NotRequired[list[EmailAddress]]
    Bcc: NotRequired[list[EmailAddress]]
    ReplyTo: NotRequired[EmailAddress]
    Subject: str
    TextPart: NotRequired[str]
    HTMLPart: NotRequired[str]
    TemplateID: NotRequired[int]
    TemplateLanguage: NotRequired[bool]
    Variables: NotRequired[dict[str, Any]]
    CustomID: NotRequired[str]
    EventPayload: NotRequired[str]
    Headers: NotRequired[dict[str, str]]
    Attachments: NotRequired[list[Attachment]]
    # Tracking
    TrackOpens: NotRequired[Literal["enabled", "disabled"]]
    TrackClicks: NotRequired[Literal["enabled", "disabled"]]
    SandboxMode: NotRequired[bool]


class SendV31Payload(TypedDict):
    """Root payload schema for Send API v3.1."""

    Messages: list[SendV31Message]
    SandboxMode: NotRequired[bool]
    Globals: NotRequired[dict[str, Any]]
