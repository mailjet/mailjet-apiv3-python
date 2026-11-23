"""Type definitions and constants for the Mailjet SDK."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Final, Literal, TypeAlias, TypedDict


if sys.version_info >= (3, 11):
    from typing import NotRequired
else:
    from typing_extensions import NotRequired


__all__ = [
    "_ALLOWED_TRACE_FIELDS",
    "_CSV_HEADERS",
    "_DEFAULT_TIMEOUT",
    "_JSON_HEADERS",
    "_TEXT_HEADERS",
    "ApiListResponse",
    "ApiVersion",
    "Attachment",
    "AuthCredentials",
    "AutoIdempotencyMode",
    "CertConfig",
    "ContactListAction",
    "ContactListSubscription",
    "ContactPayload",
    "ContactRecord",
    "EmailAddress",
    "EventCallbackUrlPayload",
    "HeadersMapping",
    "HttpMethod",
    "ManageManyContactsItem",
    "ManageManyContactsPayload",
    "PayloadType",
    "ProxyConfig",
    "QueryFilters",
    "RequestHeaders",
    "ResourceId",
    "SendV31ErrorItem",
    "SendV31Message",
    "SendV31MessageResult",
    "SendV31Payload",
    "SendV31RecipientResult",
    "SendV31Response",
    "TemplateContentPayload",
    "TemplateContentType",
    "TimeoutType",
    "TrackingMode",
    "V1TemplatePayload",
    "VerifyConfig",
    "WebhookEventType",
    "WebhookStatus",
]

# ==========================================
# Consolidated SDK Types & Constants
# ==========================================

ApiVersion: TypeAlias = Literal["v1", "v3", "v3.1", "v4"] | str  # ruff: ignore[redundant-literal-union]
TimeoutType: TypeAlias = int | float | tuple[int | float, int | float] | None
HttpMethod: TypeAlias = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
AutoIdempotencyMode: TypeAlias = Literal["fingerprint", "uuid4", "off"]
TrackingMode: TypeAlias = Literal["enabled", "disabled"]
TemplateContentType: TypeAlias = Literal["D", "P", "A"] | str  # ruff: ignore[redundant-literal-union]
ContactListAction: TypeAlias = Literal["addforce", "addnoforce", "remove", "unsub"]
WebhookEventType: TypeAlias = Literal["sent", "open", "click", "bounce", "spam", "blocked", "unsub"]
WebhookStatus: TypeAlias = Literal["alive", "dead"]

AuthCredentials: TypeAlias = str | tuple[str, str] | None
VerifyConfig: TypeAlias = bool | str | os.PathLike[str]
CertConfig: TypeAlias = str | os.PathLike[str] | tuple[str | os.PathLike[str], str | os.PathLike[str]] | None
ProxyConfig: TypeAlias = str | Mapping[str, str] | None
ResourceId: TypeAlias = int | str
HeadersMapping: TypeAlias = Mapping[str, str | None]
RequestHeaders: TypeAlias = dict[str, str | None]
QueryFilters: TypeAlias = Mapping[str, Any]

_DEFAULT_TIMEOUT: Final[int] = 60
_CSV_HEADERS: Final = MappingProxyType({"Content-Type": "text/csv"})
_JSON_HEADERS: Final = MappingProxyType({"Content-Type": "application/json"})
_TEXT_HEADERS: Final = MappingProxyType({"Content-Type": "text/plain"})
_ALLOWED_TRACE_FIELDS: Final[frozenset[str]] = frozenset({"CustomID", "TemplateID"})


# ==========================================
# OpenAPI Request & Response DTOs
# ==========================================


class EmailAddress(TypedDict):
    """Schema for Mailjet email addresses."""

    Email: str
    Name: NotRequired[str]


class Attachment(TypedDict):
    """Represents a file attachment in a message."""

    ContentType: str
    Filename: str
    Base64Content: str
    ContentID: NotRequired[str]


class SendV31Message(TypedDict):
    """Represents the complete structure of a single Mailjet v3.1 message."""

    From: EmailAddress
    Sender: NotRequired[EmailAddress]
    To: list[EmailAddress]
    Cc: NotRequired[list[EmailAddress]]
    Bcc: NotRequired[list[EmailAddress]]
    ReplyTo: NotRequired[EmailAddress]
    Subject: str
    TextPart: NotRequired[str]
    HTMLPart: NotRequired[str]
    TemplateID: NotRequired[int]
    TemplateLanguage: NotRequired[bool]
    TemplateErrorReporting: NotRequired[EmailAddress]
    TemplateErrorDeliver: NotRequired[bool]
    Variables: NotRequired[dict[str, Any]]
    Priority: NotRequired[int]
    CustomCampaign: NotRequired[str]
    DeduplicateCampaign: NotRequired[bool]
    CustomID: NotRequired[str]
    EventPayload: NotRequired[str]
    URLTags: NotRequired[str]
    Headers: NotRequired[dict[str, str]]
    Attachments: NotRequired[list[Attachment]]
    InlinedAttachments: NotRequired[list[Attachment]]
    # Tracking
    TrackOpens: NotRequired[TrackingMode]
    TrackClicks: NotRequired[TrackingMode]


class SendV31Payload(TypedDict):
    """Represents the top-level payload for the Mailjet v3.1 API."""

    Messages: list[SendV31Message]
    SandboxMode: NotRequired[bool]
    AdvanceErrorHandling: NotRequired[bool]
    Globals: NotRequired[dict[str, Any]]


class SendV31RecipientResult(TypedDict):
    """Recipient delivery status entry returned by Send API v3.1."""

    Email: str
    MessageUUID: str
    MessageID: int
    MessageHref: str


class SendV31ErrorItem(TypedDict):
    """Error detail entry returned within a Send API v3.1 message response."""

    ErrorIdentifier: str
    ErrorCode: str
    StatusCode: int
    ErrorMessage: str
    ErrorRelatedTo: list[str]


class SendV31MessageResult(TypedDict):
    """Per-message response status object from Send API v3.1."""

    Status: str
    CustomID: NotRequired[str]
    Errors: NotRequired[list[SendV31ErrorItem]]
    To: NotRequired[list[SendV31RecipientResult]]
    Cc: NotRequired[list[SendV31RecipientResult]]
    Bcc: NotRequired[list[SendV31RecipientResult]]


class SendV31Response(TypedDict):
    """Top-level response envelope returned by Send API v3.1."""

    Messages: list[SendV31MessageResult]


class ApiListResponse(TypedDict):
    """Standard Mailjet v3 REST/v1 collection response envelope."""

    Count: int
    Total: int
    Data: list[dict[str, Any]]


class ContactPayload(TypedDict):
    """Request payload for creating or updating a Mailjet contact (/v3/REST/contact)."""

    Email: str
    Name: NotRequired[str]
    IsExcludedFromCampaigns: NotRequired[bool]


class ContactRecord(TypedDict):
    """Contact record representation returned by /v3/REST/contact."""

    ID: int
    Email: str
    CreatedAt: str
    DeliveredCount: NotRequired[int]
    ExclusionFromCampaignsUpdatedAt: NotRequired[str]
    IsExcludedFromCampaigns: NotRequired[bool]
    IsOptInPending: NotRequired[bool]
    IsSpamComplaining: NotRequired[bool]
    LastActivityAt: NotRequired[str]
    LastUpdateAt: NotRequired[str]
    Name: NotRequired[str]
    UnsubscribedAt: NotRequired[str]
    UnsubscribedBy: NotRequired[str]


class ContactListSubscription(TypedDict):
    """Contact list membership action entry for bulk contact management."""

    ListID: int
    Action: ContactListAction


class ManageManyContactsItem(TypedDict):
    """Contact entry for /v3/REST/contact/managemanycontacts requests."""

    Email: str
    Name: NotRequired[str]
    IsExcludedFromCampaigns: NotRequired[bool]
    Properties: NotRequired[dict[str, Any]]


class ManageManyContactsPayload(TypedDict):
    """Bulk contact management payload (/v3/REST/contact/managemanycontacts)."""

    Contacts: list[ManageManyContactsItem]
    ContactsLists: NotRequired[list[ContactListSubscription]]


class EventCallbackUrlPayload(TypedDict):
    """Webhook registration payload (/v3/REST/eventcallbackurl)."""

    Url: str
    EventType: NotRequired[WebhookEventType]
    Version: NotRequired[Literal[1, 2]]
    IsBackup: NotRequired[bool]
    Status: NotRequired[WebhookStatus]


class TemplateContentPayload(TypedDict, total=False):
    """Content API v1 template content payload (/v1/REST/templates/{id}/contents)."""

    Author: str
    Name: str
    Locale: str
    MJMLPart: str
    HTMLPart: str
    TextPart: str
    Headers: dict[str, Any]


class V1TemplatePayload(TypedDict):
    """Content API v1 template metadata payload (/v1/REST/templates)."""

    Name: str
    EditMode: NotRequired[int]
    LabelIDs: NotRequired[list[int]]
    Purposes: NotRequired[list[str]]
    Description: NotRequired[str | None]
    IsStarred: NotRequired[bool]
    IsTextPartGenerationEnabled: NotRequired[bool]


PayloadType: TypeAlias = Mapping[str, Any] | dict[str, Any] | SendV31Payload | list[Any] | str | bytes | None
