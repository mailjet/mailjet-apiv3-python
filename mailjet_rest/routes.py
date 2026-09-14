"""Static routing mappings table and compilation rules registry."""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, NamedTuple


class Route(NamedTuple):
    """Named tuple descriptor mapping localized API boundaries.

    Attributes:
        version (str | None): Hardcoded version overwrite or None for dynamic fallback.
        path (str): Fully qualified URL template path inside the API target.
    """

    version: str | None
    path: str


RouteMapType = dict[str, Route]

# Advisory mapping for legacy and deprecated endpoints
DEPRECATION_ADVISORY: Final[MappingProxyType[str, str]] = MappingProxyType(
    {
        # Newsletters -> Campaign Drafts (Official Mailjet Deprecation)
        "newsletter": "campaigndraft",
        "newsletter_detailcontent": "campaigndraft_detailcontent",
        "newsletter_schedule": "campaigndraft_schedule",
        "newsletter_send": "campaigndraft_send",
        "newsletter_status": "campaigndraft_status",
        "newsletter_test": "campaigndraft_test",
        # Legacy Statistics -> Statcounters & Recipient ESP (Official Mailjet Deprecation)
        "apikeytotals": "statcounters",  # pragma: allowlist secret
        "campaigngraphstatistics": "statcounters",
        "campaignstatistics": "statcounters",
        "domainstatistics": "statistics_recipientEsp",
        "graphstatistics": "statcounters",
        "liststatistics": "statcounters",
        "messagestatistics": "statcounters",
        "openstatistics": "statcounters",
        "senderstatistics": "statcounters",
        # Removed SDK route alias -> Official REST resource
        "webhook": "eventcallbackurl",
        # Redundant / Ambiguous Template routes
        "template_update": "template.update(id=...)",
        "templates_contents": "template_detailcontent (v3) or template_contents (v1)",
    }
)

_ROUTE_MAP: RouteMapType = {
    # ==========================================
    # Send Emails & Batching
    # ==========================================
    "send": Route(None, "send"),
    "batch": Route(None, "batch"),
    "batchjob": Route(None, "REST/batchjob"),
    "batchjob_csverror": Route(None, "DATA/batchjob/{id}/CSVError/text:csv"),
    # ==========================================
    # Messages
    # ==========================================
    "message": Route(None, "REST/message"),
    "messagehistory": Route(None, "REST/messagehistory"),
    "messageinformation": Route(None, "REST/messageinformation"),
    "messagesentstatistics": Route(None, "REST/messagesentstatistics"),
    "messagestate": Route(None, "REST/messagestate"),
    # ==========================================
    # Message Events
    # ==========================================
    "bouncestatistics": Route(None, "REST/bouncestatistics"),
    "clickstatistics": Route(None, "REST/clickstatistics"),
    "openinformation": Route(None, "REST/openinformation"),
    # ==========================================
    # Webhooks & Parse API
    # ==========================================
    "eventcallbackurl": Route(None, "REST/eventcallbackurl"),
    "webhook": Route(None, "REST/webhook"),
    "parseroute": Route(None, "REST/parseroute"),
    # ==========================================
    # Contacts
    # ==========================================
    "contact": Route(None, "REST/contact"),
    "contactdata": Route(None, "REST/contactdata"),
    "contactmetadata": Route(None, "REST/contactmetadata"),
    "contactslist": Route(None, "REST/contactslist"),
    "contactslist_csvdata": Route(None, "DATA/contactslist/{id}/CSVData/text:plain"),
    "contactslistsignup": Route(None, "REST/contactslistsignup"),
    "listrecipient": Route(None, "REST/listrecipient"),
    "csvimport": Route(None, "REST/csvimport"),
    # Contact Sub-resources & Actions
    "contact_managemanycontacts": Route(None, "REST/contact/managemanycontacts"),
    "contact_managecontactslists": Route(None, "REST/contact/{id}/managecontactslists"),
    "contact_getcontactslists": Route(None, "REST/contact/{id}/getcontactslists"),
    "contactslist_managemanycontacts": Route(None, "REST/contactslist/{id}/managemanycontacts"),
    "contactslist_importlist": Route(None, "REST/contactslist/{id}/importlist"),
    "contactslist_managecontact": Route(None, "REST/contactslist/{id}/managecontact"),
    "contactslist_verify": Route(None, "REST/contactslist/{id}/verify"),
    # ==========================================
    # Segmentation
    # ==========================================
    "contactfilter": Route(None, "REST/contactfilter"),
    # ==========================================
    # Campaigns & Newsletters
    # ==========================================
    "campaign": Route(None, "REST/campaign"),
    "campaigndraft": Route(None, "REST/campaigndraft"),
    "campaigndraft_detailcontent": Route(None, "REST/campaigndraft/{id}/detailcontent"),
    "campaigndraft_schedule": Route(None, "REST/campaigndraft/{id}/schedule"),
    "campaigndraft_send": Route(None, "REST/campaigndraft/{id}/send"),
    "campaigndraft_status": Route(None, "REST/campaigndraft/{id}/status"),
    "campaigndraft_test": Route(None, "REST/campaigndraft/{id}/test"),
    # Deprecated Newsletters (Maintained for Backward Compatibility)
    "newsletter": Route(None, "REST/newsletter"),
    "newsletter_detailcontent": Route(None, "REST/newsletter/{id}/detailcontent"),
    "newsletter_schedule": Route(None, "REST/newsletter/{id}/schedule"),
    "newsletter_send": Route(None, "REST/newsletter/{id}/send"),
    "newsletter_status": Route(None, "REST/newsletter/{id}/status"),
    "newsletter_test": Route(None, "REST/newsletter/{id}/test"),
    # ==========================================
    # Templates
    # ==========================================
    "template": Route(None, "REST/template"),
    "templates": Route(None, "REST/templates"),
    "template_detailcontent": Route(None, "REST/template/{id}/detailcontent"),
    "template_update": Route(None, "REST/template/{id}"),
    "templates_contents": Route(None, "REST/templates/{id}/contents"),
    "template_contents": Route("v1", "REST/templates/{id}/contents"),
    "template_content_by_type": Route("v1", "REST/templates/{id}/contents/types/{action_id}"),
    # ==========================================
    # Active Statistics
    # ==========================================
    "statcounters": Route(None, "REST/statcounters"),
    "campaignoverview": Route(None, "REST/campaignoverview"),
    "contactstatistics": Route(None, "REST/contactstatistics"),
    "geostatistics": Route(None, "REST/geostatistics"),
    "listrecipientstatistics": Route(None, "REST/listrecipientstatistics"),
    "statistics_linkClick": Route(None, "REST/statistics/link-click"),
    "statistics_recipientEsp": Route(None, "REST/statistics/recipient-esp"),
    "toplinkclicked": Route(None, "REST/toplinkclicked"),
    "useragentstatistics": Route(None, "REST/useragentstatistics"),
    # Deprecated Statistics (Maintained for Backward Compatibility)
    "apikeytotals": Route(None, "REST/apikeytotals"),
    "campaigngraphstatistics": Route(None, "REST/campaigngraphstatistics"),
    "campaignstatistics": Route(None, "REST/campaignstatistics"),
    "domainstatistics": Route(None, "REST/domainstatistics"),
    "graphstatistics": Route(None, "REST/graphstatistics"),
    "liststatistics": Route(None, "REST/liststatistics"),
    "messagestatistics": Route(None, "REST/messagestatistics"),
    "openstatistics": Route(None, "REST/openstatistics"),
    "senderstatistics": Route(None, "REST/senderstatistics"),
    # ==========================================
    # Sender Addresses and Domains
    # ==========================================
    "sender": Route(None, "REST/sender"),
    "sender_validate": Route(None, "REST/sender/{id}/validate"),
    "metasender": Route(None, "REST/metasender"),
    "dns": Route(None, "REST/dns"),
    "dns_check": Route(None, "REST/dns/{id}/check"),
    # ==========================================
    # Settings (API Keys & Account)
    # ==========================================
    "apikey": Route(None, "REST/apikey"),
    "apikeyaccess": Route(None, "REST/apikeyaccess"),
    "myprofile": Route(None, "REST/myprofile"),
    "user": Route(None, "REST/user"),
    # ==========================================
    # Content API (v1) - Assets, Labels & Tokens
    # ==========================================
    "tokens": Route("v1", "REST/tokens"),
    "labels": Route("v1", "REST/labels"),
    "images": Route("v1", "REST/images"),
    "data_images": Route("v1", "data/images"),
}

ROUTE_MAP: Final[MappingProxyType[str, Route]] = MappingProxyType(_ROUTE_MAP)
