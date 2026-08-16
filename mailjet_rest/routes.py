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


_ROUTE_MAP: RouteMapType = {
    # ==========================================
    # Send Emails & Batching
    # ==========================================
    "send": Route(None, "send"),
    "batch": Route(None, "batch"),
    "batchjob": Route(None, "REST/batchjob"),
    # ==========================================
    # Messages
    # ==========================================
    "message": Route(None, "REST/message"),
    "messagehistory": Route(None, "REST/messagehistory"),
    "messageinformation": Route(None, "REST/messageinformation"),
    "messagesentstatistics": Route(None, "REST/messagesentstatistics"),
    "messagestate": Route(None, "REST/messagestate"),
    # ==========================================
    # Contacts
    # ==========================================
    "contact": Route(None, "REST/contact"),
    "contactslist": Route(None, "REST/contactslist"),
    # Bulk Contact Management
    "contact_managemanycontacts": Route(None, "REST/contact/managemanycontacts"),
    "contactslist_importlist": Route(None, "REST/contactslist/{id}/importlist"),
    "contactslist_managemanycontacts": Route(None, "REST/contactslist/{id}/managemanycontacts"),
    "csvimport": Route(None, "REST/csvimport"),
    # Contact Properties
    "contactdata": Route(None, "REST/contactdata"),
    "contactmetadata": Route(None, "REST/contactmetadata"),
    # Subscriptions
    "contact_getcontactslists": Route(None, "REST/contact/{id}/getcontactslists"),
    "contact_managecontactslists": Route(None, "REST/contact/{id}/managecontactslists"),
    "contactslist_managecontact": Route(None, "REST/contactslist/{id}/managecontact"),
    "contactslistsignup": Route(None, "REST/contactslistsignup"),
    "listrecipient": Route(None, "REST/listrecipient"),
    # Verifications
    "contactslist_verify": Route(None, "REST/contactslist/{id}/verify"),
    # ==========================================
    # Campaigns
    # ==========================================
    # Drafts
    "campaigndraft": Route(None, "REST/campaigndraft"),
    "campaigndraft_detailcontent": Route(None, "REST/campaigndraft/{id}/detailcontent"),
    "campaigndraft_schedule": Route(None, "REST/campaigndraft/{id}/schedule"),
    "campaigndraft_send": Route(None, "REST/campaigndraft/{id}/send"),
    "campaigndraft_status": Route(None, "REST/campaigndraft/{id}/status"),
    "campaigndraft_test": Route(None, "REST/campaigndraft/{id}/test"),
    # Newsletters
    "newsletter": Route(None, "REST/newsletter"),
    "newsletter_detailcontent": Route(None, "REST/newsletter/{id}/detailcontent"),
    "newsletter_schedule": Route(None, "REST/newsletter/{id}/schedule"),
    "newsletter_send": Route(None, "REST/newsletter/{id}/send"),
    "newsletter_status": Route(None, "REST/newsletter/{id}/status"),
    "newsletter_test": Route(None, "REST/newsletter/{id}/test"),
    # Sent Campaigns
    "campaign": Route(None, "REST/campaign"),
    # ==========================================
    # Segmentation
    # ==========================================
    "contactfilter": Route(None, "REST/contactfilter"),
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
    # Statistics
    # ==========================================
    "campaignoverview": Route(None, "REST/campaignoverview"),
    "contactstatistics": Route(None, "REST/contactstatistics"),
    "geostatistics": Route(None, "REST/geostatistics"),
    "listrecipientstatistics": Route(None, "REST/listrecipientstatistics"),
    "statcounters": Route(None, "REST/statcounters"),
    "statistics_linkClick": Route(None, "REST/statistics/link-click"),
    "statistics_recipientEsp": Route(None, "REST/statistics/recipient-esp"),
    "toplinkclicked": Route(None, "REST/toplinkclicked"),
    "useragentstatistics": Route(None, "REST/useragentstatistics"),
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
    # Message Events
    # ==========================================
    "bouncestatistics": Route(None, "REST/bouncestatistics"),
    "clickstatistics": Route(None, "REST/clickstatistics"),
    "openinformation": Route(None, "REST/openinformation"),
    # ==========================================
    # Webhook & Parse
    # ==========================================
    "eventcallbackurl": Route(None, "REST/eventcallbackurl"),
    "webhook": Route(None, "REST/webhook"),
    "parseroute": Route(None, "REST/parseroute"),
    # ==========================================
    # Sender Addresses and Domains
    # ==========================================
    "sender": Route(None, "REST/sender"),
    "sender_validate": Route(None, "REST/sender/{id}/validate"),
    "metasender": Route(None, "REST/metasender"),
    "dns": Route(None, "REST/dns"),
    "dns_check": Route(None, "REST/dns/{id}/check"),
    # ==========================================
    # Settings (API Key Configuration & Account)
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
