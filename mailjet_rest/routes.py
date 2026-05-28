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
    # Send API & Batching
    # ==========================================
    "send": Route(None, "send"),
    "batch": Route(None, "batch"),
    "batchjob": Route(None, "REST/batchjob"),
    # ==========================================
    # Contacts & Contact Lists
    # ==========================================
    "contact": Route(None, "REST/contact"),
    "contactdata": Route(None, "REST/contactdata"),
    "contactmetadata": Route(None, "REST/contactmetadata"),
    "contactslist": Route(None, "REST/contactslist"),
    "contactfilter": Route(None, "REST/contactfilter"),
    "contactslistsignup": Route(None, "REST/contactslistsignup"),
    "csvimport": Route(None, "REST/csvimport"),
    "listrecipient": Route(None, "REST/listrecipient"),
    # Contact Actions (Sub-resources)
    "contact_managemanycontacts": Route(None, "REST/contact/managemanycontacts"),
    "contactslist_managemanycontacts": Route(None, "REST/contactslist/{id}/managemanycontacts"),
    "contact_getcontactslists": Route(None, "REST/contact/{id}/getcontactslists"),
    # ==========================================
    # Campaigns & Newsletters
    # ==========================================
    "campaign": Route(None, "REST/campaign"),
    "newsletter": Route(None, "REST/newsletter"),
    "campaigndraft": Route(None, "REST/campaigndraft"),
    # Campaign Actions
    "campaigndraft_schedule": Route(None, "REST/campaigndraft/{id}/schedule"),
    "campaigndraft_send": Route(None, "REST/campaigndraft/{id}/send"),
    "campaigndraft_test": Route(None, "REST/campaigndraft/{id}/test"),
    "campaigndraft_detailcontent": Route(None, "REST/campaigndraft/{id}/detailcontent"),
    # ==========================================
    # Messages & History
    # ==========================================
    "message": Route(None, "REST/message"),
    "messagehistory": Route(None, "REST/messagehistory"),
    "messageinformation": Route(None, "REST/messageinformation"),
    "messagestate": Route(None, "REST/messagestate"),
    # ==========================================
    # Templates
    # (Email API v3 uses Singular, Content API v1 uses Plural)
    # ==========================================
    "template": Route(None, "REST/template"),
    "templates": Route(None, "REST/templates"),
    "template_update": Route(None, "REST/template/{id}"),
    "template_detailcontent": Route(None, "REST/template/{id}/detailcontent"),
    "templates_contents": Route(None, "REST/templates/{id}/contents"),
    # Content API Template Actions
    "template_contents": Route("v1", "REST/templates/{id}/contents"),
    "template_content_by_type": Route("v1", "REST/templates/{id}/contents/types/{action_id}"),
    # ==========================================
    # Statistics & Analytics
    # ==========================================
    "statcounters": Route(None, "REST/statcounters"),
    "contactstatistics": Route(None, "REST/contactstatistics"),
    "liststatistics": Route(None, "REST/liststatistics"),
    "bouncestatistics": Route(None, "REST/bouncestatistics"),
    "clickstatistics": Route(None, "REST/clickstatistics"),
    "openinformation": Route(None, "REST/openinformation"),
    "senderstatistics": Route(None, "REST/senderstatistics"),
    "domainstatistics": Route(None, "REST/domainstatistics"),
    "campaignstatistics": Route(None, "REST/campaignstatistics"),
    "statistics_linkClick": Route(None, "REST/statistics/link-click"),
    "statistics_recipientEsp": Route(None, "REST/statistics/recipient-esp"),
    "geostatistics": Route(None, "REST/geostatistics"),
    "toplinkclicked": Route(None, "REST/toplinkclicked"),
    # ==========================================
    # Account, Senders & Domains
    # ==========================================
    "myprofile": Route(None, "REST/myprofile"),
    "user": Route(None, "REST/user"),
    "apikey": Route(None, "REST/apikey"),
    "apikeyaccess": Route(None, "REST/apikeyaccess"),
    "apikeytotals": Route(None, "REST/apikeytotals"),
    "sender": Route(None, "REST/sender"),
    "metasender": Route(None, "REST/metasender"),
    "sender_validate": Route(None, "REST/sender/{id}/validate"),
    "dns": Route(None, "REST/dns"),
    "dns_check": Route(None, "REST/dns/{id}/check"),
    # ==========================================
    # Webhooks & Parse API
    # ==========================================
    "eventcallbackurl": Route(None, "REST/eventcallbackurl"),
    "webhook": Route(None, "REST/webhook"),
    "parseroute": Route(None, "REST/parseroute"),
    # ==========================================
    # Content API (v1) - Assets, Labels & Tokens
    # ==========================================
    "tokens": Route("v1", "REST/tokens"),
    "labels": Route("v1", "REST/labels"),
    "images": Route("v1", "REST/images"),
    "data_images": Route("v1", "DATA/images"),
}

ROUTE_MAP: Final = MappingProxyType(_ROUTE_MAP)
