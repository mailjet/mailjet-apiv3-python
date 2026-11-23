"""Mailjet Enhanced Fuzzer Seed Harvester & Synthetic Corpus Generator.

Harvests live API success/error payloads (including stateful CRUD lifecycles
with automatic teardown) AND synthesizes structural, binary, and adversarial
seeds across all synchronous and asynchronous Atheris fuzz targets.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import logging
import os
import re
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests


logger = logging.getLogger("seed_harvester")

BASE_URL_V3 = "https://api.mailjet.com/v3/REST"
BASE_URL_V3_DATA = "https://api.mailjet.com/v3/DATA"
BASE_URL_V3_1 = "https://api.mailjet.com/v3.1"
BASE_URL_V1 = "https://api.mailjet.com/v1/REST"
BASE_URL_V1_DATA = "https://api.mailjet.com/v1/data"
BASE_URL_V3_SEND = "https://api.mailjet.com/v3"
BASE_URL_V4 = "https://api.mailjet.com/v4"

_REDACTED_KEY_FIELDS: frozenset[str] = frozenset(
    {
        "apikey",
        "api_key",
        "secretkey",
        "secret_key",
        "accesstoken",
        "access_token",
        "token",
        "bearer",
        "password",
        "secret",
        "authorization",
        "privatekey",
        "private_key",
        "publickey",
        "public_key",
    }
)
_REDACTED_EMAIL_FIELDS: frozenset[str] = frozenset({"email", "fromemail", "replyto", "contactalt"})
_REDACTED_NAME_FIELDS: frozenset[str] = frozenset(
    {"name", "fromname", "firstname", "lastname", "username", "fullname", "companyname"}
)
_BEARER_VALUE_RE = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+\b", re.IGNORECASE)
_EMAIL_VALUE_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


@dataclass(frozen=True, slots=True)
class HarvestTarget:
    """Descriptor for an individual Mailjet API endpoint harvest probe."""

    name: str
    method: str
    url: str
    params: dict[str, Any] | None = None
    json_body: dict[str, Any] | list[Any] | None = None
    raw_data: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


TARGETS: tuple[HarvestTarget, ...] = (
    HarvestTarget(
        name="send_v31_sandbox_post",
        method="POST",
        url=f"{BASE_URL_V3_1}/send",
        json_body={
            "SandboxMode": True,
            "Messages": [
                {
                    "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                    "To": [{"Email": "passenger1@mailjet.com", "Name": "Passenger 1"}],
                    "Subject": "Your email flight plan!",
                    "TextPart": "Dear passenger 1, welcome to Mailjet!",
                    "HTMLPart": "<h3>Dear passenger 1, welcome to Mailjet!</h3>",
                    "CustomID": "AppGettingStartedTest",
                }
            ],
        },
    ),
    HarvestTarget(
        name="send_v31_variables_post",
        method="POST",
        url=f"{BASE_URL_V3_1}/send",
        json_body={
            "SandboxMode": True,
            "Globals": {"CustomCampaign": "fuzz-seed-harvest"},
            "Messages": [
                {
                    "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                    "To": [{"Email": "passenger1@mailjet.com", "Name": "Passenger 1"}],
                    "Subject": "Variables {{var:code}}",
                    "TextPart": "Code: {{var:code}}",
                    "TemplateLanguage": True,
                    "Variables": {"code": "XYZ-987", "nested": {"active": True, "count": 3}},
                }
            ],
        },
    ),
    HarvestTarget(
        name="send_v31_error_post",
        method="POST",
        url=f"{BASE_URL_V3_1}/send",
        json_body={
            "SandboxMode": True,
            "Messages": [
                {
                    "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                    "Subject": "Malicious schema test",
                }
            ],
        },
    ),
    HarvestTarget(
        name="send_v3_error_post",
        method="POST",
        url=f"{BASE_URL_V3_SEND}/send",
        json_body={},
    ),
    HarvestTarget(name="contact_get", method="GET", url=f"{BASE_URL_V3}/contact", params={"Limit": 5, "Offset": 0}),
    HarvestTarget(name="contact_notfound_get", method="GET", url=f"{BASE_URL_V3}/contact/999999999999"),
    HarvestTarget(name="contactdata_get", method="GET", url=f"{BASE_URL_V3}/contactdata", params={"Limit": 2}),
    HarvestTarget(name="contactmetadata_get", method="GET", url=f"{BASE_URL_V3}/contactmetadata"),
    HarvestTarget(
        name="contactmetadata_error_post",
        method="POST",
        url=f"{BASE_URL_V3}/contactmetadata",
        json_body={"Datatype": "invalid_type", "Name": "", "NameSpace": "static"},
    ),
    HarvestTarget(name="contactslist_get", method="GET", url=f"{BASE_URL_V3}/contactslist", params={"Limit": 5}),
    HarvestTarget(name="listrecipient_get", method="GET", url=f"{BASE_URL_V3}/listrecipient", params={"Limit": 5}),
    HarvestTarget(
        name="listrecipient_error_post",
        method="POST",
        url=f"{BASE_URL_V3}/listrecipient",
        json_body={"ContactAlt": "fuzz-contact@example.com", "ListID": 999999999},
    ),
    HarvestTarget(
        name="csvimport_error_post",
        method="POST",
        url=f"{BASE_URL_V3}/csvimport",
        json_body={"Method": "addnoforce", "ContactsListID": 999999999, "DataID": 888888888},
    ),
    HarvestTarget(
        name="batchjob_csverror_notfound_get",
        method="GET",
        url=f"{BASE_URL_V3_DATA}/batchjob/999999999/CSVError/text:csv",
    ),
    HarvestTarget(name="contactfilter_get", method="GET", url=f"{BASE_URL_V3}/contactfilter", params={"Limit": 5}),
    HarvestTarget(name="campaign_get", method="GET", url=f"{BASE_URL_V3}/campaign", params={"Limit": 5}),
    HarvestTarget(name="campaigndraft_get", method="GET", url=f"{BASE_URL_V3}/campaigndraft", params={"Limit": 5}),
    HarvestTarget(name="newsletter_get", method="GET", url=f"{BASE_URL_V3}/newsletter", params={"Limit": 2}),
    HarvestTarget(name="template_get", method="GET", url=f"{BASE_URL_V3}/template", params={"Limit": 5}),
    HarvestTarget(
        name="template_detailcontent_notfound_get",
        method="GET",
        url=f"{BASE_URL_V3}/template/999999999999/detailcontent",
    ),
    HarvestTarget(name="eventcallbackurl_get", method="GET", url=f"{BASE_URL_V3}/eventcallbackurl"),
    HarvestTarget(name="parseroute_get", method="GET", url=f"{BASE_URL_V3}/parseroute"),
    HarvestTarget(name="sender_get", method="GET", url=f"{BASE_URL_V3}/sender"),
    HarvestTarget(name="sender_error_post", method="POST", url=f"{BASE_URL_V3}/sender", json_body={}),
    HarvestTarget(name="metasender_get", method="GET", url=f"{BASE_URL_V3}/metasender"),
    HarvestTarget(name="dns_get", method="GET", url=f"{BASE_URL_V3}/dns"),
    HarvestTarget(name="message_get", method="GET", url=f"{BASE_URL_V3}/message", params={"Limit": 10}),
    HarvestTarget(
        name="statcounters_get",
        method="GET",
        url=f"{BASE_URL_V3}/statcounters",
        params={"CounterSource": "APIKey", "CounterTiming": "Message", "CounterResolution": "Lifetime"},
    ),
    HarvestTarget(
        name="bouncestatistics_get", method="GET", url=f"{BASE_URL_V3}/bouncestatistics", params={"Limit": 5}
    ),
    HarvestTarget(name="clickstatistics_get", method="GET", url=f"{BASE_URL_V3}/clickstatistics", params={"Limit": 5}),
    HarvestTarget(name="openinformation_get", method="GET", url=f"{BASE_URL_V3}/openinformation", params={"Limit": 5}),
    HarvestTarget(name="geostatistics_get", method="GET", url=f"{BASE_URL_V3}/geostatistics"),
    HarvestTarget(name="toplinkclicked_get", method="GET", url=f"{BASE_URL_V3}/toplinkclicked"),
    HarvestTarget(name="useragentstatistics_get", method="GET", url=f"{BASE_URL_V3}/useragentstatistics"),
    HarvestTarget(name="labels_get", method="GET", url=f"{BASE_URL_V1}/labels"),
    HarvestTarget(name="v1_templates_get", method="GET", url=f"{BASE_URL_V1}/templates"),
    HarvestTarget(
        name="template_contents_lock_notfound_post",
        method="POST",
        url=f"{BASE_URL_V1}/templates/999999999999/contents/lock",
    ),
    HarvestTarget(
        name="template_contents_publish_notfound_post",
        method="POST",
        url=f"{BASE_URL_V1}/templates/999999999999/contents/publish",
    ),
    HarvestTarget(
        name="template_contents_unlock_notfound_post",
        method="POST",
        url=f"{BASE_URL_V1}/templates/999999999999/contents/unlock",
    ),
    HarvestTarget(
        name="data_images_by_type_notfound_get",
        method="GET",
        url=f"{BASE_URL_V1_DATA}/images/999999999999/image:png",
    ),
    HarvestTarget(
        name="contacts_v4_notfound_delete",
        method="DELETE",
        url=f"{BASE_URL_V4}/contacts/999999999999",
    ),
)

CORPUS_MAP: dict[str, tuple[str, ...]] = {
    "fuzz_endpoint": (
        "contact_get",
        "contactdata_get",
        "contactmetadata_get",
        "contactslist_get",
        "listrecipient_get",
        "message_get",
        "campaign_get",
        "campaigndraft_get",
        "newsletter_get",
        "template_get",
        "sender_get",
        "metasender_get",
        "dns_get",
        "eventcallbackurl_get",
        "parseroute_get",
        "statcounters_get",
        "bouncestatistics_get",
        "clickstatistics_get",
        "openinformation_get",
        "geostatistics_get",
        "toplinkclicked_get",
        "useragentstatistics_get",
        "labels_get",
        "v1_templates_get",
        "template_contents_lock_notfound_post",
        "template_contents_publish_notfound_post",
        "template_contents_unlock_notfound_post",
        "data_images_by_type_notfound_get",
        "contacts_v4_notfound_delete",
    ),
    "fuzz_async_endpoint": (
        "contact_get",
        "contactslist_get",
        "message_get",
        "campaign_get",
        "template_get",
        "statcounters_get",
        "labels_get",
        "v1_templates_get",
        "template_contents_lock_notfound_post",
        "template_contents_publish_notfound_post",
        "template_contents_unlock_notfound_post",
        "data_images_by_type_notfound_get",
        "contacts_v4_notfound_delete",
        "lifecycle_contact_create",
        "lifecycle_contact_get",
        "lifecycle_contact_update",
        "lifecycle_contact_delete",
    ),
    "fuzz_async_client": (
        "send_v31_sandbox_post",
        "send_v31_variables_post",
        "send_v31_error_post",
        "contact_get",
        "contact_notfound_get",
        "contacts_v4_notfound_delete",
        "v1_templates_get",
        "lifecycle_contact_create",
    ),
    "fuzz_builder": (
        "send_v31_sandbox_post",
        "send_v31_variables_post",
    ),
    "fuzz_structure_aware": (
        "send_v31_sandbox_post",
        "send_v31_variables_post",
        "lifecycle_contact_create",
        "csvimport_error_post",
        "listrecipient_error_post",
    ),
    "fuzz_error_parser": (
        "send_v31_error_post",
        "send_v3_error_post",
        "contact_notfound_get",
        "contactmetadata_error_post",
        "template_detailcontent_notfound_get",
        "batchjob_csverror_notfound_get",
        "csvimport_error_post",
        "listrecipient_error_post",
        "sender_error_post",
    ),
    "fuzz_pagination_stream": (
        "contact_get",
        "contactslist_get",
        "message_get",
        "campaign_get",
        "bouncestatistics_get",
        "listrecipient_get",
        "clickstatistics_get",
        "openinformation_get",
    ),
    "fuzz_async_pagination_and_retry": (
        "contact_get",
        "contactslist_get",
        "message_get",
        "campaign_get",
        "bouncestatistics_get",
    ),
    "fuzz_openapi_routes_and_mock_parity": (
        "send_v31_sandbox_post",
        "contact_get",
        "contact_notfound_get",
        "statcounters_get",
        "labels_get",
        "v1_templates_get",
        "contacts_v4_notfound_delete",
    ),
    "fuzz_evil_server": (
        "send_v31_sandbox_post",
        "send_v31_error_post",
        "contact_notfound_get",
        "batchjob_csverror_notfound_get",
    ),
    "fuzz_async_evil_server": (
        "send_v31_sandbox_post",
        "send_v31_error_post",
        "contact_notfound_get",
        "batchjob_csverror_notfound_get",
    ),
    "fuzz_network_chaos": (
        "send_v31_sandbox_post",
        "send_v31_error_post",
        "contact_get",
        "contact_notfound_get",
    ),
    "fuzz_differential": (
        "send_v31_sandbox_post",
        "send_v31_variables_post",
        "send_v3_error_post",
    ),
    "fuzz_differential_v3": (
        "send_v31_sandbox_post",
        "send_v3_error_post",
    ),
    "fuzz_idempotency_fingerprint": (
        "send_v31_sandbox_post",
        "send_v31_variables_post",
        "lifecycle_contact_create",
    ),
}


class CorpusWriter:
    """Content-addressed seed writer with SHA-256 deduplication and dry-run support."""

    def __init__(self, base_corpus_dir: Path, *, dry_run: bool = False) -> None:
        """Initialize the corpus writer and deduplication cache."""
        self.base_corpus_dir = base_corpus_dir
        self.dry_run = dry_run
        self._seen_hashes: dict[str, set[str]] = {}
        self.written_count = 0
        self.skipped_duplicates = 0

    def write_seed(self, fuzzer_name: str, seed_name: str, data: bytes) -> None:
        """Write a unique seed file into the target fuzzer's corpus folder."""
        if not data:
            return

        digest = hashlib.sha256(data).hexdigest()
        seen = self._seen_hashes.setdefault(fuzzer_name, set())
        if digest in seen:
            self.skipped_duplicates += 1
            return
        seen.add(digest)

        target_dir = self.base_corpus_dir / fuzzer_name
        file_path = target_dir / f"{seed_name}_{digest[:10]}.seed"

        if self.dry_run:
            logger.info("[DRY-RUN] Would write %s (%d bytes)", file_path, len(data))
            self.written_count += 1
            return

        target_dir.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(data)
        self.written_count += 1
        logger.debug("Saved seed %s (%d bytes)", file_path, len(data))


def _scrub_string_value(text: str, key_lower: str) -> str:
    if key_lower in _REDACTED_KEY_FIELDS:
        return "[REDACTED]"
    if key_lower in _REDACTED_EMAIL_FIELDS:
        return "redacted@example.com"
    if key_lower in _REDACTED_NAME_FIELDS:
        return "[REDACTED_NAME]"
    scrubbed = _BEARER_VALUE_RE.sub(r"\1 [REDACTED]", text)
    return _EMAIL_VALUE_RE.sub("redacted@example.com", scrubbed)


def scrub_sensitive_payload(node: Any, *, key_name: str | None = None) -> Any:
    """Recursively scrub PII and credential fields from harvested API payloads.

    Returns:
        Any: Redacted payload preserving original JSON schema structure.
    """
    if isinstance(node, dict):
        return {k: scrub_sensitive_payload(v, key_name=str(k)) for k, v in node.items()}
    if isinstance(node, list):
        return [scrub_sensitive_payload(item, key_name=key_name) for item in node]
    if isinstance(node, str):
        return _scrub_string_value(node, (key_name or "").lower())
    if key_name and key_name.lower() in _REDACTED_KEY_FIELDS and node is not None:
        return "[REDACTED]"
    return node


def _serialize_response_body(resp: requests.Response) -> bytes:
    """Parse response body as pretty scrubbed JSON if valid, otherwise scrub raw text bytes.

    Returns:
        bytes: Encoded redacted JSON or scrubbed raw response bytes.
    """
    try:
        parsed = resp.json()
    except ValueError:
        raw_bytes = resp.content or resp.text.encode("utf-8", errors="replace")
        if not raw_bytes:
            return b""
        return _scrub_string_value(raw_bytes.decode("utf-8", errors="replace"), "").encode("utf-8")
    cleaned = scrub_sensitive_payload(parsed)
    return json.dumps(cleaned, indent=2, ensure_ascii=False).encode("utf-8")


def _dispatch_target_to_corpora(writer: CorpusWriter, target_name: str, status_code: int, payload: bytes) -> None:
    """Route a harvested payload to every mapped fuzzer corpus directory."""
    for fuzzer_folder, target_names in CORPUS_MAP.items():
        if target_name in target_names:
            writer.write_seed(fuzzer_folder, f"{status_code}_{target_name}", payload)


def harvest_live_static_targets(
    session: requests.Session,
    writer: CorpusWriter,
    timeout: float,
) -> None:
    """Execute read-only and stateless validation probes against the live Mailjet API."""
    for target in TARGETS:
        logger.info("Harvesting %s %s (%s)...", target.method, target.url, target.name)
        try:
            resp = session.request(
                target.method,
                target.url,
                params=target.params,
                json=target.json_body,
                data=target.raw_data,
                headers=target.headers or None,
                timeout=timeout,
            )
            payload = _serialize_response_body(resp)
            _dispatch_target_to_corpora(writer, target.name, resp.status_code, payload)
        except requests.exceptions.RequestException as exc:
            logger.warning("Network error harvesting %s: %s", target.name, exc)


def _harvest_contact_step(
    session: requests.Session,
    writer: CorpusWriter,
    contact_email: str,
    suffix: str,
    timeout: float,
) -> int | None:
    """Create, read, and update a temporary contact.

    Returns:
        The created contact ID, or ``None`` if creation failed.
    """
    c_create = session.post(
        f"{BASE_URL_V3}/contact",
        json={"Email": contact_email, "IsExcludedFromCampaigns": True},
        timeout=timeout,
    )
    _dispatch_target_to_corpora(
        writer, "lifecycle_contact_create", c_create.status_code, _serialize_response_body(c_create)
    )
    if c_create.status_code != 201:
        return None
    contact_id: int = c_create.json()["Data"][0]["ID"]
    c_get = session.get(f"{BASE_URL_V3}/contact/{contact_id}", timeout=timeout)
    _dispatch_target_to_corpora(writer, "lifecycle_contact_get", c_get.status_code, _serialize_response_body(c_get))
    c_upd = session.put(
        f"{BASE_URL_V3}/contact/{contact_id}",
        json={"Name": f"Fuzz User {suffix}"},
        timeout=timeout,
    )
    _dispatch_target_to_corpora(writer, "lifecycle_contact_update", c_upd.status_code, _serialize_response_body(c_upd))
    return contact_id


def _harvest_list_csv_step(
    session: requests.Session,
    writer: CorpusWriter,
    contact_email: str,
    suffix: str,
    timeout: float,
) -> int | None:
    """Create a temporary contacts list and upload CSV data.

    Returns:
        The created contacts list ID, or ``None`` if creation failed.
    """
    l_create = session.post(
        f"{BASE_URL_V3}/contactslist",
        json={"Name": f"FuzzHarvestList_{suffix}"},
        timeout=timeout,
    )
    if l_create.status_code != 201:
        return None
    list_id: int = l_create.json()["Data"][0]["ID"]
    csv_body = f"email,name\n{contact_email},Fuzz User\n"
    csv_resp = session.post(
        f"{BASE_URL_V3_DATA}/contactslist/{list_id}/CSVData/text:plain",
        data=csv_body.encode("utf-8"),
        headers={"Content-Type": "text/plain"},
        timeout=timeout,
    )
    writer.write_seed("fuzz_csv_import_flow", f"{csv_resp.status_code}_csv_upload", _serialize_response_body(csv_resp))
    writer.write_seed("fuzz_endpoint", f"{csv_resp.status_code}_csv_upload", _serialize_response_body(csv_resp))
    return list_id


def harvest_live_crud_lifecycles(
    session: requests.Session,
    writer: CorpusWriter,
    timeout: float,
) -> None:
    """Execute stateful Create -> Read -> Update -> Delete lifecycles with guaranteed cleanup."""
    suffix = uuid.uuid4().hex[:8]
    contact_email = f"fuzz-harvest-{suffix}@example.com"
    contact_id: int | None = None
    list_id: int | None = None

    try:
        contact_id = _harvest_contact_step(session, writer, contact_email, suffix, timeout)
        list_id = _harvest_list_csv_step(session, writer, contact_email, suffix, timeout)
    except requests.exceptions.RequestException as exc:
        logger.warning("Contact/List lifecycle harvest interrupted: %s", exc)
    finally:
        if contact_id is not None:
            with contextlib.suppress(requests.RequestException):
                c_del = session.delete(f"{BASE_URL_V4}/contacts/{contact_id}", timeout=timeout)
                if c_del.status_code < 400:
                    del_payload = _serialize_response_body(c_del)
                    if del_payload:
                        _dispatch_target_to_corpora(writer, "lifecycle_contact_delete", c_del.status_code, del_payload)
        if list_id is not None:
            with contextlib.suppress(requests.RequestException):
                session.delete(f"{BASE_URL_V3}/contactslist/{list_id}", timeout=timeout)


def generate_synthetic_seeds(writer: CorpusWriter) -> None:
    """Synthesize structural, binary FDP, and adversarial edge-case seeds for all fuzzers."""
    logger.info("Generating synthetic and adversarial seeds for all sync & async fuzzers...")

    json_seeds: dict[str, bytes] = {
        "valid_v31_send": json.dumps(
            {
                "SandboxMode": True,
                "Messages": [
                    {
                        "From": {"Email": "pilot@mailjet.com", "Name": "Pilot"},
                        "To": [{"Email": "passenger@mailjet.com", "Name": "Passenger"}],
                        "Subject": "Flight Plan",
                        "TextPart": "Hello {{var:name}}",
                        "HTMLPart": "<h1>Hello {{var:name}}</h1>",
                        "Variables": {"name": "World", "nested": [1, 2, {"k": "v"}]},
                        "CustomID": "trace-001",
                    }
                ],
            }
        ).encode("utf-8"),
        "valid_pagination_page": json.dumps(
            {
                "Count": 2,
                "Total": 2,
                "Data": [{"ID": 101, "Email": "a@example.com"}, {"ID": 102, "Email": "b@example.com"}],
            }
        ).encode("utf-8"),
        "empty_pagination_page": json.dumps({"Count": 0, "Total": 0, "Data": []}).encode("utf-8"),
        "v3_error_payload": json.dumps(
            {"ErrorIdentifier": "abc-123", "StatusCode": 400, "ErrorMessage": "Invalid payload format"}
        ).encode("utf-8"),
        "v31_rfc8058_tracking": json.dumps(
            {
                "Messages": [
                    {
                        "From": {"Email": "pilot@mailjet.com", "Name": "Pilot"},
                        "To": [{"Email": "passenger@mailjet.com", "Name": "Passenger"}],
                        "Subject": "RFC 8058 & Tracking",
                        "TextPart": "Unsubscribe cleanly",
                        "Headers": {
                            "List-Unsubscribe": "<https://example.com/unsub?id=1>",
                            "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
                        },
                        "TrackOpens": "enabled",
                        "TrackClicks": "disabled",
                        "URLTags": "utm_source=fuzz&utm_medium=email",
                    }
                ]
            }
        ).encode("utf-8"),
        "synthetic_v3_send": json.dumps(
            {
                "FromEmail": "pilot@example.com",
                "FromName": "Synthetic Pilot",
                "Subject": "Synthetic v3 Send",
                "Text-part": "Legacy send API fuzzing",
                "Recipients": [{"Email": "passenger1@example.com"}],
            }
        ).encode("utf-8"),
        "synthetic_v1_tokens": json.dumps(
            {
                "Count": 1,
                "Data": [
                    {
                        "ID": 1001,
                        "Name": "synthetic-token",
                        "AccessToken": "[REDACTED_TOKEN]",
                        "Scopes": ["mailjet:content:read"],
                    }
                ],
            }
        ).encode("utf-8"),
        "synthetic_profile_user": json.dumps(
            {
                "Count": 1,
                "Data": [
                    {
                        "ID": 42,
                        "Email": "profile@example.com",
                        "Name": "Synthetic Profile",
                        "Username": "synth_user",
                    }
                ],
            }
        ).encode("utf-8"),
        "synthetic_apikey": json.dumps(
            {
                "Count": 1,
                "Data": [
                    {
                        "ID": 7,
                        "APIKey": "[REDACTED_APIKEY]",
                        "SecretKey": "[REDACTED_SECRET]",
                        "IsMaster": False,
                        "Name": "Synthetic Key",
                    }
                ],
            }
        ).encode("utf-8"),
    }

    for target_fuzzer in (
        "fuzz_endpoint",
        "fuzz_async_endpoint",
        "fuzz_async_client",
        "fuzz_builder",
        "fuzz_structure_aware",
        "fuzz_differential",
        "fuzz_differential_v3",
        "fuzz_error_parser",
        "fuzz_pagination_stream",
        "fuzz_async_pagination_and_retry",
        "fuzz_openapi_routes_and_mock_parity",
        "fuzz_idempotency_fingerprint",
        "fuzz_telemetry",
    ):
        for seed_name, seed_bytes in json_seeds.items():
            writer.write_seed(target_fuzzer, f"synth_{seed_name}", seed_bytes)

    adversarial_vectors: dict[str, bytes] = {
        "path_traversal_dotdot": b"../../etc/passwd\x00.json",
        "path_traversal_double_encoded": b"%252e%252e%252fadmin%252fdelete",
        "template_injection": b"{{7*7}}{% debug %}123",
        "crlf_header_smuggling": b"X-Custom: val\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "xss_script_svg": b"<svg/onload=alert(1)><script>document.cookie</script>",
        "idn_homograph": b"user@xn--mnchen-3ya.de\x00user@m\xc3\xbcnchen.de",
        "ssrf_localhost_and_evil": b"http://127.0.0.1:8080/\x00https://evil.com/",
        "null_byte_control_chars": b"\x00\x01\x02\x07\x08\x0b\x0c\x0e\x1f\x7fBearer secret_token_123",
        "deep_nested_json": (b'{"a":' * 60) + b"1" + (b"}" * 60),
        "malformed_truncated_json": b'{"Messages": [{"From": {"Email": "unterminated',
        "csv_injection": b"email,name\n=cmd|' /C calc'!A0@evil.com,\"Mallory\r\nInjected\"\n",
        "form_urlencoded_mapping": b"From=pilot%40mailjet.com&To=passenger%40mailjet.com&Subject=Form+Mapping",
        "non_latin1_auth_probe": "key_\u2603:\u00e9\u20ac_secret".encode(),
    }

    all_fdp_fuzzers = (
        "fuzz_core",
        "fuzz_client",
        "fuzz_async_client",
        "fuzz_endpoint",
        "fuzz_async_endpoint",
        "fuzz_endpoint_routing",
        "fuzz_config",
        "fuzz_guardrails",
        "fuzz_guardrails_crypto",
        "fuzz_spamguard",
        "fuzz_redacting_filter",
        "fuzz_idempotency_fingerprint",
        "fuzz_secret_auth",
        "fuzz_jitter_retry",
        "fuzz_audit_events",
        "fuzz_chunked_streamer",
        "fuzz_csv_import_flow",
        "fuzz_network_chaos",
        "fuzz_evil_server",
        "fuzz_async_evil_server",
        "fuzz_state_machine",
        "fuzz_state_sequence",
        "fuzz_router",
        "fuzz_webhooks",
        "fuzz_version_and_exports",
        "fuzz_telemetry",
        "fuzz_transport_security",
        "fuzz_multipart_and_filesystem",
        "fuzz_async_pagination_and_retry",
        "fuzz_openapi_routes_and_mock_parity",
    )

    for fuzzer_name in all_fdp_fuzzers:
        for vec_name, vec_bytes in adversarial_vectors.items():
            writer.write_seed(fuzzer_name, f"adv_{vec_name}", vec_bytes)

        for idx in range(16):
            binary_seed = bytes([(idx * 17 + offset) % 256 for offset in range(32)])
            writer.write_seed(fuzzer_name, f"bin_fdp_{idx:02d}", binary_seed)


def parse_args() -> argparse.Namespace:
    """Parse command-line options for seed harvesting and corpus generation.

    Returns:
        argparse.Namespace: Parsed CLI options.
    """
    parser = argparse.ArgumentParser(description="Mailjet SDK Fuzzer Seed Harvester & Corpus Generator")
    parser.add_argument(
        "--mode",
        choices=("all", "live", "synthetic"),
        default="all",
        help="Harvest mode: 'live' API calls only, 'synthetic' offline seeds only, or 'all' (default).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("tests") / "fuzz" / "corpus",
        help="Root directory where per-fuzzer corpus folders are stored.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP request timeout in seconds for live harvesting (default: 10.0).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log planned corpus writes without touching the filesystem.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove existing corpus directory before generating fresh seeds.",
    )
    return parser.parse_args()


def _run_live_harvest(writer: CorpusWriter, timeout: float) -> None:
    public_key = os.environ.get("MJ_APIKEY_PUBLIC")
    private_key = os.environ.get("MJ_APIKEY_PRIVATE")
    if not public_key or not private_key:
        logger.warning("MJ_APIKEY_PUBLIC or MJ_APIKEY_PRIVATE is not set; skipping live API harvest.")
        return

    with requests.Session() as session:
        session.auth = (public_key, private_key)
        session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "mailjet-apiv3-python-seed-harvester/1.0",
            }
        )
        harvest_live_static_targets(session=session, writer=writer, timeout=timeout)
        harvest_live_crud_lifecycles(session=session, writer=writer, timeout=timeout)


def harvest_seeds(
    mode: str = "all",
    output_dir: Path | None = None,
    timeout: float = 10.0,
    *,
    dry_run: bool = False,
    clean: bool = False,
) -> None:
    """Run the Mailjet seed harvesting and synthetic corpus generation pipeline."""
    corpus_root = output_dir or (Path("tests") / "fuzz" / "corpus")

    if clean and corpus_root.exists() and not dry_run:
        logger.info("Cleaning existing corpus directory: %s", corpus_root)
        shutil.rmtree(corpus_root)

    writer = CorpusWriter(base_corpus_dir=corpus_root, dry_run=dry_run)

    if mode in {"all", "synthetic"}:
        generate_synthetic_seeds(writer)

    if mode in {"all", "live"}:
        _run_live_harvest(writer=writer, timeout=timeout)

    logger.info(
        "Seed harvesting complete: %d unique seeds written, %d duplicates skipped.",
        writer.written_count,
        writer.skipped_duplicates,
    )


def main() -> None:
    """CLI entry point for seed harvester."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    args = parse_args()
    harvest_seeds(
        mode=args.mode,
        output_dir=args.output_dir,
        timeout=args.timeout,
        dry_run=args.dry_run,
        clean=args.clean,
    )


if __name__ == "__main__":
    main()
