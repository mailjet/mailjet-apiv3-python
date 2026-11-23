from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Any

from mailjet_rest import Client, verify_webhook_signature


def _get_client() -> Client:
    """Create a Mailjet v3 Client lazily from environment credentials."""
    return Client(
        auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
    )


def setup_webhook(client: Client | None = None) -> Any:
    """POST https://api.mailjet.com/v3/REST/eventcallbackurl"""
    data = {
        "EventType": "open",
        "Url": "https://www.mydomain.com/webhook",
        "Status": "alive",
    }
    return (client or _get_client()).eventcallbackurl.create(data=data)


def list_webhooks(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/eventcallbackurl"""
    return (client or _get_client()).eventcallbackurl.get()


def get_webhook(webhook_id: int, client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/eventcallbackurl/{id}"""
    return (client or _get_client()).eventcallbackurl.get(id=webhook_id)


def update_webhook(
    webhook_id: int,
    url: str = "https://www.mydomain.com/webhook-v2",
    client: Client | None = None,
) -> Any:
    """PUT https://api.mailjet.com/v3/REST/eventcallbackurl/{id}"""
    return (client or _get_client()).eventcallbackurl.update(
        id=webhook_id,
        data={"Url": url, "Status": "alive"},
    )


def delete_webhook(webhook_id: int, client: Client | None = None) -> Any:
    """DELETE https://api.mailjet.com/v3/REST/eventcallbackurl/{id}"""
    return (client or _get_client()).eventcallbackurl.delete(id=webhook_id)


def verify_webhook_demo() -> bool:
    """Demonstrate offline constant-time HMAC-SHA256 webhook verification with replay protection."""
    payload = b'{"event":"open","MessageID":123456}'
    demo_secret = "demo_signing_key"  # pragma: allowlist secret
    sig = hmac.new(demo_secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    now_ts = int(time.time())
    valid = verify_webhook_signature(payload, sig, demo_secret, timestamp_unix=now_ts, max_age_seconds=300)
    expired = verify_webhook_signature(payload, sig, demo_secret, timestamp_unix=now_ts - 3600, max_age_seconds=300)
    return valid and not expired


if __name__ == "__main__":
    demo_ok = verify_webhook_demo()
    print(f"verify_webhook_demo: {demo_ok}")
    if not os.environ.get("MJ_APIKEY_PUBLIC") or not os.environ.get("MJ_APIKEY_PRIVATE"):
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run live webhook calls.")
    else:
        with _get_client() as mailjet30:
            listed = list_webhooks(client=mailjet30)
            print(f"list_webhooks: {listed.status_code}")
            result = setup_webhook(client=mailjet30)
            print(f"setup_webhook: {result.status_code}")
            if result.status_code == 201 and result.json().get("Data"):
                wid = result.json()["Data"][0]["ID"]
                print(f"get_webhook: {get_webhook(wid, client=mailjet30).status_code}")
                print(f"update_webhook: {update_webhook(wid, client=mailjet30).status_code}")
                print(f"delete_webhook: {delete_webhook(wid, client=mailjet30).status_code}")
