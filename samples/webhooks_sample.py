import hashlib
import hmac
import os
import time

from mailjet_rest import Client, verify_webhook_signature


MAX_HOOK_OUTPUT_CHARS = 8_000

mailjet30 = Client(
    auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
)


def setup_webhook():
    """POST https://api.mailjet.com/v3/REST/eventcallbackurl"""
    data = {
        "EventType": "open",
        "Url": "https://www.mydomain.com/webhook",
        "Status": "alive",
    }
    return mailjet30.eventcallbackurl.create(data=data)


def list_webhooks():
    """GET https://api.mailjet.com/v3/REST/eventcallbackurl"""
    return mailjet30.eventcallbackurl.get()


def get_webhook(webhook_id: int):
    """GET https://api.mailjet.com/v3/REST/eventcallbackurl/{id}"""
    return mailjet30.eventcallbackurl.get(id=webhook_id)


def update_webhook(webhook_id: int, url: str = "https://www.mydomain.com/webhook-v2"):
    """PUT https://api.mailjet.com/v3/REST/eventcallbackurl/{id}"""
    return mailjet30.eventcallbackurl.update(id=webhook_id, data={"Url": url, "Status": "alive"})


def delete_webhook(webhook_id: int):
    """DELETE https://api.mailjet.com/v3/REST/eventcallbackurl/{id}"""
    return mailjet30.eventcallbackurl.delete(id=webhook_id)


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
    print(f"verify_webhook_demo: {demo_ok}"[:MAX_HOOK_OUTPUT_CHARS])
    if not os.environ.get("MJ_APIKEY_PUBLIC") or not os.environ.get("MJ_APIKEY_PRIVATE"):
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run live webhook calls."[:MAX_HOOK_OUTPUT_CHARS])
    else:
        listed = list_webhooks()
        print(f"list_webhooks: {listed.status_code}"[:MAX_HOOK_OUTPUT_CHARS])
        result = setup_webhook()
        output = f"setup_webhook: {result.status_code}"
        print(output[:MAX_HOOK_OUTPUT_CHARS])
        if result.status_code == 201 and result.json().get("Data"):
            wid = result.json()["Data"][0]["ID"]
            print(f"get_webhook: {get_webhook(wid).status_code}"[:MAX_HOOK_OUTPUT_CHARS])
            print(f"update_webhook: {update_webhook(wid).status_code}"[:MAX_HOOK_OUTPUT_CHARS])
            print(f"delete_webhook: {delete_webhook(wid).status_code}"[:MAX_HOOK_OUTPUT_CHARS])
