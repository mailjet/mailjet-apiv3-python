import os

from mailjet_rest import Client


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


if __name__ == "__main__":
    result = setup_webhook()
    output = f"Status Code: {result.status_code}"
    print(output[:MAX_HOOK_OUTPUT_CHARS])
