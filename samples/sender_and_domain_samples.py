import json
import os

from mailjet_rest import Client

mailjet30 = Client(
    auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
)


def validate_an_entire_domain():
    """GET https://api.mailjet.com/v3/REST/dns"""
    _id = "$dns_ID"
    return mailjet30.dns.get(id=_id)


def do_an_immediate_check_via_a_post():
    """POST https://api.mailjet.com/v3/REST/dns/$dns_ID/check"""
    _id = "$dns_ID"
    return mailjet30.dns_check.create(id=_id)


def host_a_text_file():
    """GET https://api.mailjet.com/v3/REST/sender"""
    _id = "$sender_ID"
    return mailjet30.sender.get(id=_id)


def validation_by_doing_a_post():
    """POST https://api.mailjet.com/v3/REST/sender/$sender_ID/validate"""
    _id = "$sender_ID"
    return mailjet30.sender_validate.create(id=_id)


def spf_and_dkim_validation():
    """GET https://api.mailjet.com/v3/REST/dns"""
    _id = "$dns_ID"
    return mailjet30.dns.get(id=_id)


if __name__ == "__main__":
    result = host_a_text_file()
    print(f"Status Code: {result.status_code}")
    try:
        print(json.dumps(result.json(), indent=4))
    except ValueError:
        print(result.text)
