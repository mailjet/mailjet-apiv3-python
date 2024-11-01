import json
import os

from mailjet_rest import Client


mailjet30 = Client(
    auth=(os.environ["MJ_APIKEY_PUBLIC"], os.environ["MJ_APIKEY_PRIVATE"]),
)

mailjet31 = Client(
    auth=(os.environ["MJ_APIKEY_PUBLIC"], os.environ["MJ_APIKEY_PRIVATE"]),
    version="v3.1",
)


def validate_an_entire_domain():
    """GET https: // api.mailjet.com / v3 / REST / dns"""
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
    """ET https://api.mailjet.com/v3/REST/dns"""
    _id = "$dns_ID"
    return mailjet30.dns.get(id=_id)


def use_a_sender_on_all_api_keys():
    """POST https://api.mailjet.com/v3/REST/metasender"""
    data = {
        "Description": "Metasender 1 - used for Promo emails",
        "Email": "pilot@mailjet.com",
    }
    return mailjet30.metasender.create(data=data)


if __name__ == "__main__":
    result = validate_an_entire_domain()
    print(result.status_code)
    try:
        print(json.dumps(result.json(), indent=4))
    except json.decoder.JSONDecodeError:
        print(result.text)
