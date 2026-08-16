import json
import os

from mailjet_rest import Client

mailjet30 = Client(auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")))


def validate_an_entire_domain(dns_id=0):
    return mailjet30.dns.get(id=dns_id)


def do_an_immediate_check_via_a_post(dns_id=0):
    return mailjet30.dns_check.create(id=dns_id)


def host_a_text_file(sender_id=0):
    """GET https://api.mailjet.com/v3/REST/sender/$sender_ID"""
    return mailjet30.sender.get(id=sender_id)


def validation_by_doing_a_post(sender_id=0):
    return mailjet30.sender_validate.create(id=sender_id)


def spf_and_dkim_validation(dns_id=0):
    return mailjet30.dns.get(id=dns_id)


if __name__ == "__main__":
    # Dynamically fetch an active DNS ID to prevent 404 Not Found errors
    dns_res = mailjet30.dns.get(filters={"Limit": 1})
    dns_id = dns_res.json()["Data"][0]["ID"] if dns_res.status_code == 200 and dns_res.json().get("Data") else 0

    # Dynamically fetch an active Sender ID to prevent 404 Not Found errors
    sender_res = mailjet30.sender.get(filters={"Limit": 1})
    sender_id = (
        sender_res.json()["Data"][0]["ID"] if sender_res.status_code == 200 and sender_res.json().get("Data") else 0
    )

    funcs = [
        (validate_an_entire_domain, {"dns_id": dns_id}),
        (do_an_immediate_check_via_a_post, {"dns_id": dns_id}),
        (host_a_text_file, {"sender_id": sender_id}),
        (validation_by_doing_a_post, {"sender_id": sender_id}),
        (spf_and_dkim_validation, {"dns_id": dns_id}),
    ]

    for f, kwargs in funcs:
        try:
            r = f(**kwargs)
            print(f"{f.__name__}: {r.status_code if hasattr(r, 'status_code') else r}")
        except Exception as e:
            print(f"{f.__name__} failed: {e}")
