from __future__ import annotations

import os
from typing import Any

from mailjet_rest import Client


def _get_client() -> Client:
    """Create a Mailjet v3 Client lazily from environment credentials."""
    return Client(auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")))


def validate_an_entire_domain(dns_id: int = 0, client: Client | None = None) -> Any:
    return (client or _get_client()).dns.get(id=dns_id)


def do_an_immediate_check_via_a_post(dns_id: int = 0, client: Client | None = None) -> Any:
    return (client or _get_client()).dns_check.create(id=dns_id)


def host_a_text_file(sender_id: int = 0, client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/sender/$sender_ID"""
    return (client or _get_client()).sender.get(id=sender_id)


def validation_by_doing_a_post(sender_id: int = 0, client: Client | None = None) -> Any:
    return (client or _get_client()).sender_validate.create(id=sender_id)


def spf_and_dkim_validation(dns_id: int = 0, client: Client | None = None) -> Any:
    return (client or _get_client()).dns.get(id=dns_id)


def list_metasenders(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/metasender"""
    return (client or _get_client()).metasender.get(filters={"Limit": 5})


def create_metasender(
    email: str = "noreply@example.com",
    description: str = "Sample domain",
    client: Client | None = None,
) -> Any:
    """POST https://api.mailjet.com/v3/REST/metasender"""
    return (client or _get_client()).metasender.create(data={"Email": email, "Description": description})


if __name__ == "__main__":
    if not os.environ.get("MJ_APIKEY_PUBLIC") or not os.environ.get("MJ_APIKEY_PRIVATE"):
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run this sample.")
        raise SystemExit(0)

    with _get_client() as mailjet30:
        # Dynamically fetch an active DNS ID to prevent 404 Not Found errors
        dns_res = mailjet30.dns.get(filters={"Limit": 1})
        dns_id = dns_res.json()["Data"][0]["ID"] if dns_res.status_code == 200 and dns_res.json().get("Data") else 0

        # Dynamically fetch an active Sender ID to prevent 404 Not Found errors
        sender_res = mailjet30.sender.get(filters={"Limit": 1})
        sender_id = (
            sender_res.json()["Data"][0]["ID"] if sender_res.status_code == 200 and sender_res.json().get("Data") else 0
        )

        inactive_res = mailjet30.sender.get(filters={"Status": "Inactive", "Limit": 1})
        inactive_sender_id = (
            inactive_res.json()["Data"][0]["ID"]
            if inactive_res.status_code == 200 and inactive_res.json().get("Data")
            else 0
        )

        funcs: list[tuple[Any, dict[str, Any]]] = [
            (validate_an_entire_domain, {"dns_id": dns_id}),
            (do_an_immediate_check_via_a_post, {"dns_id": dns_id}),
            (host_a_text_file, {"sender_id": sender_id}),
            (spf_and_dkim_validation, {"dns_id": dns_id}),
            (list_metasenders, {}),
        ]

        for f, kwargs in funcs:
            try:
                r = f(client=mailjet30, **kwargs)
                print(f"{f.__name__}: {r.status_code if hasattr(r, 'status_code') else r}")
            except Exception as e:
                print(f"{f.__name__} failed: {e}")

        if inactive_sender_id:
            try:
                r = validation_by_doing_a_post(sender_id=inactive_sender_id, client=mailjet30)
                print(f"validation_by_doing_a_post: {r.status_code if hasattr(r, 'status_code') else r}")
            except Exception as e:
                print(f"validation_by_doing_a_post failed: {e}")
        else:
            print("validation_by_doing_a_post: skipped (no inactive sender to validate)")
