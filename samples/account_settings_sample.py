"""Examples for Mailjet Account Settings, Profile, User, and API Key endpoints."""

from __future__ import annotations

import os
from typing import Any

from mailjet_rest import Client


def _get_client() -> Client:
    """Create a Mailjet v3 Client lazily from environment credentials."""
    return Client(
        auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
    )


def list_api_keys(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/apikey"""
    return (client or _get_client()).apikey.get()


def list_api_key_access(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/apikeyaccess"""
    return (client or _get_client()).apikeyaccess.get()


def get_my_profile(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/myprofile"""
    return (client or _get_client()).myprofile.get()


def update_my_profile(company_name: str, client: Client | None = None) -> Any:
    """PUT https://api.mailjet.com/v3/REST/myprofile"""
    return (client or _get_client()).myprofile.update(data={"CompanyName": company_name})


def get_user(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/user"""
    return (client or _get_client()).user.get()


if __name__ == "__main__":
    if not os.environ.get("MJ_APIKEY_PUBLIC") or not os.environ.get("MJ_APIKEY_PRIVATE"):
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run this sample.")
    else:
        with _get_client() as mailjet30:
            for func in (list_api_keys, list_api_key_access, get_my_profile, get_user):
                try:
                    res = func(client=mailjet30)
                    print(f"{func.__name__}: {res.status_code}")
                except Exception as exc:
                    print(f"{func.__name__} failed: {exc}")
            # Mutating call kept optional for safety:
            # update_my_profile("Example Corp", client=mailjet30)
