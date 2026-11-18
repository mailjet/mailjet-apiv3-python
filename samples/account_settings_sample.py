"""Examples for Mailjet Account Settings, Profile, User, and API Key endpoints."""

from __future__ import annotations

import os
from typing import Any

from mailjet_rest import Client

mailjet30 = Client(
    auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
)


def list_api_keys() -> Any:
    """GET https://api.mailjet.com/v3/REST/apikey"""
    return mailjet30.apikey.get()


def list_api_key_access() -> Any:
    """GET https://api.mailjet.com/v3/REST/apikeyaccess"""
    return mailjet30.apikeyaccess.get()


def get_my_profile() -> Any:
    """GET https://api.mailjet.com/v3/REST/myprofile"""
    return mailjet30.myprofile.get()


def update_my_profile(company_name: str) -> Any:
    """PUT https://api.mailjet.com/v3/REST/myprofile"""
    return mailjet30.myprofile.update(data={"CompanyName": company_name})


def get_user() -> Any:
    """GET https://api.mailjet.com/v3/REST/user"""
    return mailjet30.user.get()


if __name__ == "__main__":
    if not os.environ.get("MJ_APIKEY_PUBLIC") or not os.environ.get("MJ_APIKEY_PRIVATE"):
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run this sample.")
    else:
        for func in (list_api_keys, list_api_key_access, get_my_profile, get_user):
            try:
                res = func()
                print(f"{func.__name__}: {res.status_code}")
            except Exception as exc:
                print(f"{func.__name__} failed: {exc}")
        # Mutating call kept optional for safety:
        # update_my_profile("Example Corp")
