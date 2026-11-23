"""Examples for Mailjet Messages and Message Events endpoints."""

from __future__ import annotations

import os
from typing import Any

from mailjet_rest import Client


def _get_client() -> Client:
    """Create a Mailjet v3 Client lazily from environment credentials."""
    return Client(
        auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
    )


def list_messages(limit: int = 5, client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/message"""
    return (client or _get_client()).message.get(filters={"Limit": limit})


def get_message(message_id: int, client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/message/{id}"""
    return (client or _get_client()).message.get(id=message_id)


def get_message_history(message_id: int, client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/messagehistory/{id}"""
    return (client or _get_client()).messagehistory.get(id=message_id)


def get_message_information(message_id: int, client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/messageinformation/{id}"""
    return (client or _get_client()).messageinformation.get(id=message_id)


def list_message_sent_statistics(limit: int = 5, client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/messagesentstatistics (deprecated 410 Gone; prefer statcounters)."""
    return (client or _get_client()).messagesentstatistics.get(filters={"Limit": limit})


def get_api_key_statcounters(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/statcounters"""
    return (client or _get_client()).statcounters.get(
        filters={
            "CounterSource": "APIKey",
            "CounterTiming": "Message",
            "CounterResolution": "Lifetime",
        }
    )


def list_message_states(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/messagestate"""
    return (client or _get_client()).messagestate.get()


def list_bounce_statistics(limit: int = 5, client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/bouncestatistics"""
    return (client or _get_client()).bouncestatistics.get(filters={"Limit": limit})


def list_click_statistics(limit: int = 5, client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/clickstatistics"""
    return (client or _get_client()).clickstatistics.get(filters={"Limit": limit})


def list_open_information(limit: int = 5, client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/openinformation"""
    return (client or _get_client()).openinformation.get(filters={"Limit": limit})


if __name__ == "__main__":
    if not os.environ.get("MJ_APIKEY_PUBLIC") or not os.environ.get("MJ_APIKEY_PRIVATE"):
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run this sample.")
    else:
        with _get_client() as mailjet30:
            msgs = list_messages(limit=1, client=mailjet30)
            print(f"list_messages: {msgs.status_code}")
            msg_id = msgs.json()["Data"][0]["ID"] if msgs.status_code == 200 and msgs.json().get("Data") else 0

            steps: list[tuple[Any, dict[str, Any]]] = [
                (get_message, {"message_id": msg_id}),
                (get_message_history, {"message_id": msg_id}),
                (get_message_information, {"message_id": msg_id}),
                (get_api_key_statcounters, {}),
                (list_message_states, {}),
                (list_bounce_statistics, {}),
                (list_click_statistics, {}),
                (list_open_information, {}),
            ]
            for func, kwargs in steps:
                try:
                    res = func(client=mailjet30, **kwargs)
                    print(f"{func.__name__}: {res.status_code}")
                except Exception as exc:
                    print(f"{func.__name__} failed: {exc}")
