from __future__ import annotations

import json
import os
import time
from typing import Any

from mailjet_rest import Client
from mailjet_rest.errors import ApiError


def _get_client() -> Client:
    """Create a Mailjet v3 Client lazily from environment credentials."""
    return Client(
        auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
    )


def get_valid_campaign_id(client: Client | None = None) -> int:
    """Dynamically fetch a valid sent campaign ID from the account."""
    active_client = client or _get_client()
    try:
        res = active_client.campaign.get(filters={"Limit": 1})
        if res.status_code == 200 and res.json().get("Data"):
            return int(res.json()["Data"][0]["ID"])
    except (ApiError, ValueError, KeyError) as exc:
        print(f"Campaign lookup fallback: {exc}")
    return 0


def event_based_vs_message_based_stats_timing(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/statcounters"""
    active_client = client or _get_client()
    cmp_id = get_valid_campaign_id(client=active_client)
    filters = {
        "SourceId": cmp_id,
        "CounterSource": "Campaign",
        "CounterTiming": "Message",
        "CounterResolution": "Lifetime",
    }
    return active_client.statcounters.get(filters=filters)


def view_the_spread_of_events_over_time(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/statcounters"""
    active_client = client or _get_client()
    cmp_id = get_valid_campaign_id(client=active_client)

    # Use a narrow window (e.g., last 30 days) to satisfy Mailjet's 100x resolution limit rule
    now = int(time.time())
    from_ts = str(now - (30 * 86400))
    to_ts = str(now)

    filters = {
        "SourceId": cmp_id,
        "CounterSource": "Campaign",
        "CounterTiming": "Event",
        "CounterResolution": "Day",
        "FromTS": from_ts,
        "ToTS": to_ts,
    }
    return active_client.statcounters.get(filters=filters)


def statistics_for_specific_recipient(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/contactstatistics"""
    return (client or _get_client()).contactstatistics.get()


def stats_for_clicked_links(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/statistics/link-click"""
    active_client = client or _get_client()
    cmp_id = get_valid_campaign_id(client=active_client)
    filters = {"CampaignId": cmp_id}
    return active_client.statistics_linkClick.get(filters=filters)


def mailbox_provider_statistics(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/statistics/recipient-esp"""
    active_client = client or _get_client()
    cmp_id = get_valid_campaign_id(client=active_client)
    filters = {"CampaignId": cmp_id}
    return active_client.statistics_recipientEsp.get(filters=filters)


def geographical_statistics(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/geostatistics"""
    return (client or _get_client()).geostatistics.get()


def campaign_overview(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/campaignoverview"""
    return (client or _get_client()).campaignoverview.get(filters={"Limit": 5})


def list_recipient_statistics(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/listrecipientstatistics"""
    return (client or _get_client()).listrecipientstatistics.get(filters={"Limit": 5})


def top_links_clicked(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/toplinkclicked"""
    active_client = client or _get_client()
    cmp_id = get_valid_campaign_id(client=active_client)
    return active_client.toplinkclicked.get(filters={"CampaignID": cmp_id, "Limit": 5})


def user_agent_statistics(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/useragentstatistics"""
    return (client or _get_client()).useragentstatistics.get(filters={"Limit": 5})


if __name__ == "__main__":
    if not os.environ.get("MJ_APIKEY_PUBLIC") or not os.environ.get("MJ_APIKEY_PRIVATE"):
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run this sample.")
        raise SystemExit(0)

    functions = [
        event_based_vs_message_based_stats_timing,
        view_the_spread_of_events_over_time,
        statistics_for_specific_recipient,
        stats_for_clicked_links,
        mailbox_provider_statistics,
        geographical_statistics,
        campaign_overview,
        list_recipient_statistics,
        top_links_clicked,
        user_agent_statistics,
    ]

    with _get_client() as mailjet30:
        for func in functions:
            print(f"\n=> Running: {func.__name__}()")
            try:
                result = func(client=mailjet30)
                status = getattr(result, "status_code", "N/A")
                print(f"Status Code: {status}")
                try:
                    print(json.dumps(result.json(), indent=4))
                except (ValueError, AttributeError):
                    print(getattr(result, "text", str(result)))
            except Exception as e:
                print(f"[FAIL] Failed: {e}")
