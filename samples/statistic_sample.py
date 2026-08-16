import json
import os
import time

from mailjet_rest import Client

mailjet30 = Client(
    auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
)

mailjet31 = Client(
    auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
    version="v3.1",
)


def get_valid_campaign_id():
    """Dynamically fetch a valid sent campaign ID from the account."""
    try:
        res = mailjet30.campaign.get(filters={"Limit": 1})
        if res.status_code == 200 and res.json().get("Data"):
            return res.json()["Data"][0]["ID"]
    except Exception:
        pass
    return 0


def event_based_vs_message_based_stats_timing():
    """GET https://api.mailjet.com/v3/REST/statcounters"""
    cmp_id = get_valid_campaign_id()
    filters = {
        "SourceId": cmp_id,
        "CounterSource": "Campaign",
        "CounterTiming": "Message",
        "CounterResolution": "Lifetime",
    }
    return mailjet30.statcounters.get(filters=filters)


def view_the_spread_of_events_over_time():
    """GET https://api.mailjet.com/v3/REST/statcounters"""
    cmp_id = get_valid_campaign_id()

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
    return mailjet30.statcounters.get(filters=filters)


def statistics_for_specific_recipient():
    """GET https://api.mailjet.com/v3/REST/contactstatistics"""
    return mailjet30.contactstatistics.get()


def stats_for_clicked_links():
    """GET https://api.mailjet.com/v3/REST/statistics/link-click"""
    cmp_id = get_valid_campaign_id()
    filters = {"CampaignId": cmp_id}
    return mailjet30.statistics_linkClick.get(filters=filters)


def mailbox_provider_statistics():
    """GET https://api.mailjet.com/v3/REST/statistics/recipient-esp"""
    cmp_id = get_valid_campaign_id()
    filters = {"CampaignId": cmp_id}
    return mailjet30.statistics_recipientEsp.get(filters=filters)


def geographical_statistics():
    """GET https://api.mailjet.com/v3/REST/geostatistics"""
    return mailjet30.geostatistics.get()


if __name__ == "__main__":
    functions = [
        event_based_vs_message_based_stats_timing,
        view_the_spread_of_events_over_time,
        statistics_for_specific_recipient,
        stats_for_clicked_links,
        mailbox_provider_statistics,
        geographical_statistics,
    ]

    for func in functions:
        print(f"\n=> Running: {func.__name__}()")
        try:
            result = func()
            status = getattr(result, "status_code", "N/A")
            print(f"Status Code: {status}")
            try:
                print(json.dumps(result.json(), indent=4))
            except (ValueError, AttributeError):
                print(getattr(result, "text", str(result)))
        except Exception as e:
            print(f"❌ Failed: {e}")
