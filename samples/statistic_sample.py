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


def event_based_vs_message_based_stats_timing():
    """GET https://api.mailjet.com/v3/REST/statcounters"""
    filters = {
        "SourceId": "$Campaign_ID",
        "CounterSource": "Campaign",
        "CounterTiming": "Message",
        "CounterResolution": "Lifetime",
    }
    return mailjet30.statcounters.get(filters=filters)


def view_the_spread_of_events_over_time():
    """GET https://api.mailjet.com/v3/REST/statcounters"""
    filters = {
        "SourceId": "$Campaign_ID",
        "CounterSource": "Campaign",
        "CounterTiming": "Event",
        "CounterResolution": "Day",
        "FromTS": "123",
        "ToTS": "456",
    }
    return mailjet30.statcounters.get(filters=filters)


def statistics_for_specific_recipient():
    """GET https://api.mailjet.com/v3/REST/contactstatistics"""
    return mailjet30.contactstatistics.get()


def stats_for_clicked_links():
    """GET https://api.mailjet.com/v3/REST/statistics/link-click"""
    filters = {"CampaignId": "$Campaign_ID"}
    return mailjet30.statistics_linkClick.get(filters=filters)


def mailbox_provider_statistics():
    """GET https://api.mailjet.com/v3/REST/statistics/recipient-esp"""
    filters = {"CampaignId": "$Campaign_ID"}
    return mailjet30.statistics_recipientEsp.get(filters=filters)


def geographical_statistics():
    """GET https://api.mailjet.com/v3/REST/geostatistics"""
    return mailjet30.geostatistics.get()


if __name__ == "__main__":
    result = geographical_statistics()
    print(result.status_code)
    try:
        print(json.dumps(result.json(), indent=4))
    except json.decoder.JSONDecodeError:
        print(result.text)
