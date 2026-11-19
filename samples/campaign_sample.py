from __future__ import annotations

import datetime
import os
import uuid
from typing import Any

from mailjet_rest import Client
from mailjet_rest.builders import MessageBuilder, SendPayloadBuilder, TemplateContentBuilder


def _get_client(version: str = "v3") -> Client:
    """Create a Mailjet Client lazily from environment credentials."""
    return Client(
        auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
        version=version,
    )


def create_a_campaign_draft(client: Client | None = None) -> Any:
    """POST https://api.mailjet.com/v3/REST/campaigndraft"""
    active_client = client or _get_client()

    # 1. Fetch a validated & active sender
    sender_res = active_client.sender.get(filters={"Limit": 1, "Status": "Active"})
    sender_email = (
        sender_res.json()["Data"][0]["Email"]
        if sender_res.status_code == 200 and sender_res.json().get("Data")
        else "Mister@mailjet.com"
    )

    # 2. Create a new contact list dynamically
    list_res = active_client.contactslist.create(data={"Name": f"Campaign Test List {uuid.uuid4().hex[:6]}"})
    list_id = list_res.json()["Data"][0]["ID"] if list_res.status_code == 201 else 0

    if list_id:
        # 3. Create the contact in the global contact list first so listrecipient can resolve it
        contact_email = f"test+{uuid.uuid4().hex[:6]}@mailjet.com"
        active_client.contact.create(data={"Email": contact_email})
        active_client.listrecipient.create(data={"ContactAlt": contact_email, "ListID": list_id})

    data = {
        "Locale": "en_US",
        "Sender": "MisterMailjet",
        "SenderEmail": sender_email,
        "Subject": "Greetings from Mailjet",
        "ContactsListID": list_id,
        "Title": "Friday newsletter",
    }
    return active_client.campaigndraft.create(data=data)


def by_adding_custom_content(draft_id: int = 0, client: Client | None = None) -> Any:
    data = (
        TemplateContentBuilder()
        .set_headers({"X-Custom": "object"})
        .set_content(
            html="<h3>Dear passenger, welcome to Mailjet!</h3><br />May the delivery force be with you!",
            text="Dear passenger, welcome to Mailjet! May the delivery force be with you!",
        )
        .build()
    )
    return (client or _get_client()).campaigndraft_detailcontent.create(id=draft_id, data=data)


def schedule_the_campaign(draft_id: int = 0, client: Client | None = None) -> Any:
    future_date = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    data = {"Date": future_date}
    return (client or _get_client()).campaigndraft_schedule.create(id=draft_id, data=data)


def send_the_campaign_right_away(draft_id: int = 0, client: Client | None = None) -> Any:
    return (client or _get_client()).campaigndraft_send.create(id=draft_id)


def api_call_requirements(client: Client | None = None) -> Any:
    message = (
        MessageBuilder()
        .set_sender("pilot@mailjet.com", "Mailjet Pilot")
        .add_recipient("passenger1@mailjet.com", "passenger 1")
        .set_subject("Your email flight plan!")
        .set_content(
            text="Dear passenger 1, welcome to Mailjet! May the delivery force be with you!",
            html='<h3>Dear passenger 1, welcome to <a href="https://www.mailjet.com/">Mailjet</a>!</h3><br />May the delivery force be with you!',
        )
    ).build()
    message["CustomCampaign"] = "SendAPI_campaign"
    message["DeduplicateCampaign"] = True
    payload = SendPayloadBuilder().add_message(message).set_sandbox_mode(True).build()
    return (client or _get_client("v3.1")).send.create(data=payload)


if __name__ == "__main__":
    if not os.environ.get("MJ_APIKEY_PUBLIC") or not os.environ.get("MJ_APIKEY_PRIVATE"):
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run this sample.")
        raise SystemExit(0)

    with _get_client("v3") as mailjet30, _get_client("v3.1") as mailjet31:
        d_id1 = 0
        try:
            res1 = create_a_campaign_draft(client=mailjet30)
            print(f"create_a_campaign_draft: {res1.status_code}")
            d_id1 = res1.json()["Data"][0]["ID"] if res1.status_code == 201 else 0
        except Exception as e:
            print(f"create_a_campaign_draft failed: {e}")

        try:
            res_content = by_adding_custom_content(d_id1, client=mailjet30)
            print(f"by_adding_custom_content: {res_content.status_code}")
        except Exception as e:
            print(f"by_adding_custom_content failed: {e}")

        try:
            res_sched = schedule_the_campaign(d_id1, client=mailjet30)
            print(f"schedule_the_campaign: {res_sched.status_code}")
        except Exception as e:
            print(f"schedule_the_campaign failed: {e}")

        try:
            res2 = create_a_campaign_draft(client=mailjet30)
            d_id2 = res2.json()["Data"][0]["ID"] if res2.status_code == 201 else 0
            by_adding_custom_content(d_id2, client=mailjet30)
            res_send = send_the_campaign_right_away(d_id2, client=mailjet30)
            print(f"send_the_campaign_right_away: {res_send.status_code}")
        except Exception as e:
            print(f"send_the_campaign_right_away failed: {e}")

        try:
            res_api = api_call_requirements(client=mailjet31)
            print(f"api_call_requirements: {res_api.status_code}")
        except Exception as e:
            print(f"api_call_requirements failed: {e}")
