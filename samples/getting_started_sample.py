from __future__ import annotations

import logging
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any

from mailjet_rest import Client
from mailjet_rest.builders import MessageBuilder, SendPayloadBuilder, TemplateContentBuilder


logging.getLogger("mailjet_rest.client").setLevel(logging.CRITICAL)


def _get_client(version: str = "v3") -> Client:
    """Create a Mailjet Client lazily from environment credentials."""
    return Client(
        auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
        version=version,
    )


def send_messages(client: Client | None = None) -> Any:
    message = (
        MessageBuilder()
        .set_sender("pilot@mailjet.com", "Mailjet Pilot")
        .add_recipient("passenger1@mailjet.com", "passenger 1")
        .set_subject("Your email flight plan!")
        .set_content(
            text="Dear passenger 1, welcome to Mailjet! May the delivery force be with you!",
            html='<h3>Dear passenger 1, welcome to <a href="https://www.mailjet.com/">Mailjet</a>!<br />May the delivery force be with you!</h3>',
        )
    )
    payload = SendPayloadBuilder().add_message(message).set_sandbox_mode(True).build()
    return (client or _get_client("v3.1")).send.create(data=payload)


def send_messages_with_builder(client: Client | None = None) -> Any:
    with tempfile.TemporaryDirectory() as safe_dir:
        test_file = Path(safe_dir) / "flight_manifest.txt"
        test_file.write_text("Passenger: John Doe. Class: First. Status: Cleared.", encoding="utf-8")
        message = (
            MessageBuilder()
            .set_sender("pilot@mailjet.com", "Mailjet Pilot")
            .add_recipient("passenger1@mailjet.com", "passenger 1")
            .add_cc("copilot@mailjet.com", "Co-Pilot")
            .set_reply_to("support@mailjet.com")
            .set_subject("Your email flight plan!")
            .set_content(
                text="Dear passenger, welcome to Mailjet!",
                html="<h3>Welcome to <a href='https://www.mailjet.com/'>Mailjet</a>!</h3>",
            )
            .attach_file(test_file, base_dir=safe_dir)
        )
        payload = SendPayloadBuilder().add_message(message).set_sandbox_mode(True).build()
        return (client or _get_client("v3.1")).send.create(data=payload)


def retrieve_messages_from_campaign(client: Client | None = None) -> Any:
    active_client = client or _get_client("v3")
    cmp_res = active_client.campaign.get(filters={"Limit": 1})
    c_id = cmp_res.json()["Data"][0]["ID"] if cmp_res.status_code == 200 and cmp_res.json().get("Data") else 0
    return active_client.message.get(filters={"CampaignID": c_id})


def retrieve_message(client: Client | None = None) -> Any:
    active_client = client or _get_client("v3")
    msg_res = active_client.message.get(filters={"Limit": 1})
    _id = msg_res.json()["Data"][0]["ID"] if msg_res.status_code == 200 and msg_res.json().get("Data") else 0
    if not _id:
        return msg_res
    return active_client.message.get(id=_id)


def view_message_history(client: Client | None = None) -> Any:
    active_client = client or _get_client("v3")
    msg_res = active_client.message.get(filters={"Limit": 1})
    _id = msg_res.json()["Data"][0]["ID"] if msg_res.status_code == 200 and msg_res.json().get("Data") else 0
    if not _id:
        return msg_res
    return active_client.messagehistory.get(id=_id)


def retrieve_statistic(client: Client | None = None) -> Any:
    filters = {"CounterSource": "APIKey", "CounterTiming": "Message", "CounterResolution": "Lifetime"}
    return (client or _get_client("v3")).statcounters.get(filters=filters)


def setup_webhook(client: Client | None = None) -> Any:
    active_client = client or _get_client("v3")
    data = {"EventType": "open", "Url": f"https://www.mydomain.com/webhook_{uuid.uuid4().hex[:6]}", "Status": "alive"}

    # Mailjet only allows 1 webhook per EventType. Check if one already exists.
    get_webhook = active_client.eventcallbackurl.get(filters={"EventType": "open"})
    if get_webhook.status_code == 200 and get_webhook.json().get("Data"):
        w_id = get_webhook.json()["Data"][0]["ID"]
        return active_client.eventcallbackurl.update(id=w_id, data=data)

    return active_client.eventcallbackurl.create(data=data)


def setup_parse_api(client: Client | None = None) -> Any:
    active_client = client or _get_client("v3")
    data = {"Url": f"https://www.mydomain.com/mj_parse_{uuid.uuid4().hex[:6]}.php"}
    get_parse = active_client.parseroute.get()
    if get_parse.status_code == 200 and get_parse.json().get("Data"):
        p_id = get_parse.json()["Data"][0]["ID"]
        return active_client.parseroute.update(id=p_id, data=data)
    return active_client.parseroute.create(data=data)


def create_segmentation_filter(client: Client | None = None) -> Any:
    data = {
        "Description": "Test Filter",
        "Expression": "(age<35)",
        "Name": f"Customers under 35 {uuid.uuid4().hex[:6]}",
    }
    return (client or _get_client("v3")).contactfilter.create(data=data)


def manage_contacts_bulk(client: Client | None = None) -> Any:
    active_client = client or _get_client("v3")
    lists_res = active_client.contactslist.get(filters={"Limit": 1})
    if lists_res.status_code == 200 and lists_res.json().get("Data"):
        list_id = lists_res.json()["Data"][0]["ID"]
        data = {"Action": "addnoforce", "Contacts": [{"Email": "passenger1@mailjet.com"}]}
        return active_client.contactslist_managemanycontacts.create(id=list_id, data=data)
    return lists_res


def update_template_content(client: Client | None = None) -> Any:
    active_client = client or _get_client("v3")
    payload = (
        TemplateContentBuilder()
        .set_content(html="<h1>Welcome to the Flight!</h1>")
        .set_headers({"X-Custom-Header": "Flight-Update", "X-Priority": "1"})
        .build()
    )
    # Dynamically create a fresh template to ensure a valid ID exists
    t_res = active_client.template.create(
        data={"Name": f"Getting Started Template {uuid.uuid4().hex[:6]}", "Author": "Test", "EditMode": 1}
    )
    if t_res.status_code == 201:
        t_id = t_res.json()["Data"][0]["ID"]
        return active_client.template_detailcontent.create(id=t_id, data=payload)
    return t_res


if __name__ == "__main__":
    if not os.environ.get("MJ_APIKEY_PUBLIC") or not os.environ.get("MJ_APIKEY_PRIVATE"):
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run this sample.")
        raise SystemExit(0)

    with _get_client("v3") as mailjet30, _get_client("v3.1") as mailjet31:
        steps: list[tuple[Any, Client]] = [
            (send_messages, mailjet31),
            (send_messages_with_builder, mailjet31),
            (retrieve_messages_from_campaign, mailjet30),
            (retrieve_message, mailjet30),
            (view_message_history, mailjet30),
            (retrieve_statistic, mailjet30),
            (setup_webhook, mailjet30),
            (setup_parse_api, mailjet30),
            (create_segmentation_filter, mailjet30),
            (manage_contacts_bulk, mailjet30),
            (update_template_content, mailjet30),
        ]

        for f, cli in steps:
            try:
                r = f(client=cli)
                print(f"{f.__name__}: {r.status_code if hasattr(r, 'status_code') else r}")
            except Exception as e:
                print(f"{f.__name__} failed: {e}")
