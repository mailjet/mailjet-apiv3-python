import json
import logging
import os
import tempfile
import uuid
from pathlib import Path

from mailjet_rest.builders import MessageBuilder, SendPayloadBuilder, TemplateContentBuilder
from mailjet_rest import Client, ApiError, CriticalApiError, TimeoutError, DoesNotExistError

logging.getLogger("mailjet_rest.client").setLevel(logging.CRITICAL)

mailjet30 = Client(auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")))
mailjet31 = Client(
    auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")), version="v3.1"
)


def send_messages():
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
    return mailjet31.send.create(data=payload)


def send_messages_with_builder():
    with tempfile.TemporaryDirectory() as safe_dir:
        test_file = Path(safe_dir) / "flight_manifest.txt"
        test_file.write_text("Passenger: John Doe. Class: First. Status: Cleared.")
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
        return mailjet31.send.create(data=payload)


def retrieve_messages_from_campaign():
    # Dynamically fetch an active CampaignID
    cmp_res = mailjet30.campaign.get(filters={"Limit": 1})
    c_id = cmp_res.json()["Data"][0]["ID"] if cmp_res.status_code == 200 and cmp_res.json().get("Data") else 0
    return mailjet30.message.get(filters={"CampaignID": c_id})


def retrieve_message():
    # Dynamically fetch an active MessageID
    msg_res = mailjet30.message.get(filters={"Limit": 1})
    _id = msg_res.json()["Data"][0]["ID"] if msg_res.status_code == 200 and msg_res.json().get("Data") else 0
    if not _id:
        return msg_res
    return mailjet30.message.get(id=_id)


def view_message_history():
    # Dynamically fetch an active MessageID
    msg_res = mailjet30.message.get(filters={"Limit": 1})
    _id = msg_res.json()["Data"][0]["ID"] if msg_res.status_code == 200 and msg_res.json().get("Data") else 0
    if not _id:
        return msg_res
    return mailjet30.messagehistory.get(id=_id)


def retrieve_statistic():
    filters = {"CounterSource": "APIKey", "CounterTiming": "Message", "CounterResolution": "Lifetime"}
    return mailjet30.statcounters.get(filters=filters)


def setup_webhook():
    data = {"EventType": "open", "Url": f"https://www.mydomain.com/webhook_{uuid.uuid4().hex[:6]}", "Status": "alive"}

    # Mailjet only allows 1 webhook per EventType. Check if one already exists.
    get_webhook = mailjet30.eventcallbackurl.get(filters={"EventType": "open"})
    if get_webhook.status_code == 200 and get_webhook.json().get("Data"):
        w_id = get_webhook.json()["Data"][0]["ID"]
        return mailjet30.eventcallbackurl.update(id=w_id, data=data)

    return mailjet30.eventcallbackurl.create(data=data)


def setup_parse_api():
    data = {"Url": f"https://www.mydomain.com/mj_parse_{uuid.uuid4().hex[:6]}.php"}
    get_parse = mailjet30.parseroute.get()
    if get_parse.status_code == 200 and get_parse.json().get("Data"):
        p_id = get_parse.json()["Data"][0]["ID"]
        return mailjet30.parseroute.update(id=p_id, data=data)
    return mailjet30.parseroute.create(data=data)


def create_segmentation_filter():
    data = {
        "Description": "Test Filter",
        "Expression": "(age<35)",
        "Name": f"Customers under 35 {uuid.uuid4().hex[:6]}",
    }
    return mailjet30.contactfilter.create(data=data)


def manage_contacts_bulk():
    # Dynamically fetch an active ListID
    lists_res = mailjet30.contactslist.get(filters={"Limit": 1})
    if lists_res.status_code == 200 and lists_res.json().get("Data"):
        list_id = lists_res.json()["Data"][0]["ID"]
        data = {"Action": "addnoforce", "Contacts": [{"Email": "passenger1@mailjet.com"}]}
        return mailjet30.contactslist_managemanycontacts.create(id=list_id, data=data)
    return lists_res


def update_template_content():
    payload = (
        TemplateContentBuilder()
        .set_content(html="<h1>Welcome to the Flight!</h1>")
        .set_headers({"X-Custom-Header": "Flight-Update", "X-Priority": "1"})
        .build()
    )
    # Dynamically create a fresh template to ensure a valid ID exists
    t_res = mailjet30.template.create(
        data={"Name": f"Getting Started Template {uuid.uuid4().hex[:6]}", "Author": "Test", "EditMode": 1}
    )
    if t_res.status_code == 201:
        t_id = t_res.json()["Data"][0]["ID"]
        return mailjet30.template_detailcontent.create(id=t_id, data=payload)
    return t_res


if __name__ == "__main__":
    funcs = [
        send_messages,
        send_messages_with_builder,
        retrieve_messages_from_campaign,
        retrieve_message,
        view_message_history,
        retrieve_statistic,
        setup_webhook,
        setup_parse_api,
        create_segmentation_filter,
        manage_contacts_bulk,
        update_template_content,
    ]

    for f in funcs:
        try:
            r = f()
            print(f"{f.__name__}: {r.status_code if hasattr(r, 'status_code') else r}")
        except Exception as e:
            print(f"{f.__name__} failed: {e}")
