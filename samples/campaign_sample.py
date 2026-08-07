import json
import os

from mailjet_rest import Client
from mailjet_rest.builders import MessageBuilder, SendPayloadBuilder, TemplateContentBuilder

mailjet30 = Client(
    auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
)

mailjet31 = Client(
    auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
    version="v3.1",
)


def create_a_campaign_draft():
    """POST https://api.mailjet.com/v3/REST/campaigndraft"""
    data = {
        "Locale": "en_US",
        "Sender": "MisterMailjet",
        "SenderEmail": "Mister@mailjet.com",
        "Subject": "Greetings from Mailjet",
        "ContactsListID": "$ID_CONTACTSLIST",
        "Title": "Friday newsletter",
    }
    return mailjet30.campaigndraft.create(data=data)


def by_adding_custom_content():
    """POST https://api.mailjet.com/v3/REST/campaigndraft/$draft_ID/detailcontent"""
    _id = "$draft_ID"

    # Use TemplateContentBuilder to safely format Text-part and Html-part (CWE-400 protected)
    data = (
        TemplateContentBuilder()
        .set_headers({"X-Custom": "object"})
        .set_content(
            html="<h3>Dear passenger, welcome to Mailjet!</h3><br />May the delivery force be with you!",
            text="Dear passenger, welcome to Mailjet! May the delivery force be with you!",
        )
        .build()
    )
    return mailjet30.campaigndraft_detailcontent.create(id=_id, data=data)


def schedule_the_campaign():
    """POST https://api.mailjet.com/v3/REST/campaigndraft/$draft_ID/schedule"""
    _id = "$draft_ID"
    data = {"Date": "2018-01-01T00:00:00"}
    return mailjet30.campaigndraft_schedule.create(id=_id, data=data)


def send_the_campaign_right_away():
    """POST https://api.mailjet.com/v3/REST/campaigndraft/$draft_ID/send"""
    _id = "$draft_ID"
    return mailjet30.campaigndraft_send.create(id=_id)


def api_call_requirements():
    """POST https://api.mailjet.com/v3.1/send"""

    # Safely build the core message
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

    # The builder returns a standard dictionary, allowing developers to easily append
    # advanced routing properties like CustomCampaign directly before dispatch.
    message["CustomCampaign"] = "SendAPI_campaign"
    message["DeduplicateCampaign"] = True

    # Wrap it in the v3.1 payload wrapper
    payload = SendPayloadBuilder().add_message(message).build()

    return mailjet31.send.create(data=payload)


if __name__ == "__main__":
    result = create_a_campaign_draft()
    print(f"Status Code: {result.status_code}")
    try:
        print(json.dumps(result.json(), indent=4))
    except ValueError:
        print(result.text)
