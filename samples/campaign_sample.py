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
    data = {
        "Headers": "object",
        "Html-part": "<h3>Dear passenger, welcome to Mailjet!</h3><br />May the delivery force be with you!",
        "MJMLContent": "",
        "Text-part": "Dear passenger, welcome to Mailjet! May the delivery force be with you!",
    }
    return mailjet30.campaigndraft_detailcontent.create(id=_id, data=data)


def test_your_campaign():
    """POST https://api.mailjet.com/v3/REST/campaigndraft/$draft_ID/test"""
    _id = "$draft_ID"
    data = {"Recipients": [{"Email": "passenger@mailjet.com", "Name": "Passenger 1"}]}
    return mailjet30.campaigndraft_test.create(id=_id, data=data)


def schedule_the_sending():
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
    # fmt: off
    data = {
        "Messages": [
            {
                "From": {
                    "Email": "pilot@mailjet.com",
                    "Name": "Mailjet Pilot"},
                "To": [
                    {
                        "Email": "passenger1@mailjet.com",
                        "Name": "passenger 1"}],
                "Subject": "Your email flight plan!",
                "TextPart": "Dear passenger 1, welcome to Mailjet! May the delivery force be with you!",
                "HTMLPart": "<h3>Dear passenger 1, welcome to <a "
                            "href=\"https://www.mailjet.com/\">Mailjet</a>!</h3><br />May the delivery force be with "
                            "you!",
                "CustomCampaign": "SendAPI_campaign",
                "DeduplicateCampaign": True}]}
    # fmt: on
    return mailjet31.send.create(data=data)


if __name__ == "__main__":
    result = create_a_campaign_draft()
    print(result.status_code)
    try:
        print(json.dumps(result.json(), indent=4))
    except json.decoder.JSONDecodeError:
        print(result.text)
