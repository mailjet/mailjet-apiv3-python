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


def create_your_segment():
    """POST https://api.mailjet.com/v3/REST/contactfilter"""
    data = {
        "Description": "Will send only to contacts under 35 years of age.",
        "Expression": "(age<35)",
        "Name": "Customers under 35",
    }
    return mailjet30.contactfilter.create(data=data)


def create_a_campaign_with_a_segmentation_filter():
    """POST https://api.mailjet.com/v3/REST/newsletter"""
    data = {
        "Title": "Mailjet greets every contact over 40",
        "Locale": "en_US",
        "Sender": "MisterMailjet",
        "SenderEmail": "Mister@mailjet.com",
        "Subject": "Greetings from Mailjet",
        "ContactsListID": "$ID_CONTACTLIST",
        "SegmentationID": "$ID_CONTACT_FILTER",
    }
    return mailjet30.newsletter.create(data=data)


if __name__ == "__main__":
    result = create_your_segment()
    print(result.status_code)
    try:
        print(json.dumps(result.json(), indent=4))
    except json.decoder.JSONDecodeError:
        print(result.text)
