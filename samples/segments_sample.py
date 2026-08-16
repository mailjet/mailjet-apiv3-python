import json
import os
import uuid

from mailjet_rest import Client

mailjet30 = Client(auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")))


def create_your_segment():
    unique_name = f"Customers under 35 {uuid.uuid4().hex[:6]}"
    data = {
        "Description": "Will send only to contacts under 35 years of age.",
        "Expression": "(age<35)",
        "Name": unique_name,
    }
    return mailjet30.contactfilter.create(data=data)


def create_a_campaign_with_a_segmentation_filter(segmentation_id=0):
    data = {
        "Title": "Mailjet greets every contact over 40",
        "Locale": "en_US",
        "Sender": "MisterMailjet",
        "SenderEmail": "Mister@mailjet.com",
        "Subject": "Greetings from Mailjet",
        "ContactsListID": 0,
        "SegmentationID": segmentation_id,
    }
    return mailjet30.newsletter.create(data=data)


if __name__ == "__main__":
    try:
        res1 = create_your_segment()
        print(f"create_your_segment: {res1.status_code}")
        seg_id = res1.json()["Data"][0]["ID"] if res1.status_code == 201 else 0

        res2 = create_a_campaign_with_a_segmentation_filter(seg_id)
        print(f"create_a_campaign_with_a_segmentation_filter: {res2.status_code}")
    except Exception as e:
        print(f"Failed: {e}")
