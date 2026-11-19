from __future__ import annotations

import os
import uuid
from typing import Any

from mailjet_rest import Client


def _get_client() -> Client:
    """Create a Mailjet v3 Client lazily from environment credentials."""
    return Client(auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")))


def create_your_segment(client: Client | None = None) -> Any:
    unique_name = f"Customers under 35 {uuid.uuid4().hex[:6]}"
    data = {
        "Description": "Will send only to contacts under 35 years of age.",
        "Expression": "(age<35)",
        "Name": unique_name,
    }
    return (client or _get_client()).contactfilter.create(data=data)


def create_a_campaign_with_a_segmentation_filter(segmentation_id: int = 0, client: Client | None = None) -> Any:
    data = {
        "Title": "Mailjet greets every contact over 40",
        "Locale": "en_US",
        "Sender": "MisterMailjet",
        "SenderEmail": "Mister@mailjet.com",
        "Subject": "Greetings from Mailjet",
        "ContactsListID": 0,
        "SegmentationID": segmentation_id,
    }
    return (client or _get_client()).campaigndraft.create(data=data)


if __name__ == "__main__":
    if not os.environ.get("MJ_APIKEY_PUBLIC") or not os.environ.get("MJ_APIKEY_PRIVATE"):
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run this sample.")
        raise SystemExit(0)

    with _get_client() as mailjet30:
        try:
            res1 = create_your_segment(client=mailjet30)
            print(f"create_your_segment: {res1.status_code}")
            seg_id = res1.json()["Data"][0]["ID"] if res1.status_code == 201 else 0

            res2 = create_a_campaign_with_a_segmentation_filter(seg_id, client=mailjet30)
            print(f"create_a_campaign_with_a_segmentation_filter: {res2.status_code}")
        except Exception as e:
            print(f"Failed: {e}")
