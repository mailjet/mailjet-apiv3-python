import json
import logging
import os
import tempfile
from pathlib import Path

from mailjet_rest.builders import MessageBuilder, TemplateContentBuilder
from mailjet_rest import Client, ApiError, CriticalApiError, TimeoutError, DoesNotExistError
from mailjet_rest.types import SendV31Payload, SendV31Message

# Optional: Enable built-in SDK logging to see request/response details
logging.getLogger("mailjet_rest.client").setLevel(logging.DEBUG)
logging.basicConfig(format="%(levelname)s - %(name)s - %(message)s")

mailjet30 = Client(
    auth=(
        os.environ.get("MJ_APIKEY_PUBLIC", ""),
        os.environ.get("MJ_APIKEY_PRIVATE", ""),
    ),
)

mailjet31 = Client(
    auth=(
        os.environ.get("MJ_APIKEY_PUBLIC", ""),
        os.environ.get("MJ_APIKEY_PRIVATE", ""),
    ),
    version="v3.1",
    # Don't send real messages in samples
    # dry_run=True,
)


def send_messages():
    """POST https://api.mailjet.com/v3.1/send"""
    # fmt: off; pylint; noqa
    message: SendV31Message = {
        "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
        "To": [{"Email": "passenger1@mailjet.com", "Name": "passenger 1"}],
        "Subject": "Your email flight plan!",
        "TextPart": "Dear passenger 1, welcome to Mailjet! May the delivery force be with you!",
        "HTMLPart": '<h3>Dear passenger 1, welcome to <a href="https://www.mailjet.com/">Mailjet</a>!<br />May the delivery force be with you!</h3>',
    }
    payload: SendV31Payload = {
        "Messages": [message],
        "SandboxMode": True,  # Remove to send real message.
    }
    # fmt: on; pylint; noqa
    return mailjet31.send.create(data=payload)


def send_messages_with_builder():
    """POST https://api.mailjet.com/v3.1/send"""

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
            .attach_file(test_file, safe_base_dir=safe_dir)
            .build()
        )

        payload: SendV31Payload = {
            "Messages": [message],
            "SandboxMode": True,
        }
        return mailjet31.send.create(data=payload)


def retrieve_messages_from_campaign():
    """GET https://api.mailjet.com/v3/REST/message?CampaignID=$CAMPAIGNID"""
    filters = {
        "CampaignID": "*****",  # Put real ID to make it work.
    }
    return mailjet30.message.get(filters=filters)


def retrieve_message():
    """GET https://api.mailjet.com/v3/REST/message/$MESSAGE_ID"""
    _id = "*****************"  # Put real ID to make it work.
    return mailjet30.message.get(id=_id)


def view_message_history():
    """GET https://api.mailjet.com/v3/REST/messagehistory/$MESSAGE_ID"""
    _id = "*****************"  # Put real ID to make it work.
    return mailjet30.messagehistory.get(id=_id)


def retrieve_statistic():
    """GET https://api.mailjet.com/v3/REST/statcounters?CounterSource=APIKey
    \\&CounterTiming=Message\\&CounterResolution=Lifetime
    """
    filters = {
        "CounterSource": "APIKey",
        "CounterTiming": "Message",
        "CounterResolution": "Lifetime",
    }
    return mailjet30.statcounters.get(filters=filters)


def setup_webhook():
    """POST https://api.mailjet.com/v3/REST/eventcallbackurl"""
    data = {
        "EventType": "open",
        "Url": "https://www.mydomain.com/webhook",
        "Status": "alive",
    }
    return mailjet30.eventcallbackurl.create(data=data)


def setup_parse_api():
    """POST https://api.mailjet.com/v3/REST/parseroute"""
    data = {"Url": "https://www.mydomain.com/mj_parse.php"}
    return mailjet30.parseroute.create(data=data)


def create_segmentation_filter():
    """POST https://api.mailjet.com/v3/REST/contactfilter"""
    data = {
        "Description": "Will send only to contacts under 35 years of age.",
        "Expression": "(age<35)",
        "Name": "Customers under 35",
    }
    return mailjet30.contactfilter.create(data=data)


def manage_contacts_bulk():
    """
    POST /REST/contactslist/{id}/managemanycontacts
    Demonstrates O(1) route resolution with URI template interpolation.
    """
    data = {"Action": "addnoforce", "Contacts": [{"Email": "passenger1@mailjet.com"}]}
    # The SDK automatically interpolates '123' into the registry path
    return mailjet30.contactslist_managemanycontacts.create(id=123, data=data)


# Example 2: Content API Template Management
def update_template_content():
    """
    POST /REST/templates/{id}/contents
    Demonstrates the new TemplateContentBuilder with fail-fast validation.
    """
    builder = TemplateContentBuilder()
    payload = (
        builder.set_content(html="<h1>Welcome to the Flight!</h1>")
        .set_headers({"X-Custom-Header": "Flight-Update", "X-Priority": "1"})
        .build()
    )

    try:
        # Resolves to v1/REST/templates/999/contents
        return mailjet30.templates_contents.create(id=999, data=payload)
    except DoesNotExistError:
        print("⚠️ Resource 999 not found. Please verify the Template ID exists.")
        return None


if __name__ == "__main__":
    try:
        print("Running Template Content Update...")
        res = update_template_content()
        print(f"Status Code: {res.status_code}")

        # We use send_messages() here as a safe, SandboxMode-enabled test
        result = send_messages()
        print(f"1. Status Code: {result.status_code}")

        try:
            print(json.dumps(result.json(), indent=4))
        except ValueError:
            print(result.text)

        result_with_builder = send_messages_with_builder()
        print(f"2. Status Code: {result_with_builder.status_code}")

        try:
            print(json.dumps(result_with_builder.json(), indent=4))
        except ValueError:
            print(result_with_builder.text)

    except TimeoutError:
        print("The request timed out. Please check your network or increase the timeout.")
    except CriticalApiError as e:
        print(f"Failed to connect to the Mailjet API: {e}")
    except ApiError as e:
        print(f"An unexpected Mailjet API error occurred: {e}")
