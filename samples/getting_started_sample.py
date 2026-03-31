import json
import logging
import os

from mailjet_rest.client import ApiError, Client, CriticalApiError, TimeoutError

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
)


def send_messages():
    """POST https://api.mailjet.com/v3.1/send"""
    # fmt: off; pylint; noqa
    data = {
        "Messages": [
            {
                "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                "To": [{"Email": "passenger1@mailjet.com", "Name": "passenger 1"}],
                "Subject": "Your email flight plan!",
                "TextPart": "Dear passenger 1, welcome to Mailjet! May the "
                "delivery force be with you!",
                "HTMLPart": '<h3>Dear passenger 1, welcome to <a href="https'
                '://www.mailjet.com/">Mailjet</a>!<br />May the '
                "delivery force be with you!",
            },
        ],
        "SandboxMode": True,  # Remove to send real message.
    }
    # fmt: on; pylint; noqa
    return mailjet31.send.create(data=data)


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


if __name__ == "__main__":
    try:
        # We use send_messages() here as a safe, SandboxMode-enabled test
        result = send_messages()
        print(f"Status Code: {result.status_code}")

        try:
            print(json.dumps(result.json(), indent=4))
        except ValueError:  # Covers JSONDecodeError safely across Python versions
            print(result.text)

    # Demonstrate the new network exception handling
    except TimeoutError:
        print("The request to the Mailjet API timed out.")
    except CriticalApiError as e:
        print(f"Network connection failed: {e}")
    except ApiError as e:
        print(f"An unexpected Mailjet API error occurred: {e}")
