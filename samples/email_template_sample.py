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


def create_a_template():
    """POST https://api.mailjet.com/v3/REST/template"""
    data = {
        "Author": "John Doe",
        "Categories": "array",
        "Copyright": "Mailjet",
        "Description": "Used to send out promo codes.",
        "EditMode": "1",
        "IsStarred": "false",
        "IsTextPartGenerationEnabled": "true",
        "Locale": "en_US",
        "Name": "Promo Codes",
        "OwnerType": "user",
        "Presets": "string",
        "Purposes": "array",
    }
    return mailjet30.template.create(data=data)


def create_a_template_detailcontent():
    """POST https://api.mailjet.com/v3/REST/template/$template_ID/detailcontent"""
    _id = "$template_ID"

    # Use TemplateContentBuilder to natively format Text-part/Html-part
    data = (
        TemplateContentBuilder()
        .set_content(
            html="<h3>Dear passenger, welcome to Mailjet!</h3><br />May the delivery force be with you!",
            text="Dear passenger, welcome to Mailjet! May the delivery force be with you!",
        )
        .build()
    )
    return mailjet30.template_detailcontent.create(id=_id, data=data)


def use_templates_with_send_api():
    """POST https://api.mailjet.com/v3.1/send"""
    message = (
        MessageBuilder()
        .set_sender("pilot@mailjet.com", "Mailjet Pilot")
        .add_recipient("passenger1@mailjet.com", "passenger 1")
        .set_subject("Your email flight plan!")
        .set_template(template_id=1, language_active=True)
    )

    payload = SendPayloadBuilder().add_message(message).build()

    return mailjet31.send.create(data=payload)


if __name__ == "__main__":
    result = create_a_template()
    print(f"Status Code: {result.status_code}")
    try:
        print(json.dumps(result.json(), indent=4))
    except ValueError:
        print(result.text)
