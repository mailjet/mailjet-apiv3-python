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
    data = {
        "Headers": "",
        "Html-part": "<h3>Dear passenger, welcome to Mailjet!</h3><br />May the delivery force be with you!",
        "MJMLContent": "",
        "Text-part": "Dear passenger, welcome to Mailjet! May the delivery force be with you!",
    }
    return mailjet30.template_detailcontent.create(id=_id, data=data)


def use_templates_with_send_api():
    """POST https://api.mailjet.com/v3.1/send"""
    data = {
        "Messages": [
            {
                "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                "To": [{"Email": "passenger1@mailjet.com", "Name": "passenger 1"}],
                "TemplateID": 1,
                "TemplateLanguage": True,
                "Subject": "Your email flight plan!",
            },
        ],
    }
    return mailjet31.send.create(data=data)


if __name__ == "__main__":
    result = create_a_template()
    print(result.status_code)
    try:
        print(json.dumps(result.json(), indent=4))
    except json.decoder.JSONDecodeError:
        print(result.text)
