import os
import uuid

from mailjet_rest import Client
from mailjet_rest.builders import MessageBuilder, SendPayloadBuilder, TemplateContentBuilder

mailjet30 = Client(auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")))
mailjet31 = Client(
    auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")), version="v3.1"
)


def create_a_template():
    data = {
        "Author": "John Doe",
        "Categories": ["newsletter"],
        "Copyright": "Mailjet",
        "Description": "Used to send out promo codes.",
        "EditMode": 1,
        "IsStarred": False,
        "IsTextPartGenerationEnabled": True,
        "Locale": "en_US",
        "Name": f"Promo Codes {uuid.uuid4().hex[:6]}",
        "OwnerType": "user",
        "Purposes": ["marketing"],
    }
    return mailjet30.template.create(data=data)


def create_a_template_detailcontent(template_id=0):
    data = (
        TemplateContentBuilder()
        .set_content(
            html="<h3>Dear passenger, welcome to Mailjet!</h3><br />May the delivery force be with you!",
            text="Dear passenger, welcome to Mailjet! May the delivery force be with you!",
        )
        .build()
    )
    return mailjet30.template_detailcontent.create(id=template_id, data=data)


def use_templates_with_send_api():
    message = (
        MessageBuilder()
        .set_sender("pilot@mailjet.com", "Mailjet Pilot")
        .add_recipient("passenger1@mailjet.com", "passenger 1")
        .set_subject("Your email flight plan!")
        .set_template(template_id=1, language_active=True)
    )
    payload = SendPayloadBuilder().add_message(message).set_sandbox_mode(True).build()
    return mailjet31.send.create(data=payload)


if __name__ == "__main__":
    try:
        res1 = create_a_template()
        print(f"create_a_template: {res1.status_code}")
        t_id = res1.json()["Data"][0]["ID"] if res1.status_code == 201 else 0

        for f, arg in [
            (create_a_template_detailcontent, t_id),
            (use_templates_with_send_api, None),
        ]:
            try:
                r = f(arg) if arg is not None else f()
                print(f"{f.__name__}: {r.status_code if hasattr(r, 'status_code') else r}")
            except Exception as e:
                print(f"{f.__name__} failed: {e}")
    except Exception as e:
        print(f"Failed: {e}")
