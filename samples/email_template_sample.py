from __future__ import annotations

import os
import uuid
from typing import Any

from mailjet_rest import Client
from mailjet_rest.builders import MessageBuilder, SendPayloadBuilder, TemplateContentBuilder


def _get_client(version: str = "v3") -> Client:
    """Create a Mailjet Client lazily from environment credentials."""
    return Client(
        auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
        version=version,
    )


def create_a_template(client: Client | None = None) -> Any:
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
    return (client or _get_client()).template.create(data=data)


def create_a_template_detailcontent(template_id: int = 0, client: Client | None = None) -> Any:
    data = (
        TemplateContentBuilder()
        .set_content(
            html="<h3>Dear passenger, welcome to Mailjet!</h3><br />May the delivery force be with you!",
            text="Dear passenger, welcome to Mailjet! May the delivery force be with you!",
        )
        .build()
    )
    return (client or _get_client()).template_detailcontent.create(id=template_id, data=data)


def use_templates_with_send_api(client: Client | None = None) -> Any:
    message = (
        MessageBuilder()
        .set_sender("pilot@mailjet.com", "Mailjet Pilot")
        .add_recipient("passenger1@mailjet.com", "passenger 1")
        .set_subject("Your email flight plan!")
        .set_template(template_id=1, language_active=True)
    )
    payload = SendPayloadBuilder().add_message(message).set_sandbox_mode(True).build()
    return (client or _get_client("v3.1")).send.create(data=payload)


if __name__ == "__main__":
    if not os.environ.get("MJ_APIKEY_PUBLIC") or not os.environ.get("MJ_APIKEY_PRIVATE"):
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run this sample.")
        raise SystemExit(0)

    with _get_client("v3") as mailjet30, _get_client("v3.1") as mailjet31:
        try:
            res1 = create_a_template(client=mailjet30)
            print(f"create_a_template: {res1.status_code}")
            t_id = res1.json()["Data"][0]["ID"] if res1.status_code == 201 else 0

            for f, arg, cli in [
                (create_a_template_detailcontent, t_id, mailjet30),
                (use_templates_with_send_api, None, mailjet31),
            ]:
                try:
                    r = f(arg, client=cli) if arg is not None else f(client=cli)
                    print(f"{f.__name__}: {r.status_code if hasattr(r, 'status_code') else r}")
                except Exception as e:
                    print(f"{f.__name__} failed: {e}")
        except Exception as e:
            print(f"Failed: {e}")
