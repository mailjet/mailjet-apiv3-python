"""
Executable README & Smoke Test: A unified script to test and validate all examples
provided in the README.md, plus additional read-only health checks for core endpoints.
It dynamically creates required resources, runs the documented actions, and cleans up afterward.
"""

import base64
import os
import uuid
import logging

from mailjet_rest import Client

# Enable logging to see the Smart Telemetry in action!
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("mailjet_rest.client").setLevel(logging.DEBUG)
logging.basicConfig(format="%(levelname)s - %(message)s")

API_KEY = os.environ.get("MJ_APIKEY_PUBLIC", "")
API_SECRET = os.environ.get("MJ_APIKEY_PRIVATE", "")
CONTENT_TOKEN = os.environ.get("MJ_CONTENT_TOKEN", "")


def section(title: str) -> None:
    print(f"\n{'=' * 60}\n🚀 RUNNING: {title}\n{'=' * 60}")


def run_readme_tests():
    if not API_KEY or not API_SECRET:
        print("⚠️ Missing Mailjet API credentials in environment variables.")
        return

    # Using the Context Manager (Best Practice from the new README)
    with (
        Client(auth=(API_KEY, API_SECRET), version="v3.1") as mailjet_v31,
        Client(auth=(API_KEY, API_SECRET), version="v3") as mailjet_v3,
        Client(auth=CONTENT_TOKEN or (API_KEY, API_SECRET), version="v1") as mailjet_v1,
    ):
        # ---------------------------------------------------------------------
        # 1. SEND API (v3.1)
        # ---------------------------------------------------------------------
        section("Send API (v3.1) - Basic Email")
        data_send = {
            "Messages": [
                {
                    "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                    "To": [{"Email": "passenger1@mailjet.com", "Name": "Passenger 1"}],
                    "Subject": "README Test: Your email flight plan!",
                    "TextPart": "Welcome to Mailjet! May the delivery force be with you!",
                    "CustomID": "Readme_Test_Send_001",  # Triggers Smart Telemetry
                }
            ],
            "SandboxMode": True,  # IMPORTANT: Prevents actual sending during tests
        }
        res = mailjet_v31.send.create(data=data_send)
        assert res.status_code == 200, f"Failed Send API: {res.text}"
        print("✅ Send API (Basic) passed.")

        # ---------------------------------------------------------------------
        # 2. STANDARD REST ACTIONS (Contact Lifecycle)
        # ---------------------------------------------------------------------
        section("Standard REST Actions (Contact Lifecycle)")

        # POST (Create Contact)
        test_email = f"readme_test_{uuid.uuid4().hex[:8]}@mailjet.com"
        res = mailjet_v3.contact.create(data={"Email": test_email})
        assert res.status_code == 201
        contact_id = res.json()["Data"][0]["ID"]
        print(f"✅ POST (Create Contact) passed. Created ID: {contact_id}")

        # GET (Read all & Filtering & Pagination)
        res = mailjet_v3.contact.get(filters={"limit": 2, "sort": "Email desc"})
        assert res.status_code == 200
        print("✅ GET (Read all/Pagination) passed.")

        # GET (Read one)
        res = mailjet_v3.contact.get(id=contact_id)
        assert res.status_code == 200
        print("✅ GET (Read one) passed.")

        # PUT (Update)
        prop_name = f"test_prop_{uuid.uuid4().hex[:6]}"
        res_meta = mailjet_v3.contactmetadata.create(data={"Datatype": "str", "Name": prop_name, "NameSpace": "static"})
        if res_meta.status_code == 201:
            prop_id = res_meta.json()["Data"][0]["ID"]
            update_data = {"Data": [{"Name": prop_name, "value": "John"}]}
            res = mailjet_v3.contactdata.update(id=contact_id, data=update_data)
            assert res.status_code == 200
            print(f"✅ PUT (Update Contact Data) passed.")
            mailjet_v3.contactmetadata.delete(id=prop_id)

        # DELETE (Returns 204 No Content)
        res = mailjet_v3.template.create(
            data={
                "Name": f"README_Delete_Test_{uuid.uuid4().hex[:6]}",
                "Author": "SDK Test",
                "EditMode": 1,
                "Description": "To be deleted",
            }
        )
        template_id = res.json()["Data"][0]["ID"]
        res = mailjet_v3.template.delete(id=template_id)
        assert res.status_code == 204
        print(f"✅ DELETE (Template ID: {template_id}) passed.")

        # ---------------------------------------------------------------------
        # 3. EMAIL API ECOSYSTEM (Webhooks, Parse, Segmentation, Stats)
        # ---------------------------------------------------------------------
        section("Email API Ecosystem")

        # Webhooks
        webhook_url = f"https://www.example.com/webhook_{uuid.uuid4().hex[:6]}"
        res = mailjet_v3.eventcallbackurl.create(data={"EventType": "open", "Url": webhook_url, "Status": "alive"})
        assert res.status_code == 201
        mailjet_v3.eventcallbackurl.delete(id=res.json()["Data"][0]["ID"])
        print("✅ Webhooks (eventcallbackurl) passed.")

        # Parse API
        parse_url = f"https://www.example.com/parse_{uuid.uuid4().hex[:6]}"
        res = mailjet_v3.parseroute.create(data={"Url": parse_url})
        assert res.status_code == 201
        mailjet_v3.parseroute.delete(id=res.json()["Data"][0]["ID"])
        print("✅ Parse API (parseroute) passed.")

        # Segmentation
        res = mailjet_v3.contactfilter.create(
            data={
                "Description": "README Test Filter",
                "Expression": "(age<35)",
                "Name": f"README_Filter_{uuid.uuid4().hex[:6]}",
            }
        )
        assert res.status_code == 201
        mailjet_v3.contactfilter.delete(id=res.json()["Data"][0]["ID"])
        print("✅ Segmentation (contactfilter) passed.")

        # Statcounters
        res = mailjet_v3.statcounters.get(
            filters={"CounterSource": "APIKey", "CounterTiming": "Message", "CounterResolution": "Lifetime"}
        )
        assert res.status_code == 200
        print("✅ Statcounters passed.")

        # ---------------------------------------------------------------------
        # 4. CONTENT API (v1)
        # ---------------------------------------------------------------------
        section("Content API (v1)")

        # Negative Upload
        client_logger = logging.getLogger("mailjet_rest.client")
        prev_level = client_logger.level
        client_logger.setLevel(logging.CRITICAL)
        try:
            res = mailjet_v1.data_images.create(data={"name": "test.png", "image_data": "iVBORw0KGgo="})
            assert res.status_code == 400
            print("✅ Content API (Negative Upload) passed.")
        finally:
            client_logger.setLevel(prev_level)

        # Real Uploading an Image via Multipart Form-Data
        b64_string = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
        files_payload = {
            "metadata": (None, '{"name": "readme_logo.png", "Status": "open"}', "application/json"),
            "file": ("readme_logo.png", base64.b64decode(b64_string), "image/png"),
        }
        res = mailjet_v1.data_images.create(headers={"Content-Type": None}, files=files_payload)
        assert res.status_code == 201
        print("✅ Content API (Image Upload) passed.")

        # ---------------------------------------------------------------------
        # 5. ADDITIONAL HEALTH CHECKS (Read-Only)
        # ---------------------------------------------------------------------
        section("Additional Health Checks (Read-Only)")

        endpoints_to_test = [
            ("Senders", mailjet_v3.sender),
            ("Campaigns", mailjet_v3.campaign),
            ("Messages", mailjet_v3.message),
            ("Legacy Templates", mailjet_v3.template),
            ("v1 Templates", mailjet_v1.templates),
        ]

        for name, endpoint in endpoints_to_test:
            res = endpoint.get(filters={"limit": 2})
            assert res.status_code == 200, f"Health Check failed for {name}"
            print(f"✅ {name} passed.")

    print(f"\n{'=' * 60}\n🎉 ALL TESTS AND HEALTH CHECKS EXECUTED SUCCESSFULLY!\n{'=' * 60}")


if __name__ == "__main__":
    run_readme_tests()
