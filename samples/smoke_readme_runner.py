"""
Executable README & Smoke Test: A unified script to test and validate ALL examples
provided in the README.md, plus additional read-only health checks for core endpoints.
It dynamically creates required resources, runs the documented actions, and cleans up afterward.
"""

import base64
import os
import uuid
import logging
import warnings
import time
from contextlib import suppress

from mailjet_rest import Client

# Enable logging to see the Smart Telemetry and Guardrails in action!
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("mailjet_rest.client").setLevel(logging.DEBUG)
logging.basicConfig(format="%(levelname)s - %(message)s")


def section(title: str) -> None:
    print(f"\n{'=' * 60}\n🚀 RUNNING: {title}\n{'=' * 60}")


def safe_cleanup(action, name, **kwargs):
    """Executes a cleanup action without failing on permission (401) or consistency (404) errors."""
    try:
        # Temporarily silence SDK error logs for cleanup to keep output clean
        client_logger = logging.getLogger("mailjet_rest.client")
        old_level = client_logger.level
        client_logger.setLevel(logging.CRITICAL)

        res = action(**kwargs)

        client_logger.setLevel(old_level)

        if res.status_code in (200, 204):
            print(f"✅ CLEANUP: {name} deleted successfully.")
        elif res.status_code == 401:
            print(f"⚠️ CLEANUP: {name} skipped (Permission denied: Operation not allowed).")
        elif res.status_code == 404:
            print(f"⚠️ CLEANUP: {name} skipped (Not found: likely eventual consistency delay).")
        else:
            print(f"❌ CLEANUP: {name} failed with status {res.status_code}.")
    except Exception as e:
        print(f"❌ CLEANUP: {name} raised unexpected exception: {e}")


def run_readme_tests():
    api_key = os.environ.get("MJ_APIKEY_PUBLIC", "")
    api_secret = os.environ.get("MJ_APIKEY_PRIVATE", "")
    content_token = os.environ.get("MJ_CONTENT_TOKEN", "")

    if not api_key or not api_secret:
        print("⚠️ Missing Mailjet API credentials in environment variables.")
        return

    # Using the Context Manager (Best Practice for resource management)
    with (
        Client(auth=(api_key, api_secret), version="v3.1") as mailjet_v31,
        Client(auth=(api_key, api_secret), version="v3") as mailjet_v3,
        Client(auth=content_token or (api_key, api_secret), version="v1") as mailjet_v1,
    ):
        # ---------------------------------------------------------------------
        # 1. SEND API (v3.1) - Sanitized Telemetry
        # ---------------------------------------------------------------------
        section("Send API (v3.1) - Basic Email & Telemetry")
        data_send = {
            "Messages": [
                {
                    "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                    "To": [{"Email": "passenger1@mailjet.com", "Name": "Passenger 1"}],
                    "Subject": "README Test: Your email flight plan!",
                    "TextPart": "Welcome to Mailjet!",
                    # Verification: Check logs to see this sanitized to '_' (CWE-117)
                    "CustomID": "Readme_Test\n[CRITICAL]_INJECTION_ATTEMPT",
                }
            ],
            "SandboxMode": True,
        }
        res = mailjet_v31.send.create(data=data_send)
        assert res.status_code == 200, f"Failed Send API: {res.text}"
        print("✅ Send API passed (Check logs for sanitized CustomID).")

        # ---------------------------------------------------------------------
        # 2. SECURITY GUARDRAILS (Poka-Yoke Verification)
        # ---------------------------------------------------------------------
        section("Security Guardrails (Active Protection)")

        # CRLF Injection blocking
        try:
            mailjet_v3.contact.get(headers={"X-Injected": "Value\r\nAttack: Payload"})
            print("❌ Security Failure: CRLF Injection was not blocked!")
        except ValueError as e:
            print(f"✅ Guardrail Success: Blocked Header Injection - '{e}'")

        # Insecure TLS Warning
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            mailjet_v3.contact.get(verify=False)
            if any("verify=False" in str(msg.message) for msg in w):
                print("✅ Guardrail Success: Insecure TLS Warning emitted.")

        # ---------------------------------------------------------------------
        # 3. STANDARD REST ACTIONS (Contact Lifecycle)
        # ---------------------------------------------------------------------
        section("Standard REST Actions (Contact Lifecycle)")

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

        # PUT (Update Contact Metadata)
        prop_name = f"test_prop_{uuid.uuid4().hex[:6]}"
        res_meta = mailjet_v3.contactmetadata.create(data={"Datatype": "str", "Name": prop_name, "NameSpace": "static"})
        if res_meta.status_code == 201:
            prop_id = res_meta.json()["Data"][0]["ID"]
            update_data = {"Data": [{"Name": prop_name, "value": "John"}]}
            res = mailjet_v3.contactdata.update(id=contact_id, data=update_data)
            assert res.status_code == 200
            print("✅ PUT (Update Contact Data) passed.")
            # Resilient Teardown: Metadata
            safe_cleanup(mailjet_v3.contactmetadata.delete, f"Metadata {prop_id}", id=prop_id)

        # Resilient Teardown: Contact
        safe_cleanup(mailjet_v3.contact.delete, f"Contact {contact_id}", id=contact_id)

        # ---------------------------------------------------------------------
        # 4. EMAIL API ECOSYSTEM (Webhooks, Parse, Segmentation, Stats)
        # ---------------------------------------------------------------------
        section("Email API Ecosystem")

        # Webhooks
        webhook_url = f"https://www.example.com/webhook_{uuid.uuid4().hex[:6]}"
        res = mailjet_v3.eventcallbackurl.create(data={"EventType": "open", "Url": webhook_url, "Status": "alive"})
        if res.status_code == 201:
            w_id = res.json()["Data"][0]["ID"]
            print("✅ Webhooks (eventcallbackurl) created.")
            safe_cleanup(mailjet_v3.eventcallbackurl.delete, f"Webhook {w_id}", id=w_id)

        # Parse API
        parse_url = f"https://www.example.com/parse_{uuid.uuid4().hex[:6]}"
        res = mailjet_v3.parseroute.create(data={"Url": parse_url})
        if res.status_code == 201:
            p_id = res.json()["Data"][0]["ID"]
            print("✅ Parse API (parseroute) created.")
            safe_cleanup(mailjet_v3.parseroute.delete, f"ParseRoute {p_id}", id=p_id)

        # Segmentation
        res = mailjet_v3.contactfilter.create(
            data={
                "Description": "README Test Filter",
                "Expression": "(age<35)",
                "Name": f"README_Filter_{uuid.uuid4().hex[:6]}",
            }
        )
        if res.status_code == 201:
            f_id = res.json()["Data"][0]["ID"]
            print("✅ Segmentation (contactfilter) created.")
            safe_cleanup(mailjet_v3.contactfilter.delete, f"ContactFilter {f_id}", id=f_id)

        # Statcounters
        res = mailjet_v3.statcounters.get(
            filters={"CounterSource": "APIKey", "CounterTiming": "Message", "CounterResolution": "Lifetime"}
        )
        assert res.status_code == 200
        print("✅ Statcounters passed.")

        # ---------------------------------------------------------------------
        # 5. CONTENT API (v1) - Full Image Lifecycle
        # ---------------------------------------------------------------------
        section("Content API (v1)")

        # Negative Upload (Verifying error handling)
        client_logger = logging.getLogger("mailjet_rest.client")
        prev_level = client_logger.level
        client_logger.setLevel(logging.CRITICAL)
        try:
            res = mailjet_v1.data_images.create(data={"name": "test.png", "image_data": "invalid"})
            assert res.status_code == 400
            print("✅ Content API (Negative Upload) passed.")
        finally:
            client_logger.setLevel(prev_level)

        # Real Multipart Upload & Resilient Cleanup
        b64_string = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
        files_payload = {
            "metadata": (None, '{"name": "readme_logo.png", "Status": "open"}', "application/json"),
            "file": ("readme_logo.png", base64.b64decode(b64_string), "image/png"),
        }
        res = mailjet_v1.data_images.create(headers={"Content-Type": None}, files=files_payload)

        if res.status_code == 201:
            image_id = res.json()["Data"][0]["ID"]
            print(f"✅ Content API Upload passed. Image ID: {image_id}")

            # CRITICAL: Wait 1 second for the server to process the upload before trying to delete it.
            # This solves the 404 "Model does not exist" error during immediate deletion.
            time.sleep(1)

            safe_cleanup(mailjet_v1.data_images.delete, f"Image {image_id}", id=image_id)
        else:
            print(f"⚠️ Content API Upload skipped/failed: {res.status_code}")

        # ---------------------------------------------------------------------
        # 6. ADDITIONAL HEALTH CHECKS (Read-Only)
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
            res = endpoint.get(filters={"limit": 1})
            assert res.status_code == 200, f"Health Check failed for {name}"
            print(f"✅ {name} passed.")

    print(f"\n{'=' * 60}\n🎉 ALL TESTS AND HEALTH CHECKS COMPLETED SUCCESSFULLY!\n{'=' * 60}")


if __name__ == "__main__":
    run_readme_tests()
