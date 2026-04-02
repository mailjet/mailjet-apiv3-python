import base64
import json
import logging
import os
from collections.abc import Callable

from mailjet_rest import Client

# Configure logging for the smoke test
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("mailjet_rest.client").setLevel(logging.DEBUG)
logging.basicConfig(format="%(levelname)s - %(message)s")

# Fetch credentials from environment variables
API_KEY = os.environ.get("MJ_APIKEY_PUBLIC", "")
API_SECRET = os.environ.get("MJ_APIKEY_PRIVATE", "")
BEARER_TOKEN = os.environ.get("MJ_CONTENT_TOKEN", "")

# Initialize clients for different API versions
mailjet_v3 = Client(auth=(API_KEY, API_SECRET))
mailjet_v3_1 = Client(auth=(API_KEY, API_SECRET), version="v3.1")
mailjet_v1 = Client(auth=BEARER_TOKEN or (API_KEY, API_SECRET), version="v1")


def run_test(test_name: str, func: Callable, expected_status: tuple[int, ...] = (200,)) -> None:
    """Wrapper that checks if the status code matches the expected one."""
    print(f"\n{'=' * 60}\n🚀 RUNNING: {test_name}\n{'=' * 60}")
    try:
        result = func()
        if getattr(result, "status_code", None) in expected_status:
            print(f"✅ SUCCESS (Status Code: {result.status_code})")
        else:
            print(f"❌ FAILED (Expected {expected_status}, got {getattr(result, 'status_code', None)})")

        try:
            print(json.dumps(result.json(), indent=2))
        except ValueError:
            print(f"Response Text: '{getattr(result, 'text', '')}'")
    except Exception as e:
        print(f"❌ Failed Exception: {type(e).__name__}: {e}")


def test_send_sandbox():
    """Test 1: Send API v3.1 (Sandbox)"""
    data = {
        "Messages": [
            {
                "From": {"Email": "pilot@mailjet.com", "Name": "Pilot"},
                "To": [{"Email": "passenger@mailjet.com"}],
                "Subject": "Smoke Test",
                "TextPart": "This is a live routing test.",
            }
        ],
        "SandboxMode": True,
    }
    return mailjet_v3_1.send.create(data=data)


def test_get_contacts():
    """Test 2: Email API v3 (Contacts)"""
    return mailjet_v3.contact.get(filters={"limit": 2})


def test_get_statistics():
    """Test 3: Email API v3 (Statistics)"""
    filters = {
        "CounterSource": "APIKey",
        "CounterTiming": "Message",
        "CounterResolution": "Lifetime",
    }
    return mailjet_v3.statcounters.get(filters=filters)


def test_parse_api():
    """Test 4: Email API v3 (Parse API)"""
    return mailjet_v3.parseroute.get(filters={"limit": 2})


def test_segmentation():
    """Test 5: Email API v3 (Segmentation)"""
    return mailjet_v3.contactfilter.get(filters={"limit": 2})


def test_content_api_templates():
    """Test 6: Content API v1 (Templates)"""
    return mailjet_v1.templates.get(filters={"limit": 2})


def test_content_api_images_negative():
    """Test 7: Negative test (verifies server validation for missing multipart)."""
    client_logger = logging.getLogger("mailjet_rest.client")
    previous_level = client_logger.level
    # Temporarily hide the "ERROR - API Error 400" log since we expect a failure
    client_logger.setLevel(logging.CRITICAL)
    try:
        data = {"name": "test.png", "image_data": "iVBORw0KGgo="}
        return mailjet_v1.data_images.create(data=data)
    finally:
        client_logger.setLevel(previous_level)


def test_content_api_images_real_upload():
    """Test 8: REAL file upload via multipart/form-data with mandatory metadata."""
    # 1x1 Transparent PNG in Base64
    b64_string = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
    image_bytes = base64.b64decode(b64_string)

    # Status must be "open" or "locked" according to the documentation
    metadata_json = '{"name": "smoke_test_logo.png", "Status": "open"}'

    files_payload = {
        "metadata": (None, metadata_json, "application/json"),
        "file": ("smoke_test_logo.png", image_bytes, "image/png"),
    }

    # Erase default JSON Content-Type to allow requests to build multipart boundaries
    return mailjet_v1.data_images.create(headers={"Content-Type": None}, files=files_payload)


if __name__ == "__main__":
    if not API_KEY or not API_SECRET:
        print("⚠️ MJ_APIKEY_PUBLIC and/or MJ_APIKEY_PRIVATE not found.")

    run_test("1. Send API v3.1 (Sandbox)", test_send_sandbox)
    run_test("2. Email API v3 (Contacts)", test_get_contacts)
    run_test("3. Email API v3 (Statistics)", test_get_statistics)
    run_test("4. Email API v3 (Parse API)", test_parse_api)
    run_test("5. Email API v3 (Segmentation)", test_segmentation)
    run_test("6. Content API v1 (Templates)", test_content_api_templates)

    # We only explicitly pass expected_status when it deviates from the (200,) default
    run_test("7. Content API v1 (Negative Upload)", test_content_api_images_negative, expected_status=(400,))
    run_test("8. Content API v1 (Real Multipart Upload)", test_content_api_images_real_upload, expected_status=(201,))
