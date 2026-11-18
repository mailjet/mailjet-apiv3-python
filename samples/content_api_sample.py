import base64
import json
import os
import uuid

from mailjet_rest import Client

# Authenticate and optionally generate token
auth_client = Client(
    auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
    version="v1",
)


def generate_token():
    """POST https://api.mailjet.com/v1/REST/tokens using a unique name to prevent 409 Conflict."""
    unique_name = f"Sample Access Token {uuid.uuid4().hex[:6]}"
    data = {
        "Name": unique_name,
        "Permissions": ["read_template", "create_template", "create_image"],
    }
    return auth_client.tokens.create(data=data)


def upload_image():
    """POST https://api.mailjet.com/v1/data/images via multipart/form-data"""
    b64_string = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
    image_bytes = base64.b64decode(b64_string)

    files_payload = {
        "Metadata": (None, json.dumps({"Name": "sample_logo.png", "Status": "open"}), "application/json"),
        "file": ("sample_logo.png", image_bytes, "image/png"),
    }

    # Note: 'Content-Type: None' is explicitly passed to override the SDK's default `application/json`
    # header, allowing the 'requests' library to auto-generate the multipart boundary.
    return content_client.data_images.create(headers={"Content-Type": None}, files=files_payload)


def list_v1_templates():
    """GET https://api.mailjet.com/v1/REST/templates via `v1_templates` route."""
    return content_client.v1_templates.get()


def publish_template_contents(template_id: int):
    """POST https://api.mailjet.com/v1/REST/templates/{id}/contents/publish."""
    return content_client.template_contents_publish.create(id=template_id)


def unlock_template_contents(template_id: int):
    """POST https://api.mailjet.com/v1/REST/templates/{id}/contents/unlock."""
    return content_client.template_contents_unlock.create(id=template_id)


def get_image_by_type(image_id: int, content_type: str = "image:png"):
    """GET https://api.mailjet.com/v1/data/images/{id}/{content_type}."""
    return content_client.data_images_by_type.get(id=image_id, action_id=content_type)


if __name__ == "__main__":
    bearer_token = os.environ.get("MJ_CONTENT_TOKEN")
    if not bearer_token:
        token_resp = generate_token()
        print(f"Status Code: {token_resp.status_code}")
        bearer_token = token_resp.json()["Data"][0]["AccessToken"]
        print(f"\nSuccessfully generated bearer token: {bearer_token[:10]}...")

    content_client = Client(auth=bearer_token, version="v1")

    try:
        result = upload_image()
        print(f"Status Code: {result.status_code}")
        try:
            print(json.dumps(result.json(), indent=4))
        except ValueError:
            print(result.text)
    except Exception as e:
        print(f"Error during image upload: {e}")
        if hasattr(e, "response") and e.response is not None:
            print(e.response.text)
