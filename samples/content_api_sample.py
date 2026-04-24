import json
import os

from mailjet_rest import Client

# 1. Generate token using Basic Auth
auth_client = Client(
    auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
    version="v1",
)


def generate_token():
    """POST https://api.mailjet.com/v1/REST/token"""
    data = {"Name": "Sample Access Token", "Permissions": ["read_template", "create_template", "create_image"]}
    return auth_client.token.create(data=data)


# 2. Use the generated Bearer token for Content API operations
# Replace this with your actual generated token
BEARER_TOKEN = os.environ.get("MJ_CONTENT_TOKEN", "your_generated_token_here")
content_client = Client(auth=BEARER_TOKEN, version="v1")


def upload_image():
    """POST https://api.mailjet.com/v1/data/images"""
    data = {
        "name": "sample_logo.png",
        "image_data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
    }
    return content_client.data_images.create(data=data)


if __name__ == "__main__":
    # result = generate_token()
    result = upload_image()
    print(f"Status Code: {result.status_code}")
    try:
        print(json.dumps(result.json(), indent=4))
    except ValueError:
        print(result.text)
