import json
import os

from mailjet_rest import Client

mailjet30 = Client(
    auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
)


def basic_setup():
    """POST / PUT https://api.mailjet.com/v3/REST/parseroute"""
    data = {"Url": "https://www.mydomain.com/mj_parse.php"}

    # 1. Mailjet allows only one default parseroute per API Key.
    # We must check if one already exists to prevent the MJ18 Conflict error.
    get_resp = mailjet30.parseroute.get()

    if get_resp.status_code == 200 and get_resp.json().get("Data"):
        # 2. If it exists, grab the ID and update the existing route
        route_id = get_resp.json()["Data"][0]["ID"]
        return mailjet30.parseroute.update(id=route_id, data=data)

    # 3. Otherwise, safely create a new one
    return mailjet30.parseroute.create(data=data)


if __name__ == "__main__":
    result = basic_setup()
    print(f"Status Code: {result.status_code}")
    try:
        print(json.dumps(result.json(), indent=4))
    except ValueError:
        print(result.text)
