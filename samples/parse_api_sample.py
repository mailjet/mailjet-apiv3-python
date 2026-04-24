import json
import os

from mailjet_rest import Client

mailjet30 = Client(
    auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
)


def basic_setup():
    """POST https://api.mailjet.com/v3/REST/parseroute"""
    data = {"Url": "https://www.mydomain.com/mj_parse.php"}
    return mailjet30.parseroute.create(data=data)


if __name__ == "__main__":
    result = basic_setup()
    print(f"Status Code: {result.status_code}")
    try:
        print(json.dumps(result.json(), indent=4))
    except ValueError:
        print(result.text)
