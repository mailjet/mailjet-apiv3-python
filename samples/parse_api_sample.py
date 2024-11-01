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


def basic_setup():
    """POST https://api.mailjet.com/v3/REST/parseroute"""
    data = {"Url": "https://www.mydomain.com/mj_parse.php"}
    return mailjet30.parseroute.create(data=data)


if __name__ == "__main__":
    result = basic_setup()
    print(result.status_code)
    try:
        print(json.dumps(result.json(), indent=4))
    except json.decoder.JSONDecodeError:
        print(result.text)
