#!/usr/bin/env python3
"""Mailjet Enhanced Fuzzer Seed Harvester
Harvests successful AND error-case payloads to seed the fuzzing corpus.
"""

import json
import os
from pathlib import Path
from typing import Any

import requests


# Mailjet specific authentication environment variables
API_KEY_PUBLIC = os.environ.get("MJ_APIKEY_PUBLIC")
API_KEY_PRIVATE = os.environ.get("MJ_APIKEY_PRIVATE")

BASE_URL_V3 = "https://api.mailjet.com/v3/REST"
BASE_URL_V3_1 = "https://api.mailjet.com/v3.1"
BASE_URL_V1 = "https://api.mailjet.com/v1/REST"

# Schema-aware targets based on Mailjet API documentation
TARGETS: list[dict[str, Any]] = [
    # ----------------------------------------------------
    # V3.1 SEND API TARGETS (Complex deeply-nested JSON)
    # ----------------------------------------------------
    {
        "method": "POST",
        "name": "send_v31_post",
        "url": f"{BASE_URL_V3_1}/send",
        "json": {
            "Messages": [
                {
                    "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                    "To": [{"Email": "passenger1@mailjet.com", "Name": "passenger 1"}],
                    "Subject": "Your email flight plan!",
                    "TextPart": "Dear passenger 1, welcome to Mailjet!",
                    "CustomID": "AppGettingStartedTest"
                }
            ]
        }
    },
    {
        "method": "POST",
        "name": "send_v31_error_post",
        "url": f"{BASE_URL_V3_1}/send",
        "json": {
            "Messages": [
                {
                    # Intentional Error: Missing required 'To' field to trigger 400 validation error
                    "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                    "Subject": "Malicious schema test"
                }
            ]
        }
    },
    # ----------------------------------------------------
    # V3 REST API TARGETS (Resource Lookups & Pagination)
    # ----------------------------------------------------
    {
        "method": "GET",
        "name": "contact_get",
        "url": f"{BASE_URL_V3}/contact",
        "params": {"limit": 5}
    },
    {
        "method": "GET",
        "name": "message_get",
        "url": f"{BASE_URL_V3}/message",
        "params": {"limit": 10}
    },
    {
        "method": "GET",
        "name": "campaign_get",
        "url": f"{BASE_URL_V3}/campaign",
    },
    {
        "method": "GET",
        "name": "sender_get",
        "url": f"{BASE_URL_V3}/sender",
    },
    {
        "method": "GET",
        "name": "user_get",
        "url": f"{BASE_URL_V3}/user",
    },
    {
        "method": "GET",
        "name": "apikey_get",
        "url": f"{BASE_URL_V3}/apikey",
    },
    {
        "method": "GET",
        "name": "webhook_get",
        "url": f"{BASE_URL_V3}/webhook",
    },
    # ----------------------------------------------------
    # V3 REST API TARGETS (Complex POST/PUT Operations)
    # ----------------------------------------------------
    {
        "method": "POST",
        "name": "contact_managemanycontacts_post",
        "url": f"{BASE_URL_V3}/contact/managemanycontacts",
        "json": {
            "Action": "addnoforce",
            "Contacts": [{"Email": "fuzz-contact@example.com"}]
        }
    },
    {
        "method": "POST",
        "name": "contactslist_post",
        "url": f"{BASE_URL_V3}/contactslist",
        "json": {"Name": "Fuzz Test List"}
    },
    {
        "method": "POST",
        "name": "campaigndraft_post",
        "url": f"{BASE_URL_V3}/campaigndraft",
        "json": {
            "Locale": "en_US",
            "Sender": "pilot@mailjet.com",
            "SenderName": "Pilot",
            "Subject": "Fuzz Campaign",
            "Title": "Fuzz Draft"
        }
    },
    {
        "method": "POST",
        "name": "template_post",
        "url": f"{BASE_URL_V3}/template",
        "json": {
            "Name": "Fuzz Template",
            "Author": "Fuzzer",
            "Purposes": ["transactional"]
        }
    },
    {
        "method": "PUT",
        "name": "template_detailcontent_put",
        # Note: 999999 will likely 404, feeding our error parser the exact JSON error schema
        "url": f"{BASE_URL_V3}/template/999999/detailcontent",
        "json": {
            "Headers": {"Reply-To": "fuzz@mailjet.com"},
            "Html-part": "<html>Fuzz</html>"
        }
    },
    {
        "method": "POST",
        "name": "parseroute_post",
        "url": f"{BASE_URL_V3}/parseroute",
        "json": {
            "Url": "https://fuzz-target.example.com/webhook"
        }
    },
    # ----------------------------------------------------
    # V3 REST API TARGETS (Statistics & Analytics)
    # ----------------------------------------------------
    {
        "method": "GET",
        "name": "statcounters_get",
        "url": f"{BASE_URL_V3}/statcounters",
        "params": {"CounterSource": "APIKey", "CounterTiming": "Message"}
    },
    {
        "method": "GET",
        "name": "bouncestatistics_get",
        "url": f"{BASE_URL_V3}/bouncestatistics"
    },
    {
        "method": "GET",
        "name": "clickstatistics_get",
        "url": f"{BASE_URL_V3}/clickstatistics"
    },
    {
        "method": "GET",
        "name": "domainstatistics_get",
        "url": f"{BASE_URL_V3}/domainstatistics"
    },
    # ----------------------------------------------------
    # V1 CONTENT API TARGETS (Tokens & Labels)
    # ----------------------------------------------------
    {
        "method": "GET",
        "name": "tokens_get",
        "url": f"{BASE_URL_V1}/tokens"
    },
    {
        "method": "GET",
        "name": "labels_get",
        "url": f"{BASE_URL_V1}/labels"
    }
]

# Map specific API targets to their respective fuzzer corpus directories
CORPUS_MAP: dict[str, list[str]] = {
    "fuzz_endpoint": [
        "contact_get", "message_get", "campaign_get", "sender_get",
        "user_get", "apikey_get", "webhook_get", "statcounters_get",
        "bouncestatistics_get", "clickstatistics_get", "domainstatistics_get",
        "tokens_get", "labels_get"
    ],
    "fuzz_builder": [
        # Gives the fluent builders native schema constraints to mutate against
        "send_v31_post", "template_post", "campaigndraft_post"
    ],
    "fuzz_structure_aware": [
        # Provides deep JSON trees for the structured mutator to traverse
        "send_v31_post", "contact_managemanycontacts_post", "parseroute_post", "template_detailcontent_put"
    ],
    "fuzz_error_parser": [
        # Allows the error parser to learn from actual Mailjet 400/404 payloads
        "send_v31_error_post", "template_detailcontent_put"
    ],
    "fuzz_pagination_stream": [
        # Feeds the lazy-eval generator fuzzer actual list arrays returned by the API
        "contact_get", "message_get", "campaign_get"
    ]
}


def harvest_seeds() -> None:
    if not API_KEY_PUBLIC or not API_KEY_PRIVATE:
        print("❌ Error: MJ_APIKEY_PUBLIC or MJ_APIKEY_PRIVATE environment variables are missing.")
        print("💡 Hint: Set them via `export MJ_APIKEY_PUBLIC=your_key` and `export MJ_APIKEY_PRIVATE=your_secret`")
        return

    auth = (API_KEY_PUBLIC, API_KEY_PRIVATE)
    headers = {"Content-Type": "application/json"}

    for target in TARGETS:
        method = target.get("method", "GET")
        url = target["url"]
        print(f"📡 Harvesting {method} {url}...")

        try:
            # Capture data to force various API responses (Success vs Error)
            if method in ("POST", "PUT"):
                # requests.request allows dynamic execution of both POST and PUT methods safely
                resp = requests.request(
                    method, url, auth=auth, headers=headers, json=target.get("json"), timeout=10
                )
            else:
                resp = requests.get(
                    url, auth=auth, params=target.get("params"), timeout=10
                )

            # Save the raw JSON payload
            # We save the status code in the filename so the fuzzer learns
            # to distinguish between success and error schemas
            try:
                parsed_json = resp.json()
            except ValueError:
                print(f"  ⚠️ Warning: Non-JSON response for {target['name']} (HTTP {resp.status_code})")
                parsed_json = {"raw_text": resp.text}

            payload = json.dumps(parsed_json, indent=2).encode("utf-8")

            for folder, target_names in CORPUS_MAP.items():
                if target["name"] in target_names:
                    dir_path = Path("tests") / "fuzz" / "corpus" / folder
                    dir_path.mkdir(parents=True, exist_ok=True)

                    filename = f"{resp.status_code}_{target['name']}.json"
                    file_path = dir_path / filename
                    file_path.write_bytes(payload)

                    print(f"  ✅ Saved {filename} to {folder}")

        except requests.exceptions.RequestException as e:
            print(f"  ❌ Network Failure {target['name']}: {e}")
        except Exception as e:
            print(f"  ❌ Unhandled Error {target['name']}: {e}")


if __name__ == "__main__":
    harvest_seeds()
