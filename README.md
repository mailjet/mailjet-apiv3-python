![alt text](https://www.mailjet.com/images/email/transac/logo_header.png "Mailjet")

# Official Mailjet Python Wrapper

[![PyPI Version](https://img.shields.io/github/v/release/mailjet/mailjet-apiv3-python)](https://img.shields.io/github/v/release/mailjet/mailjet-apiv3-python)
[![GitHub Release](https://img.shields.io/github/v/release/mailjet/mailjet-apiv3-python)](https://img.shields.io/github/v/release/mailjet/mailjet-apiv3-python)
[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://github.com/mailjet/mailjet-apiv3-python)
[![License](https://img.shields.io/github/license/mailjet/mailjet-apiv3-python)](https://github.com/mailjet/mailjet-apiv3-python/blob/master/LICENSE)
[![PyPI Downloads](https://img.shields.io/pypi/dm/mailjet-rest)](https://img.shields.io/pypi/dm/mailjet-rest)
[![Build Status](https://img.shields.io/github/actions/workflow/status/mailjet/mailjet-apiv3-python/commit_checks.yaml)](https://github.com/mailjet/mailjet-apiv3-python)
[![GitHub Stars](https://img.shields.io/github/stars/mailjet/mailjet-apiv3-python)](https://img.shields.io/github/stars/mailjet/mailjet-apiv3-python)
[![GitHub Issues](https://img.shields.io/github/issues/mailjet/mailjet-apiv3-python)](https://img.shields.io/github/issues/mailjet/mailjet-apiv3-python)
[![GitHub PRs](https://img.shields.io/github/issues-pr/mailjet/mailjet-apiv3-python)](https://img.shields.io/github/issues-pr/mailjet/mailjet-apiv3-python)

## Table of contents

- [Overview](#overview)
- [Compatibility](#compatibility)
- [Requirements](#requirements)
  - [Test dependencies](#test-dependencies)
- [Installation](#installation)
  - [pip install](#pip-install)
    - [git clone & pip install locally](#git-clone--pip-install-locally)
    - [conda & make](#conda--make)
  - [For development](#for-development)
    - [Using conda](#using-conda)
- [Authentication](#authentication)
- [Quick Start](#quick-start)
  - [Advanced Configuration](#advanced-configuration)
    - [API Versioning](#api-versioning)
    - [Base URL](#base-url)
- [Usage](#usage)
  - [Error Handling](#error-handling)
- [Logging & Debugging](#logging--debugging)
  - [IDE Autocompletion & DX](#ide-autocompletion--dx)
  - [URL path](#url-path)
- [Request examples](#request-examples)
  - [Full list of supported endpoints](#full-list-of-supported-endpoints)
  - [Send API (v3.1)](#send-api-v31)
    - [Send a basic email](#send-a-basic-email)
  - [Send an email using a Mailjet Template](#send-an-email-using-a-mailjet-template)
  - [Standard REST Actions (GET, POST, PUT, DELETE)](#standard-rest-actions-get-post-put-delete)
    - [POST (Create)](#post-create)
    - [GET Request](#get-request)
    - [PUT (Update / Patch specific fields)](#put-update--patch-specific-fields)
    - [DELETE (Returns 204 No Content)](#delete-returns-204-no-content)
  - [Email API Ecosystem (Webhooks, Parse API, Segmentation, Stats)](#email-api-ecosystem-webhooks-parse-api-segmentation-stats)
  - [Content API](#content-api)
- [Deprecation Warnings](#deprecation-warnings)
- [Type Hinting](#type-hinting)
- [License](#license)
- [Contribute](#contribute)
- [Contributors](#contributors)

## Overview

Welcome to the [Mailjet] official Python API wrapper!

Check out all the resources and Python code examples in the official [Mailjet Documentation][doc].

## Compatibility

This library `mailjet_rest` officially supports the following Python versions:

- Python >= 3.10, < 3.15

## Requirements

- **Build backend:** `setuptools`, `wheel`, `setuptools-scm`
- **Runtime:** `requests >= 2.32.5`

### Test dependencies

For running test you need `pytest >=7.0.0` at least.
Make sure to provide the environment variables from [Authentication](#authentication).

## Installation

### pip install

Create a virtual environment and install the wrapper:

```bash
python -m venv venv
source venv/bin/activate
pip install mailjet-rest
```

#### git clone & pip install locally

Use the below code to install the wrapper locally by cloning this repository:

```bash
git clone https://github.com/mailjet/mailjet-apiv3-python
cd mailjet-apiv3-python
```

```bash
pip install .
```

#### conda & make

Use the below code to install it locally by `conda` and `make` on Unix platforms:

```bash
make install
```

### For development

#### Using conda

on Linux or macOS:

- A basic environment with a minimum number of dependencies:

```bash
make dev
conda activate mailjet
```

- A full dev environment:

```bash
make dev-full
conda activate mailjet-dev
```

## Authentication

The Mailjet Email API uses your API and Secret keys for authentication. [Grab][api_credential] and save your Mailjet API credentials securely in your environment variables.

```bash
export MJ_APIKEY_PUBLIC='your api key'  # pragma: allowlist secret
export MJ_APIKEY_PRIVATE='your api secret'  # pragma: allowlist secret
export MJ_CONTENT_TOKEN='your_bearer_token' # Optional, for Content API v1
```

## Quick Start

**Best Practice**: Use the [Mailjet] `Client` as a Context Manager (`with` statement) to automatically pool and close underlying TCP connections, preventing resource leaks.

```python
import os
from mailjet_rest import Client

api_key = os.environ.get("MJ_APIKEY_PUBLIC", "")
api_secret = os.environ.get("MJ_APIKEY_PRIVATE", "")

with Client(auth=(api_key, api_secret), version="v3.1") as mailjet:
    data = {
        "Messages": [
            {
                "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                "To": [{"Email": "passenger1@mailjet.com", "Name": "Passenger 1"}],
                "Subject": "Your email flight plan!",
                "TextPart": "Welcome to Mailjet! May the delivery force be with you!",
            }
        ]
    }
    result = mailjet.send.create(data=data)
    print(result.status_code)
```

(Note:

> **Note**
> If you choose not to use the context manager, you should manually call mailjet.close() when your application shuts down).

### Advanced Configuration

You can pass configuration overrides directly when initializing the `Client` or during individual API calls:

```python
# Set custom base URL, timeout, and API version
mailjet = Client(auth=(api_key, api_secret), version="v3.1", api_url="https://api.us.mailjet.com/", timeout=30)

# Override timeout for a single, heavy request
result = mailjet.contact.get(timeout=60)
```

#### API Versioning

The Mailjet API is spread among distinct versions:

- `v3` - The Email API
- `v3.1` - Email Send API v3.1, which is the latest version of our Send API
- `v1` - Content API (Templates, Blocks, Images)

Since most Email API endpoints are located under `v3`, it is set as the default one and does not need to be specified when making your request.
For the others you need to specify the version using `version`. For example, if using Send API `v3.1`:

```python
mailjet = Client(auth=(api_key, api_secret), version="v3.1")
```

For additional information refer to our [API Reference](https://dev.mailjet.com/reference/overview/versioning/).

#### Base URL

The default base domain name for the Mailjet API is `api.mailjet.com`. You can modify this base URL by setting a value for `api_url` in your call:

```python
mailjet = Client(auth=(api_key, api_secret), api_url="https://api.us.mailjet.com/")
```

If your account has been moved to Mailjet's **US architecture**, the URL value you need to set is `https://api.us.mailjet.com`.

## Usage

### Error Handling

The client safely wraps network-level exceptions. Standard HTTP errors (like `404 Not Found` or `400 Bad Request`) **do not** raise exceptions; they return the `requests.Response` object directly so you can inspect `status_code` and `.json()`.

```python
from mailjet_rest import CriticalApiError, TimeoutError, ApiError

try:
    result = mailjet.contact.get()
    if result.status_code != 200:
        print(f"API Error: {result.status_code} - {result.text}")

except TimeoutError:
    print("The request to the Mailjet API timed out.")
except CriticalApiError as e:
    print(f"Network connection failed: {e}")
```

## Logging & Debugging

The SDK integrates seamlessly with Python's standard `logging` library and features **Smart Telemetry**.
If you pass identifiers like `CustomID`, `Campaign`, or `TemplateID` in your payload, the SDK automatically extracts them and injects a `Trace` context into your logs.
This allows you to easily correlate local application errors with your Mailjet Dashboard analytics.

```python
import logging
from mailjet_rest import Client

logging.getLogger("mailjet_rest.client").setLevel(logging.DEBUG)
logging.basicConfig(format="%(levelname)s - %(message)s")

with Client(auth=(api_key, api_secret), version="v3.1") as mailjet:
    # Adding 'CustomID' enables Smart Tracing in the console logs
    mailjet.send.create(
        data={
            "Messages": [
                {
                    "From": {"Email": "test@test.com"},
                    "To": [{"Email": "user@test.com"}],
                    "CustomID": "Promo_Black_Friday",
                }
            ]
        }
    )
```

_Console output will feature_: `DEBUG - Sending Request: POST ... | Trace: [CustomID=Promo_Black_Friday]`

### IDE Autocompletion & DX

Because the SDK utilizes dynamic URL dispatching (`__getattr__`), to prevent "Magic Method Traps" (accidentally dispatching internal Python methods), the SDK includes strict _poka-yoke_ guardrails.
Attempting to access private attributes or removed properties (like `client.auth`) will safely throw an explicit `AttributeError` instead of a ghost API request.

### URL path

According to python special characters limitations we can't use slashes `/` and dashes `-` which is acceptable for URL path building. Instead, python client uses another way for path building. You should replace slashes `/` by underscore `_` and dashes `-` by capitalizing next letter in path.
For example, to reach `statistics/link-click` path you should call `statistics_linkClick` attribute of python client.

```python
# GET `statistics/link-click`
mailjet = Client(auth=(api_key, api_secret))
filters = {"CampaignId": "xxxxxxx"}
result = mailjet.statistics_linkClick.get(filters=filters)
print(result.status_code)
print(result.json())
```

For the **Content API (v1)**, sub-actions will be correctly routed using slashes (e.g. contents/lock). Additionally, the SDK maps the `data_images` resource specifically to `/v1/data/images` to support media uploads.

```python
# GET '/v1/data/images'
mailjet = Client(auth=(api_key, api_secret), version="v1")
result = mailjet.data_images.get()
```

## Request examples

### Full list of supported endpoints

> [!IMPORTANT]\
> This is a full list of supported endpoints this wrapper provides [samples](samples)

### Executable README (Smoke Test)

Want to test all these examples at once? We provide an executable script that dynamically creates, tests, and safely cleans up all resources mentioned in this document.
It's a great way to verify your API credentials and network access.

Simply run:

```bash
python samples/smoke_readme_runner.py
```

### Send API (v3.1)

#### Send a basic email

```python
from mailjet_rest import Client
import os

api_key = os.environ.get("MJ_APIKEY_PUBLIC", "")
api_secret = os.environ.get("MJ_APIKEY_PRIVATE", "")
mailjet = Client(auth=(api_key, api_secret), version="v3.1")

data = {
    "Messages": [
        {
            "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
            "To": [{"Email": "passenger1@mailjet.com", "Name": "Passenger 1"}],
            "Subject": "Your email flight plan!",
            "TextPart": "Dear passenger 1, welcome to Mailjet!",
            "HTMLPart": "<h3>Dear passenger 1, welcome to Mailjet!</h3>",
        }
    ]
}
result = mailjet.send.create(data=data)
print(result.status_code)
print(result.json())
```

### Send an email using a Mailjet Template

When using `TemplateLanguage`, ensure that you pass a standard Python dictionary to the `Variables` parameter.

```python
mailjet = Client(auth=(api_key, api_secret), version="v3.1")

data = {
    "Messages": [
        {
            "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
            "To": [{"Email": "passenger1@mailjet.com", "Name": "passenger 1"}],
            "TemplateID": 1234567,  # Put your actual Template ID here
            "TemplateLanguage": True,
            "Subject": "Your email flight plan!",
            "Variables": {"name": "John Doe", "custom_data": "Welcome aboard!"},
        }
    ]
}
result = mailjet.send.create(data=data)
```

### Standard REST Actions (GET, POST, PUT, DELETE)

#### POST (Create)

##### Simple POST request

```python
# Create a new contact
data = {"Email": "Mister@mailjet.com"}
result = mailjet.contact.create(data=data)
print(result.json())
```

##### Using actions

```python
# Manage the subscription status of a contact to multiple lists
id_ = "$ID"
data = {
    "ContactsLists": [
        {"ListID": "$ListID_1", "Action": "addnoforce"},
        {"ListID": "$ListID_2", "Action": "addforce"},
    ]
}
result = mailjet.contact_managecontactslists.create(id=id_, data=data)
print(result.json())
```

#### GET Request

##### Retrieve all objects

```python
# Retrieve all contacts
result = mailjet.contact.get()
print(result.json())
```

##### GET (Read one)

```python
# Retrieve a specific contact ID
id_ = "Contact_ID"
result = mailjet.contact.get(id=id_)
print(result.json())
```

##### Using filtering

```python
# Retrieve contacts that are not in the campaign exclusion list
filters = {
    "limit": 40,
    "offset": 50,
    "sort": "Email desc",
    "IsExcludedFromCampaigns": "false",
}
result = mailjet.contact.get(filters=filters)
print(result.json())
```

##### Using pagination

Some requests (for example [GET /contact](https://dev.mailjet.com/email/reference/contacts/contact/#v3_get_contact)) has `limit`, `offset` and `sort` query string parameters. These parameters could be used for pagination.
`limit` `int` Limit the response to a select number of returned objects. Default value: `10`. Maximum value: `1000`
`offset` `int` Retrieve a list of objects starting from a certain offset. Combine this query parameter with `limit` to retrieve a specific section of the list of objects. Default value: `0`
`sort` `str` Sort the results by a property and select ascending (ASC) or descending (DESC) order. The default order is ascending. Keep in mind that this is not available for all properties. Default value: `ID asc`
Next example returns 40 contacts starting from 51th record sorted by `Email` field descendally:

```python
filters = {
    "limit": 40,
    "offset": 50,
    "sort": "Email desc",
}
result = mailjet.contact.get(filters=filters)
print(result.json())
```

#### PUT (Update / Patch specific fields)

A `PUT` request in the Mailjet API will work as a `PATCH` request - the update will affect only the specified properties. The other properties of an existing resource will neither be modified, nor deleted. It also means that all non-mandatory properties can be omitted from your payload.

```python
# Update the contact properties for a contact
id_ = "$CONTACT_ID"
data = {
    "Data": [
        {"Name": "first_name", "value": "John"},
        {"Name": "last_name", "value": "Smith"},
    ]
}
result = mailjet.contactdata.update(id=id_, data=data)
print(result.json())
```

#### DELETE (Returns 204 No Content)

Upon a successful `DELETE` request the response will not include a response body, but only a `204 No Content` response code.

```python
# Delete an email template
id_ = "Template_ID"
result = mailjet.template.delete(id=id_)
print(result.json())
```

### Email API Ecosystem (Webhooks, Parse API, Segmentation, Stats)

#### Webhooks (Real-time Event Tracking)

You can subscribe to real-time events (open, click, bounce, etc.) by configuring a webhook URL using the `eventcallbackurl` resource.

```python
data = {
    "EventType": "open",
    "Url": "https://www.mydomain.com/webhook",
    "Status": "alive",
}
result = client.eventcallbackurl.create(data=data)
```

#### Parse API (Receive Inbound Emails)

The Parse API routes incoming emails sent to a specific domain to your custom webhook.

```python
data = {"Url": "https://www.mydomain.com/mj_parse.php"}
result = client.parseroute.create(data=data)
```

#### Segmentation (Contact Filters)

Create expressions to dynamically filter your contacts (e.g., customers under 35) using `contactfilter`.

```python
data = {
    "Description": "Will send only to contacts under 35 years of age.",
    "Expression": "(age<35)",
    "Name": "Customers under 35",
}
result = client.contactfilter.create(data=data)
```

#### Retrieve Campaign Statistics

Retrieve performance counters using `statcounters` or location-based statistics via `geostatistics`.

```python
from mailjet_rest import Client
import os

mailjet = Client(auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")))

filters = {"CounterSource": "APIKey", "CounterTiming": "Message", "CounterResolution": "Lifetime"}

# Getting general statistics
result = mailjet.statcounters.get(filters=filters)
print(result.status_code)
print(result.json())
```

### Content API

Requires `version="v1"`. You can authenticate using Basic Auth or a Bearer Token.

The Content API (`v1`) allows managing templates, generating API tokens, and uploading images. The SDK handles the required `/REST/` prefix for most resources automatically, while appropriately mapping `data_images` to `/data/`.

#### Generating a Token

```python
# Tokens endpoint requires Basic Auth initially
client = Client(auth=(api_key, api_secret), version="v1")
data = {"Name": "My Access Token", "Permissions": ["read_template", "create_template"]}

result = client.token.create(data=data)
print(result.json())
```

#### Uploading an Image via Multipart Form-Data

To upload physical files, use the `data_images` resource and delete the default Content-Type header so requests can generate proper multipart boundaries. The request will be mapped to `/v1/data/images`.

```python
import base64

# Base64 encoded image data (1x1 transparent PNG)
b64_string = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
image_bytes = base64.b64decode(b64_string)

# The Image upload requires a JSON metadata part (with a Status) and the physical file part
files_payload = {
    "metadata": (None, '{"name": "logo.png", "Status": "open"}', "application/json"),
    "file": ("logo.png", image_bytes, "image/png"),
}

# Deleting the default Content-Type header allows requests to generate multipart/form-data
result = client.data_images.create(headers={"Content-Type": None}, files=files_payload)
```

#### Locking a Template Content

Sub-actions are safely handled using slashes (e.g., `template_contents_lock` becomes `template/<template_id>/contents/lock`).

```python
template_id = 1234567

# This routes to POST /v1/REST/template/1234567/contents/lock
result = client.template_contents_lock.create(id=template_id)
```

## Deprecation Warnings

The SDK includes an active native Python deprecation system to protect your application from sudden API breaking changes.

If you attempt to use legacy arguments (like `ensure_ascii` or `data_encoding`), obsolete utility functions (`parse_response`), or ambiguous routing (`v1` with `/template`), the SDK will **not** break your code.
It will successfully execute the request but will emit a non-breaking `DeprecationWarning` to help you gracefully migrate to modern standards.

## Type Hinting

This SDK is fully type-hinted and compatible with static type checkers like `mypy` and `pyright`.

Because of the dynamic URL dispatch engine (`__getattr__`), IDEs may flag endpoints like `client.contact.create` as `Any`. If you enforce strict typing in your application, you may safely ignore these specific dynamically dispatched calls.

## License

[MIT](https://choosealicense.com/licenses/mit/)

## Contribute

Mailjet loves developers. You can be part of this project!

This wrapper is a great introduction to the open source world, check out the code!

Feel free to ask anything, and contribute:

- Fork the project.
- Create a new branch.
- Implement your feature or bug fix.
- Add documentation to it.
- Commit, push, open a pull request and voila.

If you have suggestions on how to improve the guides, please submit an issue in our [Official API Documentation repo](https://github.com/mailjet/api-documentation).

## Contributors

- [@diskovod](https://github.com/diskovod)
- [@DanyilNefodov](https://github.com/DanyilNefodov)
- [@skupriienko](https://github.com/skupriienko)

[api_credential]: https://app.mailjet.com/account/apikeys
[doc]: https://dev.mailjet.com/email/guides/?python#
[mailjet]: https://www.mailjet.com
