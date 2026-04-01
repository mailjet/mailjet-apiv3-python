![alt text](https://www.mailjet.com/images/email/transac/logo_header.png "Mailjet")

# Official Mailjet Python Wrapper

[![PyPI Version](https://img.shields.io/github/v/release/mailjet/mailjet-apiv3-python)](https://img.shields.io/github/v/release/mailjet/mailjet-apiv3-python)
[![GitHub Release](https://img.shields.io/github/v/release/mailjet/mailjet-apiv3-python)](https://img.shields.io/github/v/release/mailjet/mailjet-apiv3-python)
[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://github.com/mailjet/mailjet-apiv3-python)
[![License](https://img.shields.io/github/license/mailjet/mailjet-apiv3-python)](https://github.com/mailjet/mailjet-apiv3-python/blob/main/LICENSE)
[![PyPI Downloads](https://img.shields.io/pypi/dm/mailjet-rest)](https://img.shields.io/pypi/dm/mailjet-rest)
[![Build Status](https://img.shields.io/github/actions/workflow/status/mailjet/mailjet-apiv3-python/commit_checks.yaml)](https://github.com/mailjet/mailjet-apiv3-python/actions)

[![GitHub Stars](https://img.shields.io/github/stars/mailjet/mailjet-apiv3-python)](https://img.shields.io/github/stars/mailjet/mailjet-apiv3-python)
[![GitHub Issues](https://img.shields.io/github/issues/mailjet/mailjet-apiv3-python)](https://img.shields.io/github/issues/mailjet/mailjet-apiv3-python)
[![GitHub PRs](https://img.shields.io/github/issues-pr/mailjet/mailjet-apiv3-python)](https://img.shields.io/github/issues-pr/mailjet/mailjet-apiv3-python)

## Overview

Welcome to the [Mailjet] official Python API wrapper!

Check out all the resources and Python code examples in the official [Mailjet Documentation][doc].

## Table of contents

- [Compatibility](#compatibility)
- [Requirements](#requirements)
  - [Build backend dependencies](#build-backend-dependencies)
  - [Runtime dependencies](#runtime-dependencies)
  - [Test dependencies](#test-dependencies)
- [Installation](#installation)
  - [pip install](#pip-install)
    - [git clone & pip install locally](#git-clone--pip-install-locally)
    - [conda & make](#conda--make)
  - [For development](#for-development)
    - [Using conda](#using-conda)
- [Authentication](#authentication)
- [Make your first call](#make-your-first-call)
- [Client / Call configuration specifics](#client--call-configuration-specifics)
  - [API versioning](#api-versioning)
  - [Base URL](#base-url)
  - [URL path](#url-path)
- [Request examples](#request-examples)
  - [Full list of supported endpoints](#full-list-of-supported-endpoints)
  - [POST request](#post-request)
    - [Simple POST request](#simple-post-request)
    - [Using actions](#using-actions)
  - [GET request](#get-request)
    - [Retrieve all objects](#retrieve-all-objects)
    - [Using filtering](#using-filtering)
    - [Using pagination](#using-pagination)
    - [Retrieve a single object](#retrieve-a-single-object)
  - [PUT request](#put-request)
  - [DELETE request](#delete-request)
- [License](#license)
- [Contribute](#contribute)
- [Contributors](#contributors)

## Compatibility

This library `mailjet_rest` officially supports the following Python versions:

- Python >=3.10,\<3.14

It's tested up to 3.13 (including).

## Requirements

### Build backend dependencies

To build the `mailjet_rest` package from the sources you need `setuptools` (as a build backend), `wheel`, and `setuptools-scm`.

### Runtime dependencies

At runtime the package requires only `requests >=2.32.5`.

### Test dependencies

For running test you need `pytest >=7.0.0` at least.
Make sure to provide the environment variables from [Authentication](#authentication).

## Installation

### pip install

First, create a virtual environment:

```bash
virtualenv -p python3 venv
source venv/bin/activate
```

Then, install the wrapper:

```bash
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

The Mailjet Email API uses your API and Secret keys for authentication. [Grab][api_credential] and save your Mailjet API credentials.

```bash
export MJ_APIKEY_PUBLIC='your api key'  # pragma: allowlist secret
export MJ_APIKEY_PRIVATE='your api secret'  # pragma: allowlist secret
```

> **Note**
> For the SMS API the authorization credentials are your API Token.

Initialize your [Mailjet] client:

```python
# import the mailjet wrapper
from mailjet_rest import Client
import os

# Get your environment Mailjet keys
api_key = os.environ["MJ_APIKEY_PUBLIC"]
api_secret = os.environ["MJ_APIKEY_PRIVATE"]

mailjet = Client(auth=(api_key, api_secret))
```

## Make your first call

Here's an example on how to send an email:

```python
from mailjet_rest import Client
import os

api_key = os.environ["MJ_APIKEY_PUBLIC"]
api_secret = os.environ["MJ_APIKEY_PRIVATE"]
mailjet = Client(auth=(api_key, api_secret))
data = {
    "FromEmail": "$SENDER_EMAIL",
    "FromName": "$SENDER_NAME",
    "Subject": "Your email flight plan!",
    "Text-part": "Dear passenger, welcome to Mailjet! May the delivery force be with you!",
    "Html-part": '<h3>Dear passenger, welcome to <a href="https://www.mailjet.com/">Mailjet</a>!<br />May the delivery force be with you!',
    "Recipients": [{"Email": "$RECIPIENT_EMAIL"}],
}
result = mailjet.send.create(data=data)
print(result.status_code)
print(result.json())
```

## Error Handling

The client safely wraps network-level exceptions to prevent leaking requests dependencies. You can catch these custom exceptions to handle network drops or timeouts gracefully:
from mailjet_rest import Client, TimeoutError, CriticalApiError

```python
import os
from mailjet_rest.client import Client, CriticalApiError, TimeoutError, ApiError

api_key = os.environ.get("MJ_APIKEY_PUBLIC", "")
api_secret = os.environ.get("MJ_APIKEY_PRIVATE", "")
mailjet = Client(auth=(api_key, api_secret))

try:
    result = mailjet.contact.get()
    # Note: HTTP errors (like 404 or 401) do not raise exceptions by default.
    # You should always check the status_code:
    if result.status_code != 200:
        print(f"API Error: {result.status_code}")
except TimeoutError:
    print("The request to the Mailjet API timed out.")
except CriticalApiError as e:
    print(f"Network connection failed: {e}")
except ApiError as e:
    print(f"An unexpected Mailjet API error occurred: {e}")
```

## Logging & Debugging

The Mailjet SDK includes built-in logging to help you troubleshoot API requests, inspect generated URLs, and read server error messages (like `400 Bad Request` or `401 Unauthorized`).
The SDK uses the standard Python logging module under the namespace mailjet_rest.client.

To enable detailed logging in your application, configure the logger before making requests:

```python
import logging
from mailjet_rest import Client

# Enable DEBUG level for the Mailjet SDK logger
logging.getLogger("mailjet_rest.client").setLevel(logging.DEBUG)

# Configure the basic console output (if not already configured in your app)
logging.basicConfig(format="%(levelname)s - %(name)s - %(message)s")

# Now, any API requests or errors will be printed to your console
mailjet = Client(auth=("api_key", "api_secret"))
mailjet.contact.get()
```

## Client / Call Configuration Specifics

### Client / Call configuration override

You can pass a dictionary to the client or to the call to establish a configuration.

#### Client

```python
mailjet = Client(auth=(api_key, api_secret), timeout=30)
```

#### Call

```python
result = mailjet.send.create(data=data, timeout=30)
```

### API Versioning

The Mailjet API is spread among distinct versions:

- `v3` - The Email API
- `v3.1` - Email Send API v3.1, which is the latest version of our Send API
- `v1` - Content API (Templates, Blocks, Images)

Since most Email API endpoints are located under `v3`, it is set as the default one and does not need to be specified when making your request. For the others you need to specify the version using `version`. For example, if using Send API `v3.1`:

```python
# import the mailjet wrapper
from mailjet_rest import Client
import os

# Get your environment Mailjet keys
api_key = os.environ["MJ_APIKEY_PUBLIC"]
api_secret = os.environ["MJ_APIKEY_PRIVATE"]

mailjet = Client(auth=(api_key, api_secret), version="v3.1")
```

For additional information refer to our [API Reference](https://dev.mailjet.com/reference/overview/versioning/).

### Base URL

The default base domain name for the Mailjet API is `api.mailjet.com`. You can modify this base URL by setting a value for `api_url` in your call:

```python
mailjet = Client(auth=(api_key, api_secret), api_url="https://api.us.mailjet.com/")
```

If your account has been moved to Mailjet's **US architecture**, the URL value you need to set is `https://api.us.mailjet.com`.

### URL path

According to python special characters limitations we can't use slashes `/` and dashes `-` which is acceptable for URL path building. Instead python client uses another way for path building. You should replace slashes `/` by underscore `_` and dashes `-` by capitalizing next letter in path.
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
from mailjet_rest import Client
import os

api_key = os.environ.get("MJ_APIKEY_PUBLIC", "")
api_secret = os.environ.get("MJ_APIKEY_PRIVATE", "")
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

### POST request

#### Simple POST request

```python
"""
Create a new contact:
"""

from mailjet_rest import Client
import os

api_key = os.environ["MJ_APIKEY_PUBLIC"]
api_secret = os.environ["MJ_APIKEY_PRIVATE"]
mailjet = Client(auth=(api_key, api_secret))
data = {"Email": "Mister@mailjet.com"}
result = mailjet.contact.create(data=data)
print(result.status_code)
print(result.json())
```

#### Using actions

```python
"""
Manage the subscription status of a contact to multiple lists:
"""

from mailjet_rest import Client
import os

api_key = os.environ["MJ_APIKEY_PUBLIC"]
api_secret = os.environ["MJ_APIKEY_PRIVATE"]
mailjet = Client(auth=(api_key, api_secret))
id_ = "$ID"
data = {
    "ContactsLists": [
        {"ListID": "$ListID_1", "Action": "addnoforce"},
        {"ListID": "$ListID_2", "Action": "addforce"},
    ]
}
result = mailjet.contact_managecontactslists.create(id=id_, data=data)
print(result.status_code)
print(result.json())
```

### GET Request

#### Retrieve all objects

```python
"""
Retrieve all contacts:
"""

from mailjet_rest import Client
import os

api_key = os.environ["MJ_APIKEY_PUBLIC"]
api_secret = os.environ["MJ_APIKEY_PRIVATE"]
mailjet = Client(auth=(api_key, api_secret))
result = mailjet.contact.get()
print(result.status_code)
print(result.json())
```

#### Using filtering

```python
"""
Retrieve all contacts that are not in the campaign exclusion list:
"""

from mailjet_rest import Client
import os

api_key = os.environ["MJ_APIKEY_PUBLIC"]
api_secret = os.environ["MJ_APIKEY_PRIVATE"]
mailjet = Client(auth=(api_key, api_secret))
filters = {
    "IsExcludedFromCampaigns": "false",
}
result = mailjet.contact.get(filters=filters)
print(result.status_code)
print(result.json())
```

#### Using pagination

Some requests (for example [GET /contact](https://dev.mailjet.com/email/reference/contacts/contact/#v3_get_contact)) has `limit`, `offset` and `sort` query string parameters. These parameters could be used for pagination.
`limit` `int` Limit the response to a select number of returned objects. Default value: `10`. Maximum value: `1000`
`offset` `int` Retrieve a list of objects starting from a certain offset. Combine this query parameter with `limit` to retrieve a specific section of the list of objects. Default value: `0`
`sort` `str` Sort the results by a property and select ascending (ASC) or descending (DESC) order. The default order is ascending. Keep in mind that this is not available for all properties. Default value: `ID asc`
Next example returns 40 contacts starting from 51th record sorted by `Email` field descendally:

```python
import os
from mailjet_rest import Client

api_key = os.environ["MJ_APIKEY_PUBLIC"]
api_secret = os.environ["MJ_APIKEY_PRIVATE"]
mailjet = Client(auth=(api_key, api_secret))

filters = {
    "limit": 40,
    "offset": 50,
    "sort": "Email desc",
}
result = mailjet.contact.get(filters=filters)
print(result.status_code)
print(result.json())
```

#### Retrieve a single object

```python
"""
Retrieve a specific contact ID:
"""

from mailjet_rest import Client
import os

api_key = os.environ["MJ_APIKEY_PUBLIC"]
api_secret = os.environ["MJ_APIKEY_PRIVATE"]
mailjet = Client(auth=(api_key, api_secret))
id_ = "Contact_ID"
result = mailjet.contact.get(id=id_)
print(result.status_code)
print(result.json())
```

### PUT request

A `PUT` request in the Mailjet API will work as a `PATCH` request - the update will affect only the specified properties. The other properties of an existing resource will neither be modified, nor deleted. It also means that all non-mandatory properties can be omitted from your payload.

Here's an example of a `PUT` request:

```python
"""
Update the contact properties for a contact:
"""

from mailjet_rest import Client
import os

api_key = os.environ["MJ_APIKEY_PUBLIC"]
api_secret = os.environ["MJ_APIKEY_PRIVATE"]
mailjet = Client(auth=(api_key, api_secret))
id_ = "$CONTACT_ID"
data = {
    "Data": [
        {"Name": "first_name", "value": "John"},
        {"Name": "last_name", "value": "Smith"},
    ]
}
result = mailjet.contactdata.update(id=id_, data=data)
print(result.status_code)
print(result.json())
```

### DELETE request

Upon a successful `DELETE` request the response will not include a response body, but only a `204 No Content` response code.

Here's an example of a `DELETE` request:

```python
"""
Delete an email template:
"""

from mailjet_rest import Client
import os

api_key = os.environ["MJ_APIKEY_PUBLIC"]
api_secret = os.environ["MJ_APIKEY_PRIVATE"]
mailjet = Client(auth=(api_key, api_secret))
id_ = "Template_ID"
result = mailjet.template.delete(id=id_)
print(result.status_code)
print(result.json())
```

### Email API Ecosystem (Webhooks, Parse API, Segmentation, Stats)

#### Webhooks: Real-time Event Tracking

You can subscribe to real-time events (open, click, bounce, etc.) by configuring a webhook URL using the `eventcallbackurl` resource.

```python
from mailjet_rest import Client
import os

client = Client(auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")))

data = {
    "EventType": "open",
    "Url": "[https://www.mydomain.com/webhook](https://www.mydomain.com/webhook)",
    "Status": "alive",
}
result = client.eventcallbackurl.create(data=data)
print(result.status_code)
```

#### Parse API: Receive Inbound Emails

The Parse API routes incoming emails sent to a specific domain to your custom webhook.

```python
from mailjet_rest import Client
import os

client = Client(auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")))

data = {"Url": "https://www.mydomain.com/mj_parse.php"}
result = client.parseroute.create(data=data)
print(result.status_code)
```

#### Segmentation: Contact Filters

Create expressions to dynamically filter your contacts (e.g., customers under 35) using `contactfilter`.

```python
from mailjet_rest import Client
import os

client = Client(auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")))

data = {
    "Description": "Will send only to contacts under 35 years of age.",
    "Expression": "(age<35)",
    "Name": "Customers under 35",
}
result = client.contactfilter.create(data=data)
print(result.status_code)
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

The Content API (`v1`) allows managing templates, generating API tokens, and uploading images. The SDK handles the required `/REST/` prefix for most resources automatically, while appropriately mapping `data_images` to `/data/`.

#### Generating a Token

```python
from mailjet_rest import Client
import os

api_key = os.environ.get("MJ_APIKEY_PUBLIC", "")
api_secret = os.environ.get("MJ_APIKEY_PRIVATE", "")

# Tokens endpoint requires Basic Auth initially
client = Client(auth=(api_key, api_secret), version="v1")
data = {"Name": "My Access Token", "Permissions": ["read_template", "create_template"]}

result = client.token.create(data=data)
print(result.json())
```

#### Uploading an Image

Use the `data_images` resource to map the request to `/v1/data/images`.

```python
from mailjet_rest import Client
import os

api_key = os.environ.get("MJ_APIKEY_PUBLIC", "")
api_secret = os.environ.get("MJ_APIKEY_PRIVATE", "")

client = Client(auth=(api_key, api_secret), version="v1")

# Base64 encoded image data
data = {
    "name": "logo.png",
    # 1x1 PNG pixel
    "image_data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
}

result = client.data_images.create(data=data)
print(result.status_code)
```

#### Locking a Template Content

Sub-actions are safely handled using slashes (`contents/lock` instead of `contents-lock`).

```python
from mailjet_rest import Client
import os

client = Client(auth=(os.environ["MJ_APIKEY_PUBLIC"], os.environ["MJ_APIKEY_PRIVATE"]), version="v1")

template_id = 1234567

# This routes to POST /v1/REST/template/1234567/contents/lock
result = client.template_contents_lock.create(id=template_id)
print(result.status_code)
```

#### Update Template Content

Use the specific \_detailcontent resource route to update the HTML or Text parts of an existing template.

```python
from mailjet_rest import Client
import os

api_key = os.environ.get("MJ_APIKEY_PUBLIC", "")
api_secret = os.environ.get("MJ_APIKEY_PRIVATE", "")
mailjet = Client(auth=(api_key, api_secret))

template_id = 1234567

data = {
    "Html-part": "<html><body><h1>Updated Content from Python SDK</h1></body></html>",
    "Text-part": "Updated Content from Python SDK",
    "Headers": {"Subject": "New Subject from API"},
}

result = mailjet.template_detailcontent.create(id=template_id, data=data)
print(result.status_code)
```

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
[mailjet]: (https://www.mailjet.com)
