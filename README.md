
[mailjet]:(http://www.mailjet.com/)
[api_credential]: https://app.mailjet.com/account/api_keys
[doc]: http://dev.mailjet.com/guides/?python#
[api_doc]: https://github.com/mailjet/api-documentation

![alt text](https://www.mailjet.com/images/email/transac/logo_header.png "Mailjet")

# Official Mailjet Python Wrapper

[![Build Status](https://travis-ci.org/mailjet/mailjet-apiv3-python.svg?branch=master)](https://travis-ci.org/mailjet/mailjet-apiv3-python)
![Current Version](https://img.shields.io/badge/version-1.3.2-green.svg)

## Overview

Welcome to the [Mailjet][mailjet] official Python API wrapper!

Check out all the resources and Python code examples in the official [Mailjet Documentation][doc].

## Table of contents

- [Compatibility](#compatibility)
- [Installation](#installation)
- [Authentication](#authentication)
- [Make your first call](#make-your-first-call)
- [Client / Call configuration specifics](#client--call-configuration-specifics)
  - [API versioning](#api-versioning)
  - [Base URL](#base-url)
  - [URL path](#url-path)
- [Request examples](#request-examples)
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
- [Contribute](#contribute)

## Compatibility

This library officially supports the following Python versions:

 - v2.7
 - v3.5
 - v3.6+

## Installation

Use the below code to install the wrapper:

``` bash
(sudo) pip install mailjet_rest
```

## Authentication

The Mailjet Email API uses your API and Secret keys for authentication. [Grab][api_credential] and save your Mailjet API credentials.

```bash
export MJ_APIKEY_PUBLIC='your api key'
export MJ_APIKEY_PRIVATE='your api secret'
```

Initialize your [Mailjet][mailjet] client:

```python
# import the mailjet wrapper
from mailjet_rest import Client
import os

# Get your environment Mailjet keys
API_KEY = os.environ['MJ_APIKEY_PUBLIC']
API_SECRET = os.environ['MJ_APIKEY_PRIVATE']

mailjet = Client(auth=(API_KEY, API_SECRET))
```

## Make your first call

Here's an example on how to send an email:

```python
from mailjet_rest import Client
import os
api_key = os.environ['MJ_APIKEY_PUBLIC']
api_secret = os.environ['MJ_APIKEY_PRIVATE']
mailjet = Client(auth=(api_key, api_secret), version='v3.1')
data = {
  'Messages': [
    {
      "From": {
        "Email": "$SENDER_EMAIL",
        "Name": "Me"
      },
      "To": [
        {
          "Email": "$RECIPIENT_EMAIL",
          "Name": "You"
        }
      ],
      "Subject": "My first Mailjet Email!",
      "TextPart": "Greetings from Mailjet!",
      "HTMLPart": "<h3>Dear passenger 1, welcome to <a href=\"https://www.mailjet.com/\">Mailjet</a>!</h3><br />May the delivery force be with you!"
    }
  ]
}
result = mailjet.send.create(data=data)
print result.status_code
print result.json()
```

## Client / Call Configuration Specifics

### API Versioning

The Mailjet API is spread among three distinct versions:

- `v3` - The Email API
- `v3.1` - Email Send API v3.1, which is the latest version of our Send API
- `v4` - SMS API (not supported in Python)

Since most Email API endpoints are located under `v3`, it is set as the default one and does not need to be specified when making your request. For the others you need to specify the version using `version`. For example, if using Send API `v3.1`:

``` python
# import the mailjet wrapper
from mailjet_rest import Client
import os

# Get your environment Mailjet keys
API_KEY = os.environ['MJ_APIKEY_PUBLIC']
API_SECRET = os.environ['MJ_APIKEY_PRIVATE']

mailjet = Client(auth=(API_KEY, API_SECRET), version='v3.1')
```

For additional information refer to our [API Reference](https://dev.mailjet.com/reference/overview/versioning/).

### Base URL

The default base domain name for the Mailjet API is `api.mailjet.com`. You can modify this base URL by setting a value for `api_url` in your call:

```python
mailjet = Client(auth=(api_key, api_secret),api_url="https://api.us.mailjet.com/")
```

If your account has been moved to Mailjet's **US architecture**, the URL value you need to set is `https://api.us.mailjet.com`.

### URL path

According to python special characters limitations we can't use slashes `/` and dashes `-` which is acceptable for URL path building. Instead python client uses another way for path building. You should replase slashes `/` by underscore `_` and dashes `-` by capitalizing next letter in path.
For example, to reach `statistics/link-click` path you should call `statistics_linkClick` attribute of python client.

```python
# GET `statistics/link-click`
mailjet = Client(auth=(api_key, api_secret))
filters = {
  'CampaignId': 'xxxxxxx'
}
result = mailjet.statistics_linkClick.get(filters=filters)
print result.status_code
print result.json()
``` 

## Request examples

### POST request

#### Simple POST request

```python
"""
Create a new contact:
"""
from mailjet_rest import Client
import os
api_key = os.environ['MJ_APIKEY_PUBLIC']
api_secret = os.environ['MJ_APIKEY_PRIVATE']
mailjet = Client(auth=(api_key, api_secret))
data = {
  'Email': 'Mister@mailjet.com'
}
result = mailjet.contact.create(data=data)
print result.status_code
print result.json()
```

#### Using actions

```python
"""
Manage the subscription status of a contact to multiple lists:
"""
from mailjet_rest import Client
import os
api_key = os.environ['MJ_APIKEY_PUBLIC']
api_secret = os.environ['MJ_APIKEY_PRIVATE']
mailjet = Client(auth=(api_key, api_secret))
id = '$ID'
data = {
  'ContactsLists': [
                {
                        "ListID": "$ListID_1",
                        "Action": "addnoforce"
                },
                {
                        "ListID": "$ListID_2",
                        "Action": "addforce"
                }
        ]
}
result = mailjet.contact_managecontactslists.create(id=id, data=data)
print result.status_code
print result.json()
```

### GET Request

#### Retrieve all objects

```python
"""
Retrieve all contacts:
"""
from mailjet_rest import Client
import os
api_key = os.environ['MJ_APIKEY_PUBLIC']
api_secret = os.environ['MJ_APIKEY_PRIVATE']
mailjet = Client(auth=(api_key, api_secret))
result = mailjet.contact.get()
print result.status_code
print result.json()
```

#### Using filtering

```python
"""
Retrieve all contacts that are not in the campaign exclusion list:
"""
from mailjet_rest import Client
import os
api_key = os.environ['MJ_APIKEY_PUBLIC']
api_secret = os.environ['MJ_APIKEY_PRIVATE']
mailjet = Client(auth=(api_key, api_secret))
filters = {
  'IsExcludedFromCampaigns': false,
}
result = mailjet.contact.get(filters=filters)
print result.status_code
print result.json()
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
api_key = os.environ['MJ_APIKEY_PUBLIC']
api_secret = os.environ['MJ_APIKEY_PRIVATE']
mailjet = Client(auth=(api_key, api_secret))
id = 'Contact_ID'
result = mailjet.contact.get(id=id)
print result.status_code
print result.json()
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
api_key = os.environ['MJ_APIKEY_PUBLIC']
api_secret = os.environ['MJ_APIKEY_PRIVATE']
mailjet = Client(auth=(api_key, api_secret))
id = '$CONTACT_ID'
data = {
  'Data': [
                {
                        "Name": "first_name",
                        "value": "John"
                },
                {
                        "Name": "last_name",
                        "value": "Smith"
                }
        ]
}
result = mailjet.contactdata.update(id=id, data=data)
print result.status_code
print result.json()
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
api_key = os.environ['MJ_APIKEY_PUBLIC']
api_secret = os.environ['MJ_APIKEY_PRIVATE']
mailjet = Client(auth=(api_key, api_secret))
id = 'Template_ID'
result = mailjet.template.delete(id=id)
print result.status_code
print result.json()
```

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
