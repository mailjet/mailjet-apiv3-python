import json
import os
from pathlib import Path

from mailjet_rest import Client


mailjet30 = Client(
    auth=(os.environ["MJ_APIKEY_PUBLIC"], os.environ["MJ_APIKEY_PRIVATE"]),
)

mailjet31 = Client(
    auth=(os.environ["MJ_APIKEY_PUBLIC"], os.environ["MJ_APIKEY_PRIVATE"]),
    version="v3.1",
)


def create_a_contact():
    """POST https://api.mailjet.com/v3/REST/contact"""
    data = {
        "IsExcludedFromCampaigns": "true",
        "Name": "New Contact",
        "Email": "passenger@mailjet.com",
    }
    return mailjet30.contact.create(data=data)


def create_contact_metadata():
    """POST https://api.mailjet.com/v3/REST/contactmetadata"""
    data = {"Datatype": "str", "Name": "first_name", "NameSpace": "static"}
    return mailjet30.contactmetadata.create(data=data)


def edit_contact_data():
    """PUT https://api.mailjet.com/v3/REST/contactdata/$contact_ID"""
    _id = "*********"  # Put real ID to make it work.
    data = {"Data": [{"Name": "first_name", "Value": "John"}]}
    return mailjet30.contactdata.update(id=_id, data=data)


def manage_contact_properties():
    """POST https://api.mailjet.com/v3/REST/contactmetadata"""
    _id = "$contact_ID"
    data = {"Data": [{"Name": "first_name", "Value": "John"}]}
    return mailjet30.contactdata.update(id=_id, data=data)


def create_a_contact_list():
    """POST https://api.mailjet.com/v3/REST/contactslist"""
    data = {"Name": "my_contactslist"}
    return mailjet30.contactslist.create(data=data)


def add_a_contact_to_a_contact_list():
    """POST https://api.mailjet.com/v3/REST/listrecipient"""
    data = {
        "IsUnsubscribed": "true",
        "ContactID": "987654321",
        "ContactAlt": "passenger@mailjet.com",
        "ListID": "123456",
        "ListAlt": "abcdef123",
    }
    return mailjet30.listrecipient.create(data=data)


def manage_the_subscription_status_of_an_existing_contact():
    """POST https://api.mailjet.com/v3/REST/contact/$contact_ID/managecontactslists"""
    _id = "$contact_ID"
    data = {
        "ContactsLists": [
            {"Action": "addforce", "ListID": "987654321"},
            {"Action": "addnoforce", "ListID": "987654321"},
            {"Action": "remove", "ListID": "987654321"},
            {"Action": "unsub", "ListID": "987654321"},
        ],
    }
    return mailjet30.contact_managecontactslists.create(id=_id, data=data)


def manage_multiple_contacts_in_a_list():
    """POST https://api.mailjet.com/v3/REST/contactslist/$list_ID/managemanycontacts"""
    _id = "$list_ID"
    data = {
        "Action": "addnoforce",
        "Contacts": [
            {
                "Email": "passenger@mailjet.com",
                "IsExcludedFromCampaigns": "false",
                "Name": "Passenger 1",
                "Properties": "object",
            },
        ],
    }
    return mailjet30.contactslist_managemanycontacts.create(id=_id, data=data)


def monitor_the_upload_job():
    """GET https://api.mailjet.com/v3/REST/contactslist/$list_ID/managemanycontacts"""
    _id = "$list_ID"
    return mailjet30.contactslist_managemanycontacts.get(id=_id)


def manage_multiple_contacts_across_multiple_lists():
    """POST https://api.mailjet.com/v3/REST/contact/managemanycontacts"""
    data = {
        "Contacts": [
            {
                "Email": "passenger@mailjet.com",
                "IsExcludedFromCampaigns": "false",
                "Name": "Passenger 1",
                "Properties": "object",
            },
        ],
        "ContactsLists": [
            {"Action": "addforce", "ListID": "987654321"},
            {"Action": "addnoforce", "ListID": "987654321"},
            {"Action": "remove", "ListID": "987654321"},
            {"Action": "unsub", "ListID": "987654321"},
        ],
    }
    return mailjet30.contact_managemanycontacts.create(data=data)


def upload_the_csv():
    """POST https://api.mailjet.com/v3/DATA/contactslist
    /$ID_CONTACTLIST/CSVData/text:plain"""
    return mailjet30.contactslist_csvdata.create(
        id="$ID_CONTACTLIST",
        data=Path("./data.csv").read_text(encoding="utf-8"),
    )


def import_csv_content_to_a_list():
    """POST https://api.mailjet.com/v3/REST/csvimport"""
    data = {
        "ErrThreshold": "1",
        "ImportOptions": "",
        "Method": "addnoforce",
        "ContactsListID": "123456",
        "DataID": "98765432123456789",
    }
    return mailjet30.csvimport.create(data=data)


def using_csv_with_atetime_contact_data():
    """POST https://api.mailjet.com/v3/REST/csvimport"""
    # fmt: off
    data = {
        "ContactsListID": "$ID_CONTACTLIST",
        "DataID": "$ID_DATA",
        "Method": "addnoforce",
        "ImportOptions": "{\"DateTimeFormat\": \"yyyy/mm/dd\","
                         "\"TimezoneOffset\": 2,\"FieldNames\": "
                         "[\"email\", \"birthday\"]} ",
    }
    # fmt: on
    return mailjet30.csvimport.create(data=data)


def monitor_the_import_progress():
    """GET https://api.mailjet.com/v3/REST/csvimport/$importjob_ID"""
    _id = "$importjob_ID"
    return mailjet30.csvimport.get(id=_id)


def error_handling():
    """https://api.mailjet.com/v3/DATA/BatchJob/$job_id/CSVError/text:csv"""
    """Not available in Python, please refer to Curl"""


def single_contact_exclusion():
    """PUT https://api.mailjet.com/v3/REST/contact/$ID_OR_EMAIL"""
    _id = "$ID_OR_EMAIL"
    data = {"IsExcludedFromCampaigns": "true"}
    return mailjet30.contact.update(id=_id, data=data)


def using_contact_managemanycontacts():
    """POST https://api.mailjet.com/v3/REST/contact/managemanycontacts"""
    data = {
        "Contacts": [
            {
                "Email": "jimsmith@example.com",
                "Name": "Jim",
                "IsExcludedFromCampaigns": "true",
                "Properties": {"Property1": "value", "Property2": "value2"},
            },
            {
                "Email": "janetdoe@example.com",
                "Name": "Janet",
                "IsExcludedFromCampaigns": "true",
                "Properties": {"Property1": "value", "Property2": "value2"},
            },
        ],
    }
    return mailjet30.contact_managemanycontacts.create(data=data)


def using_csvimport():
    """POST https://api.mailjet.com/v3/REST/csvimport"""
    data = {"DataID": "$ID_DATA", "Method": "excludemarketing"}
    return mailjet30.csvimport.create(data=data)


def retrieve_a_contact():
    """GET https://api.mailjet.com/v3/REST/contact/$CONTACT_EMAIL"""
    _id = "$CONTACT_EMAIL"
    return mailjet30.contact.get(id=_id)


def delete_the_contact():
    """DELETE https://api.mailjet.com/v4/contacts/{contact_ID}"""


if __name__ == "__main__":
    result = edit_contact_data()
    print(result.status_code)
    try:
        print(json.dumps(result.json(), indent=4))
    except json.decoder.JSONDecodeError:
        print(result.text)
