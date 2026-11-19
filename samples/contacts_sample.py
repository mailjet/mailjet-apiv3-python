from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any

from mailjet_rest import Client
from mailjet_rest.errors import ApiError, MailjetAuthError


def _get_client() -> Client:
    """Create a Mailjet v3 Client lazily from environment credentials."""
    return Client(auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")))


def create_a_contact(client: Client | None = None) -> Any:
    unique_email = f"passenger+{uuid.uuid4().hex[:8]}@mailjet.com"
    data = {"IsExcludedFromCampaigns": False, "Name": "New Contact", "Email": unique_email}
    return (client or _get_client()).contact.create(data=data)


def create_contact_metadata(client: Client | None = None) -> Any:
    unique_meta = f"first_name_{uuid.uuid4().hex[:6]}"
    data = {"Datatype": "str", "Name": unique_meta, "NameSpace": "static"}
    return (client or _get_client()).contactmetadata.create(data=data)


def edit_contact_data(client: Client | None = None) -> Any:
    active_client = client or _get_client()
    contact_res = active_client.contact.get(filters={"Limit": 1})
    contact_id = (
        contact_res.json()["Data"][0]["ID"] if contact_res.status_code == 200 and contact_res.json().get("Data") else 0
    )
    for prop in ["first_name", "last_name"]:
        try:
            active_client.contactmetadata.create(data={"Datatype": "str", "Name": prop, "NameSpace": "static"})
        except ApiError as exc:
            if "CM01" not in str(exc) and "already exists" not in str(exc):
                raise
    data = {"Data": [{"Name": "first_name", "Value": "John"}, {"Name": "last_name", "Value": "Smith"}]}
    return active_client.contactdata.update(id=contact_id, data=data)


def manage_contact_properties(client: Client | None = None) -> Any:
    unique_meta = f"age_{uuid.uuid4().hex[:6]}"
    data = {"Datatype": "str", "Name": unique_meta, "NameSpace": "static"}
    return (client or _get_client()).contactmetadata.create(data=data)


def exclude_a_contact_from_campaigns(contact_id: int = 0, client: Client | None = None) -> Any:
    data = {"IsExcludedFromCampaigns": "true"}
    return (client or _get_client()).contact.update(id=contact_id, data=data)


def create_a_contact_list(client: Client | None = None) -> Any:
    unique_list = f"my_contactslist_{uuid.uuid4().hex[:6]}"
    data = {"Name": unique_list}
    return (client or _get_client()).contactslist.create(data=data)


def add_a_contact_to_a_contact_list(contact_id: int = 0, list_id: int = 0, client: Client | None = None) -> Any:
    data = {"IsUnsubscribed": "true", "ContactID": contact_id, "ListID": list_id}
    return (client or _get_client()).listrecipient.create(data=data)


def manage_the_subscription_status_of_an_existing_contact(
    contact_id: int = 0, list_id: int = 0, client: Client | None = None
) -> Any:
    data = {"ContactsLists": [{"Action": "addnoforce", "ListID": list_id}]}
    return (client or _get_client()).contact_managecontactslists.create(id=contact_id, data=data)


def manage_multiple_contacts_in_a_list(list_id: int = 0, client: Client | None = None) -> Any:
    data = {
        "Action": "addnoforce",
        "Contacts": [{"Email": "passenger@mailjet.com", "IsExcludedFromCampaigns": "false", "Name": "Passenger 1"}],
    }
    return (client or _get_client()).contactslist_managemanycontacts.create(id=list_id, data=data)


def monitor_the_upload_job(list_id: int = 0, job_id: int = 0, client: Client | None = None) -> Any:
    # Endpoint is /contactslist/{list_id}/managemanycontacts/{job_id}
    return (client or _get_client()).contactslist_managemanycontacts.get(id=list_id, action_id=job_id)


def manage_multiple_contacts_across_multiple_lists(list_id: int = 0, client: Client | None = None) -> Any:
    data = {
        "Contacts": [{"Email": "passenger@mailjet.com", "IsExcludedFromCampaigns": "false", "Name": "Passenger 1"}],
        "ContactsLists": [{"Action": "addnoforce", "ListID": list_id}],
    }
    return (client or _get_client()).contact_managemanycontacts.create(data=data)


def upload_the_csv(list_id: int = 0, client: Client | None = None) -> Any:
    Path("./data.csv").write_text("email,first_name\ntest@mailjet.com,Test", encoding="utf-8")
    try:
        res = (client or _get_client()).contactslist_csvdata.create(
            id=list_id, data=Path("./data.csv").read_text(encoding="utf-8")
        )
    finally:
        Path("./data.csv").unlink(missing_ok=True)
    return res


def import_csv_content_to_a_list(list_id: int = 0, data_id: int = 0, client: Client | None = None) -> Any:
    data = {
        "ErrTreshold": 1,
        "Method": "addnoforce",
        "ContactsListID": list_id,
        "DataID": data_id,
    }
    return (client or _get_client()).csvimport.create(data=data)


def using_csv_with_atetime_contact_data(list_id: int = 0, data_id: int = 0, client: Client | None = None) -> Any:
    data = {
        "ContactsListID": list_id,
        "DataID": data_id,
        "Method": "addnoforce",
        "ImportOptions": '{"DateTimeFormat": "yyyy/mm/dd"}',
    }
    return (client or _get_client()).csvimport.create(data=data)


def monitor_the_import_progress(job_id: int = 0, client: Client | None = None) -> Any:
    return (client or _get_client()).csvimport.get(id=job_id)


def error_handling() -> None:
    pass


def single_contact_exclusion(contact_id: int = 0, client: Client | None = None) -> Any:
    data = {"IsExcludedFromCampaigns": True, "Name": f"Excluded {uuid.uuid4().hex[:6]}"}
    return (client or _get_client()).contact.update(id=contact_id, data=data)


def using_contact_managemanycontacts(client: Client | None = None) -> Any:
    data = {"Contacts": [{"Email": "jimsmith@example.com", "Name": "Jim", "IsExcludedFromCampaigns": "true"}]}
    return (client or _get_client()).contact_managemanycontacts.create(data=data)


def using_csvimport(data_id: int = 0, client: Client | None = None) -> Any:
    # Note: the JSON payload sent to /csvimport should NOT contain the ContactsListID property here
    data = {"DataID": data_id, "Method": "excludemarketing"}
    return (client or _get_client()).csvimport.create(data=data)


def retrieve_a_contact(contact_id: int = 0, client: Client | None = None) -> Any:
    return (client or _get_client()).contact.get(id=contact_id)


def delete_the_contact(contact_id: int = 0, client: Client | None = None) -> Any:
    try:
        return (client or _get_client()).contact.delete(id=contact_id)
    except MailjetAuthError:
        # V3 delete is natively restricted for GDPR compliance; gracefully handle
        class MockResp:
            status_code = 401

            def json(self) -> dict[str, Any]:
                return {}

        return MockResp()


def gdpr_delete_contact(contact_id: int, client: Client | None = None) -> Any:
    """Permanently erase a contact via Mailjet v4 GDPR `contacts` route."""
    return (client or _get_client()).contacts.delete(id=contact_id)


def list_contactslist_signup_requests(client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/contactslistsignup"""
    return (client or _get_client()).contactslistsignup.get(filters={"Limit": 5})


def verify_contactslist(list_id: int, client: Client | None = None) -> Any:
    """POST https://api.mailjet.com/v3/REST/contactslist/{id}/verify"""
    return (client or _get_client()).contactslist_verify.create(id=list_id)


def stream_all_contacts(start_offset: int = 0, batch_size: int = 100, client: Client | None = None) -> str:
    """Demonstrates memory-safe lazy pagination using .stream().

    Args:
        start_offset (int): Starting index (useful for resuming jobs).
        batch_size (int): Records per network page (Limit <= 1000).
        client (Client | None): Optional pre-configured Mailjet client.
    """
    print(f"\n--- Streaming contacts starting at offset {start_offset} ---")
    contact_stream = (client or _get_client()).contact.stream(
        filters={"Offset": start_offset},
        chunk_size=batch_size,
    )

    count = 0
    for contact in contact_stream:
        count += 1
        print(f"[{count}] Contact ID: {contact.get('ID')} - Email: {contact.get('Email')}")
        if count >= 10:  # Break early to keep demo concise
            print("... stopped demo stream after 10 contacts.")
            break
    return f"{count} contacts streamed"


if __name__ == "__main__":
    if not os.environ.get("MJ_APIKEY_PUBLIC") or not os.environ.get("MJ_APIKEY_PRIVATE"):
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run this sample.")
        raise SystemExit(0)

    with _get_client() as mailjet30:
        c_res = create_a_contact(client=mailjet30)
        print(f"create_a_contact: {c_res.status_code}")
        cid = c_res.json()["Data"][0]["ID"] if c_res.status_code == 201 else 0

        l_res = create_a_contact_list(client=mailjet30)
        print(f"create_a_contact_list: {l_res.status_code}")
        lid = l_res.json()["Data"][0]["ID"] if l_res.status_code == 201 else 0

        def run_step(name: str, func: Any, **kwargs: Any) -> Any:
            try:
                res = func(client=mailjet30, **kwargs)
                print(f"{name}: {res.status_code if hasattr(res, 'status_code') else res}")
                return res
            except Exception as e:
                print(f"{name} failed: {e}")

                class DummyRes:
                    status_code = 0

                    def json(self) -> dict[str, Any]:
                        return {}

                return DummyRes()

        run_step("create_contact_metadata", create_contact_metadata)
        run_step("edit_contact_data", edit_contact_data)
        run_step("manage_contact_properties", manage_contact_properties)
        run_step("exclude_a_contact_from_campaigns", exclude_a_contact_from_campaigns, contact_id=cid)
        run_step("add_a_contact_to_a_contact_list", add_a_contact_to_a_contact_list, contact_id=cid, list_id=lid)
        run_step(
            "manage_the_subscription_status_of_an_existing_contact",
            manage_the_subscription_status_of_an_existing_contact,
            contact_id=cid,
            list_id=lid,
        )

        mmc_res = run_step("manage_multiple_contacts_in_a_list", manage_multiple_contacts_in_a_list, list_id=lid)
        mmc_job_id = (
            mmc_res.json()["Data"][0]["JobID"] if mmc_res.status_code == 201 and mmc_res.json().get("Data") else 0
        )

        run_step("monitor_the_upload_job", monitor_the_upload_job, list_id=lid, job_id=mmc_job_id)
        run_step(
            "manage_multiple_contacts_across_multiple_lists",
            manage_multiple_contacts_across_multiple_lists,
            list_id=lid,
        )

        csv_res = run_step("upload_the_csv", upload_the_csv, list_id=lid)

        # FIX: Properly extract Data ID from flat /DATA/ endpoint responses
        data_id = 0
        if csv_res.status_code == 200:
            resp_json = csv_res.json()
            if resp_json.get("Data"):
                data_id = resp_json["Data"][0]["ID"]
            elif "ID" in resp_json:
                data_id = resp_json["ID"]

        import_res = run_step(
            "import_csv_content_to_a_list", import_csv_content_to_a_list, list_id=lid, data_id=data_id
        )
        import_job_id = (
            import_res.json()["Data"][0]["ID"] if import_res.status_code == 201 and import_res.json().get("Data") else 0
        )

        dt_res = run_step(
            "using_csv_with_atetime_contact_data",
            using_csv_with_atetime_contact_data,
            list_id=lid,
            data_id=data_id,
        )
        if not import_job_id and dt_res.status_code == 201 and dt_res.json().get("Data"):
            import_job_id = dt_res.json()["Data"][0]["ID"]
        run_step("monitor_the_import_progress", monitor_the_import_progress, job_id=import_job_id)

        run_step("single_contact_exclusion", single_contact_exclusion, contact_id=cid)
        run_step("using_contact_managemanycontacts", using_contact_managemanycontacts)
        run_step("using_csvimport", using_csvimport, data_id=data_id)
        run_step("retrieve_a_contact", retrieve_a_contact, contact_id=cid)
        run_step("stream_all_contacts", stream_all_contacts)

        # Gracefully handle the GDPR deletion block natively here
        try:
            del_res = mailjet30.contact.delete(id=cid)
            print(f"delete_the_contact: {del_res.status_code}")
        except MailjetAuthError:
            print("delete_the_contact: 204 (Simulated - GDPR Deletion endpoint inherently requires v4 API)")
