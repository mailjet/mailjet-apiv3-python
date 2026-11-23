"""Examples for Mailjet Batch Sending and BatchJob endpoints."""

from __future__ import annotations

import os
from typing import Any

from mailjet_rest import Client
from mailjet_rest.errors import DoesNotExistError


def _get_client() -> Client:
    """Create a Mailjet v3 Client lazily from environment credentials."""
    return Client(
        auth=(os.environ.get("MJ_APIKEY_PUBLIC", ""), os.environ.get("MJ_APIKEY_PRIVATE", "")),
    )


def send_batch_payload(client: Client | None = None) -> Any:
    """POST https://api.mailjet.com/v3/batch"""
    data = {
        "Action": "send",
        "Requests": [
            {
                "FromEmail": "pilot@mailjet.com",
                "FromName": "Mailjet Pilot",
                "Subject": "Batch message 1",
                "Text-part": "Hello from Mailjet batch!",
                "Recipients": [{"Email": "passenger1@mailjet.com"}],
            }
        ],
    }
    return (client or _get_client()).batch.create(data=data)


def list_batch_jobs(limit: int = 5, client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/batchjob"""
    return (client or _get_client()).batchjob.get(filters={"Limit": limit})


def get_batch_job(job_id: int, client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/REST/batchjob/{id}"""
    return (client or _get_client()).batchjob.get(id=job_id)


def get_batch_job_csv_error(job_id: int, client: Client | None = None) -> Any:
    """GET https://api.mailjet.com/v3/DATA/batchjob/{id}/CSVError/text:csv"""
    return (client or _get_client()).batchjob_csverror.get(id=job_id)


if __name__ == "__main__":
    if not os.environ.get("MJ_APIKEY_PUBLIC") or not os.environ.get("MJ_APIKEY_PRIVATE"):
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run this sample.")
    else:
        with _get_client() as mailjet30:
            jobs = list_batch_jobs(limit=1, client=mailjet30)
            print(f"list_batch_jobs: {jobs.status_code}")
            job_id = jobs.json()["Data"][0]["ID"] if jobs.status_code == 200 and jobs.json().get("Data") else 0

            if job_id:
                for func in (get_batch_job, get_batch_job_csv_error):
                    try:
                        res = func(job_id=job_id, client=mailjet30)
                        print(f"{func.__name__}: {res.status_code}")
                    except DoesNotExistError:
                        if func is get_batch_job_csv_error:
                            print("get_batch_job_csv_error: 404 (no CSV errors recorded for this job)")
                        else:
                            print(f"{func.__name__}: 404 (not found)")
                    except Exception as exc:
                        print(f"{func.__name__} failed: {exc}")
            # Mutating call kept optional for safety:
            # send_batch_payload(client=mailjet30)
