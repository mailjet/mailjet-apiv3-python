"""Asynchronous Mailjet SDK usage example using AsyncClient (httpx2)."""

from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from mailjet_rest.types import SendV31Payload


async def main() -> None:
    """Demonstrate AsyncClient health check, RFC 8058 builders, send_v31, patch, and stream pagination."""
    from mailjet_rest import AsyncClient, Config  # ruff: ignore[import-outside-top-level]
    from mailjet_rest.builders import MessageBuilder, SendPayloadBuilder  # ruff: ignore[import-outside-top-level]

    api_key = os.environ.get("MJ_APIKEY_PUBLIC", "")
    api_secret = os.environ.get("MJ_APIKEY_PRIVATE", "")
    if not api_key or not api_secret:
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run this sample.")
        return

    message = (
        MessageBuilder()
        .set_sender("pilot@mailjet.com", "Mailjet Pilot")
        .add_recipient("passenger1@mailjet.com", "Passenger 1")
        .set_subject("Async flight plan")
        .set_content(text="Sent asynchronously with mailjet-rest[async]!")
        .set_tracking(opens="enabled", clicks="enabled")
        .set_list_unsubscribe("https://example.com/unsubscribe", "unsubscribe@example.com")
        .build()
    )
    payload: SendV31Payload = SendPayloadBuilder().add_message(message).set_sandbox_mode(True).build()

    async with AsyncClient(auth=(api_key, api_secret), config=Config(max_retries=2, warn_unclosed=True)) as client:
        if not await client.ping():
            print("Mailjet API ping failed; check credentials or connectivity.")
            return

        print("Available endpoints:", len(client.available_endpoints))
        send_resp = await client.send_v31.create(data=payload)
        print("Send v3.1 status:", send_resp.status_code)

        first_contact_id: int | None = None
        async for contact in client.contact.stream(chunk_size=100, max_items=5):
            if first_contact_id is None and isinstance(contact.get("ID"), int):
                first_contact_id = contact["ID"]
            print("Contact:", contact.get("Email"))

        if first_contact_id is not None:
            patch_resp = await client.contact.patch(
                id=first_contact_id,
                data={"Name": "Passenger Updated"},
            )
            print("PATCH contact status:", patch_resp.status_code)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except ImportError as exc:
        print(f"Async extra not installed ({exc}). Run: pip install 'mailjet-rest[async]'")
