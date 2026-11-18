"""Asynchronous Mailjet SDK usage example using AsyncClient (httpx2)."""

from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from mailjet_rest.types import SendV31Payload


async def main() -> None:
    """Demonstrate AsyncClient health check, send_v31, patch, and stream pagination."""
    from mailjet_rest import AsyncClient, Config  # ruff: ignore[import-outside-top-level]

    api_key = os.environ.get("MJ_APIKEY_PUBLIC", "")
    api_secret = os.environ.get("MJ_APIKEY_PRIVATE", "")
    if not api_key or not api_secret:
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run this sample.")
        return

    payload: SendV31Payload = {
        "SandboxMode": True,
        "Messages": [
            {
                "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                "To": [{"Email": "passenger1@mailjet.com", "Name": "Passenger 1"}],
                "Subject": "Async flight plan",
                "TextPart": "Sent asynchronously with mailjet-rest[async]!",
            }
        ],
    }

    async with AsyncClient(auth=(api_key, api_secret), config=Config(max_retries=2)) as client:
        if not await client.ping():
            print("Mailjet API ping failed; check credentials or connectivity.")
            return

        print("Available endpoints:", len(client.available_endpoints))
        send_resp = await client.send_v31.create(data=payload)
        print("Send v3.1 status:", send_resp.status_code)

        async for contact in client.contact.stream(chunk_size=100, max_items=5):
            print("Contact:", contact.get("Email"))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except ImportError as exc:
        print(f"Async extra not installed ({exc}). Run: pip install 'mailjet-rest[async]'")
