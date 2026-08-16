"""Property-based tests for Mailjet SDK Pagination and Streaming.
Powered by Hypothesis.
"""

from unittest.mock import MagicMock

from hypothesis import given, settings, strategies as st

from mailjet_rest.client import Client
from mailjet_rest.endpoint import Endpoint


# Disable the 200ms deadline because simulating hundreds of paginated
# mocked HTTP requests can occasionally exceed the time limit on CI servers.
@settings(max_examples=300, deadline=None)
@given(total_items=st.integers(min_value=0, max_value=5000), chunk_size=st.integers(min_value=1, max_value=1000))
def test_property_pagination_math(total_items: int, chunk_size: int) -> None:
    """INVARIANT: The `.stream()` generator must request the exact number of pages
    required based on chunk_size, correctly increment the 'Offset' query parameter,
    and yield exactly `total_items`. It must never enter an infinite loop.
    """
    mock_client = MagicMock(spec=Client)

    # Explicitly configure the mocked config to avoid string formatting errors
    # inside Endpoint._build_url during execution
    mock_client.config = MagicMock()
    mock_client.config.version = "v3"
    mock_client.config.api_url = "https://api.mailjet.com/"

    endpoint = Endpoint(client=mock_client, name="contact")

    # Generate a dummy dataset
    database = [{"ID": i} for i in range(total_items)]

    # Mock the client's API call to intercept the HTTP logic securely.
    # This avoids issues with patching __slots__ bounded methods on the Endpoint.
    def mock_api_call(*args, **kwargs):
        filters = kwargs.get("filters") or {}
        offset = filters.get("Offset", 0)
        limit = filters.get("Limit", chunk_size)

        # Slice the database exactly like the real API would
        page_data = database[offset : offset + limit]

        mock_response = MagicMock()
        mock_response.json.return_value = {"Data": page_data}
        return mock_response

    mock_client.api_call.side_effect = mock_api_call

    # Consume the stream
    streamed_items = list(endpoint.stream(chunk_size=chunk_size))

    # 1. Total items yielded must exactly match the database size
    assert len(streamed_items) == total_items

    # 2. The items must be perfectly sequential, proving no data was skipped or duplicated
    for index, item in enumerate(streamed_items):
        assert item["ID"] == index
