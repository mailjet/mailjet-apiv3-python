from typing import Any, Generator
import pytest
import responses
from mailjet_rest.client import Client

# ------------------------------------------------------------------------
# FIXTURES
# ------------------------------------------------------------------------

# --- Fixture needs a Generator return type ---
@pytest.fixture
def mocked_mailjet() -> Generator[responses.RequestsMock, None, None]:
    """Intercepts Mailjet API calls at the urllib3 layer for stable benchmarks."""
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(
            responses.POST,
            "https://api.mailjet.com/v3/REST/contact",
            json={"Count": 1, "Data": [{"ID": 123}]},
            status=201,
        )
        yield rsps


# ------------------------------------------------------------------------
# BENCHMARK 1: ROUTING OVERHEAD (CPU)
# ------------------------------------------------------------------------

def test_client_routing_speed(benchmark: Any) -> None:
    """Measure CPU overhead of the dynamic __getattr__ router and caching logic."""
    client = Client(auth=("api", "key"))

    def route_contact() -> Any:
        # Tests the efficiency of the endpoint cache dictionary
        return client.contact

    benchmark(route_contact)

# ------------------------------------------------------------------------
# BENCHMARK 2: FULL REQUEST CYCLE (MOCKED NETWORK)
# ------------------------------------------------------------------------

def test_request_cycle_performance(benchmark: Any, mocked_mailjet: responses.RequestsMock) -> None:
    """Measure the time from method call to response (with zero network delay)."""
    client = Client(auth=("api", "key"))
    payload = {"Email": "perf@example.com", "Name": "Benchmark User"}

    def send_request() -> Any:
        return client.contact.create(data=payload)

    # Use pedantic mode for higher accuracy across multiple iterations
    benchmark.pedantic(send_request, rounds=50, iterations=10)
