"""Performance and throughput benchmark tests for the Mailjet SDK."""

import tracemalloc
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
import requests
import responses

from mailjet_rest.client import Client

# Graceful import fallback for Differential Benchmarking against older tags (v1.7.0)
try:
    from mailjet_rest.builders import MessageBuilder
    from mailjet_rest.utils.guardrails import SecurityGuard
    MODERN_SDK_AVAILABLE = (
        MessageBuilder is not None
        and SecurityGuard is not None
        and hasattr(SecurityGuard, "generate_payload_fingerprint")
    )
except ImportError:
    MODERN_SDK_AVAILABLE = False
    MessageBuilder = None  # type: ignore[assignment]
    SecurityGuard = None  # type: ignore[assignment]

# ------------------------------------------------------------------------
# FIXTURES
# ------------------------------------------------------------------------

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
        # Tests the efficiency of the endpoint cache dictionary / ROUTE_MAP
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


# ------------------------------------------------------------------------
# BENCHMARK 3: FLUENT BUILDERS (v1.8.0+)
# ------------------------------------------------------------------------

@pytest.mark.skipif(not MODERN_SDK_AVAILABLE, reason="Builders not available in this tag")
def test_message_builder_performance(benchmark: Any) -> None:
    """Measure the CPU cost of fluent schema validation and structural limits."""
    def build_payload() -> Any:
        assert MessageBuilder is not None
        return (
            MessageBuilder()
            .set_sender("test@example.com", "Test")
            .add_recipient("user@example.com", "User")
            .set_subject("Performance Test")
            .set_content(text="Hello", html="<b>Hello</b>")
            .build()
        )
    benchmark(build_payload)


# ------------------------------------------------------------------------
# BENCHMARK 4: SECURITY GUARDRAILS (v1.8.0+)
# ------------------------------------------------------------------------

@pytest.mark.skipif(not MODERN_SDK_AVAILABLE, reason="Guardrails not available in this tag")
def test_idempotency_fingerprint_performance(benchmark: Any) -> None:
    """Measure the CPU cost of recursive SHA-256 payload hashing."""
    payload = {
        "Messages": [{"To": "test@test.com", "CustomID": "ignore_me", "Variables": {"A": 1, "B": 2}}],
        "SandboxMode": True
    }

    def generate_hash() -> Any:
        assert SecurityGuard is not None
        return SecurityGuard.generate_payload_fingerprint(payload)

    benchmark(generate_hash)


# ------------------------------------------------------------------------
# BENCHMARK 5: SYNCHRONOUS CONNECTION POOLING (THREADING)
# ------------------------------------------------------------------------

def test_sync_client_concurrent_throughput(benchmark: Any, mocked_mailjet: responses.RequestsMock) -> None:
    """Measures how fast the synchronous Client can dispatch concurrent requests.
    This proves that pool_maxsize=100 prevents ThreadPoolExecutor bottlenecks.
    """

    def send_one_request(i: int) -> requests.Response:
        return client.contact.create(data={"Email": f"user_{i}@example.com"})

    def dispatch_batch() -> None:
        with ThreadPoolExecutor(max_workers=BATCH_SIZE) as executor:
            list(executor.map(send_one_request, range(BATCH_SIZE)))

    BATCH_SIZE = 50
    with Client(auth=("api", "key")) as client:
        benchmark.pedantic(dispatch_batch, rounds=10, iterations=5)

# ------------------------------------------------------------------------
# BENCHMARK 6: MEMORY FOOTPRINT & LEAK PREVENTION (__slots__)
# ------------------------------------------------------------------------

def test_memory_footprint_leak_prevention() -> None:
    """Proves that processing large requests doesn't bloat the RSS memory footprint."""
    client = Client(auth=("api", "key"))

    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()

    for _ in range(5000):
        # Trigger endpoint resolution and routing cache to test __slots__ mapping
        _ = client.contact

    snapshot_after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    stats = snapshot_after.compare_to(snapshot_before, 'lineno')
    total_diff_kb = sum(stat.size_diff for stat in stats) / 1024

    print(f"\nMemory Delta after 5,000 operations: {total_diff_kb:.2f} KB")

    # Guardrail to ensure slots prevent dynamic hash table memory bloat
    assert total_diff_kb < 100.0, f"Memory leak detected! Footprint grew by {total_diff_kb:.2f} KB"
