# Mailjet Python SDK: Performance & Architecture

This document outlines the architectural decisions made to ensure the Mailjet Python SDK remains blazingly fast and memory-efficient.

## Core Optimizations (Introduced in v1.6.0)

### 1. High-Speed Dynamic Routing (Endpoint Caching)

The SDK utilizes a lazy-loading cache for API endpoints.

- **O(1) Resolution:** Once an endpoint (like `client.contact`) is accessed, it is cached in an instance-level dictionary. Subsequent calls bypass dynamic string manipulation and object instantiation.
- **Pre-computed Routing:** All URL path fragments are pre-computed during `Endpoint` initialization, ensuring that the `api_call` method only performs minimal, highly optimized string joining.

### 2. Memory Density & Speed (`__slots__`)

We implemented `__slots__` across the core `Client`, `Config`, and `Endpoint` classes.

- **RAM Footprint:** By removing the dynamic `__dict__`, we reduced the memory overhead of every instantiated client.
- **Attribute Access:** `__slots__` provides strictly faster attribute access than standard dictionary-backed classes, yielding a massive ~50x speedup in routing operations.

### 3. Allocation Avoidance (`MappingProxyType` & `ClassVar`)

- **Zero-Allocation Headers:** We use `types.MappingProxyType` for global constants like `_JSON_HEADERS`. The SDK avoids creating brand-new dictionaries from scratch for every single API call, unpacking these immutable proxies directly.
- **Shared Retry Strategies:** The `urllib3` retry configuration was moved to a `ClassVar`, preventing the instantiation of redundant retry adapters on every request.

______________________________________________________________________

## Benchmarks (v1.5.1 vs. v1.6.0 Refactor)

Our internal `pytest-benchmark` and `cProfile` suites verify these architectural gains on Python 3.14. Despite adding heavy OWASP security guardrails (PEP 578 Audit Hooks, SSRF prevention, Regex validation), the memory optimizations yielded a net performance increase.

| Metric                   | v1.5.1 (Baseline) | Optimized Architecture | Delta             |
| :----------------------- | :---------------- | :--------------------- | :---------------- |
| **Routing Speed (Mean)** | ~7.66 µs          | **~0.15 µs (152 ns)**  | **~50x Faster**   |
| **Request Cycle (Mean)** | ~260.94 µs        | **~243.70 µs**         | **~6.6% Faster**  |
| **Routing Ops/Sec**      | ~130 Kops/s       | **~6,566 Kops/s**      | **Massive Boost** |

*Note: Benchmarks measure network-isolated internal overhead using mocked `responses`. Testing hardware: Darwin-CPython-3.14-64bit.*

______________________________________________________________________

## Profiling the Codebase

To ensure no performance regressions are introduced during development, run the following commands:

**To profile Cold-Boot initialization (useful for Serverless/Lambda environments):**

```bash
python tests/test_boot.py
```

**To benchmark the routing and throughput performance:**

```bash
./manage.sh perf_bench --benchmark-compare
```
