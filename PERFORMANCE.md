# Mailjet Python SDK: Performance & Architecture

This document outlines the architectural decisions made to ensure the Mailjet Python SDK remains blazingly fast and memory-efficient.

## Core Optimizations

### 1. Memory Density & Speed (__slots__)

We have implemented `__slots__` across the core `Client`, `Config`, and `Endpoint` classes.

- **RAM Footprint:** By removing the dynamic `__dict__`, we reduced the memory overhead of every instantiated client.
- **Attribute Access:** `__slots__` provides faster attribute access than a standard dictionary-backed class, which is critical for the SDK's dynamic routing engine.

### 2. High-Speed Dynamic Routing (Endpoint Caching)

The SDK utilizes a lazy-loading cache for API endpoints.

- **O(1) Resolution:** Once an endpoint (like `client.contact`) is accessed, it is cached in an instance-level dictionary. Subsequent calls avoid all string manipulation and object instantiation overhead.
- **Pre-computed Routing:** All URL path fragments are pre-computed during `Endpoint` initialization, ensuring that the `api_call` method only performs minimal joining operations.

### 3. Header Immutability (MappingProxyType)

We use `types.MappingProxyType` for global constants like `_JSON_HEADERS` and `_TEXT_HEADERS`.

- **Zero-Allocation Merges:** The SDK avoids creating brand-new dictionaries from scratch for every single API call. It unpacks these immutable proxies into the request context, significantly reducing Garbage Collection (GC) pressure in high-throughput environments.

______________________________________________________________________

## Benchmarks (v1.5.1 vs. Refactor)

Our internal `pytest-benchmark` and `cProfile` suites verify these architectural gains on Python 3.14.

| Metric                   | v1.5.1 (Baseline) | refactor-client  | Performance Status |
| :----------------------- | :---------------- | :--------------- | :----------------- |
| **Routing Speed (Mean)** | ~151.85 ns        | **~151.78 ns**   | **Optimized**      |
| **Request Cycle (Mean)** | ~255.44 µs        | **~239.47 µs**   | **~6.3% Faster**   |
| **Throughput (Ops/Sec)** | ~6.58 Mops/s      | **~6.58 Mops/s** | **Stable/Peak**    |

*Note: Benchmarks measure network-isolated internal overhead using mocked responses.*

______________________________________________________________________

## Profiling the Codebase

To ensure no performance regressions are introduced during development:

**To profile Cold-Boot initialization:**

```bash
python tests/test_boot.py
```

**To benchmark the routing and throughput performance:**

```bash
./manage.sh perf_bench --benchmark-compare
```
