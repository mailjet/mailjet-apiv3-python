# Mailjet Python SDK: Performance & Architecture

This document outlines the architectural decisions made to ensure the Mailjet Python SDK remains blazingly fast and memory-efficient.

## Core Optimizations

### 1. High-Speed Static Routing (O(1) Registry)

The SDK utilizes a static, immutable routing registry (`ROUTE_MAP`).

- **O(1) Resolution:** Dynamic `__getattr__` and procedural `if/elif` URL construction chains have been entirely replaced. Endpoint resolution is now a direct dictionary hash lookup, effectively pushing routing speed to the theoretical limit of the Python interpreter.
- **Pre-computed Routing:** All URL path fragments are pre-computed and mapped during initialization, ensuring that the API call dispatcher performs zero dynamic string manipulation.

### 2. Memory Density & Speed (`__slots__`)

We implemented `__slots__` across the core `Client`, `Config`, and `Endpoint` infrastructure classes.

- **RAM Footprint:** By removing the dynamic `__dict__`, we drastically reduced the memory allocation overhead of every instantiated client object.
- **Attribute Access:** `__slots__` provides strictly faster attribute access than standard dictionary-backed classes.

### 3. Allocation Avoidance & Cold-Boot Optimization

- **Zero-Allocation Headers:** We use `types.MappingProxyType` for global constants (e.g., `_JSON_HEADERS`). The SDK avoids creating brand-new dictionaries from scratch for every single API call, unpacking these immutable proxies directly.
- **Optimized Imports:** By replacing module-level regular expression compilation (`re.compile`) with native string methods, cold-boot initialization time has been reduced by ~28%, making the SDK highly suitable for Serverless/Lambda environments.

## The Benchmarks

Despite adding strict OWASP security guardrails (PEP 578 Audit Hooks, Path Traversal mitigations, URL quoting), the architectural refactoring yielded massive performance gains across the board.

### v1.5.1 vs. v1.6.0 (Architecture Overhaul)

The initial refactor (v1.6.0) replaced heavy string-parsing with object caching. We deliberately traded a fractional increase in one-time startup cost (to load modern typing and dataclasses) for a massive, repeatable increase in runtime routing speed and request throughput.

| Metric                   | Legacy (v1.5.1) | Baseline (v1.6.0) | Delta              |
| :----------------------- | :-------------- | :---------------- | :----------------- |
| **Routing Speed (Mean)** | ~7.61 µs        | **~210.94 ns**    | **~36x Faster**    |
| **Request Cycle (Mean)** | ~271.67 µs      | **~256.78 µs**    | **~5.4% Faster**   |
| **Routing Ops/Sec**      | ~131 Kops/s     | **~4,740 Kops/s** | **Massive Boost**  |
| **Cold-Boot Init Time**  | **~0.099 s**    | ~0.176 s          | *+77ms (Expected)* |

### v1.6.0 vs. Current Refined (v1.7.0)

The subsequent refinement fully replaced the procedural caching layer with a static O(1) immutable dictionary (`ROUTE_MAP`) and stripped out regex from the import sequence. This completely recovered the cold-boot penalty while compounding the routing speed even further.

| Metric                   | Baseline (v1.6.0) | Current Refined   | Delta                    |
| :----------------------- | :---------------- | :---------------- | :----------------------- |
| **Routing Speed (Mean)** | ~210.94 ns        | **~138.73 ns**    | **~34.2% Faster**        |
| **Routing Speed (Min)**  | ~125.03 ns        | **~82.88 ns**     | **Sub-100ns execution**  |
| **Request Cycle (Mean)** | ~256.78 µs        | **~250.81 µs**    | **~2.3% Faster**         |
| **Routing Ops/Sec**      | ~4,740 Kops/s     | **~7,208 Kops/s** | **+2.4 Million Ops/sec** |
| **Cold-Boot Init Time**  | ~0.176 s          | **~0.126 s**      | **~50ms Faster (~28%)**  |

*Note: Benchmarks measure network-isolated internal overhead using mocked `responses`. Testing hardware: Darwin-CPython-3.12-64bit.*

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
