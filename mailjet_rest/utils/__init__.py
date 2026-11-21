"""Utility subpackage for security guardrails, transport TLS, retries, routing, telemetry, and versioning.

Modules:
    - filesystem_security: Attachment path traversal and multipart filename/header validation.
    - guardrails: Centralized OWASP API security guardrails and redacting log filter.
    - html_guard: Lazy HTML XSS and tag-bomb parser checks.
    - retry: Full-jitter retry policy, Retry-After parsing, and stream pointer reset helpers.
    - routing: Stateless endpoint URL resolution, query casting, and pagination helpers.
    - telemetry: Sanitized API trace extraction and lifecycle response logging.
    - transport_security: Hardened TLS 1.2+ SSLContext caching, keep-alive adapter, and SecretAuth.
    - version: Package semantic version parsing and normalization.
"""
