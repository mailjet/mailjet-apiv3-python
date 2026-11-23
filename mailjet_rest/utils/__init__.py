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

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Callable

    from mailjet_rest.utils import (
        filesystem_security as filesystem_security,
        guardrails as guardrails,
        html_guard as html_guard,
        retry as retry,
        routing as routing,
        telemetry as telemetry,
        transport_security as transport_security,
        version as version,
    )

_UTIL_SUBMODULE_LOADERS: dict[str, Callable[[], Any]] = {
    "filesystem_security": lambda: importlib.import_module("mailjet_rest.utils.filesystem_security"),
    "guardrails": lambda: importlib.import_module("mailjet_rest.utils.guardrails"),
    "html_guard": lambda: importlib.import_module("mailjet_rest.utils.html_guard"),
    "retry": lambda: importlib.import_module("mailjet_rest.utils.retry"),
    "routing": lambda: importlib.import_module("mailjet_rest.utils.routing"),
    "telemetry": lambda: importlib.import_module("mailjet_rest.utils.telemetry"),
    "transport_security": lambda: importlib.import_module("mailjet_rest.utils.transport_security"),
    "version": lambda: importlib.import_module("mailjet_rest.utils.version"),
}


def __getattr__(name: str) -> Any:
    """Resolve utility submodules lazily via PEP 562.

    Returns:
        Any: Imported ``mailjet_rest.utils.<name>`` submodule.
    """
    loader = _UTIL_SUBMODULE_LOADERS.get(name)
    if loader is None:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)
    submod = loader()
    globals()[name] = submod
    return submod
