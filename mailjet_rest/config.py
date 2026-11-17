"""Configuration settings for the Mailjet SDK."""

from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from mailjet_rest._version import __version__
from mailjet_rest.types import _DEFAULT_TIMEOUT, AutoIdempotencyMode, TimeoutType
from mailjet_rest.utils.guardrails import SecurityGuard


_VALID_IDEMPOTENCY_MODES: frozenset[str] = frozenset({"fingerprint", "uuid4", "off"})


@dataclass(slots=True, kw_only=True)
class Config:
    """Configuration settings for interacting with the Mailjet API.

    Attributes:
        ALLOWED_ROOT_DOMAIN (ClassVar[str]): The permitted root domain to prevent SSRF.
        version (str): The API version to use (e.g., 'v3', 'v3.1', 'v1').
        api_url (str): The base URL for the Mailjet API.
        user_agent (str): The User-Agent string sent with API requests.
        timeout (TimeoutType): Request timeout in seconds.
        dry_run (bool): Intercept mutating calls without performing network requests.
        enable_security_audit (bool): Enable runtime PEP 578 security audit event emission.
        verify (bool | str | Path): TLS verification setting or path to a custom CA bundle.
        auto_idempotency_mode (AutoIdempotencyMode): Strategy for auto-populating Idempotency-Key.
        pool_connections (int): Number of urllib3 connection pools to cache per Client.
        pool_maxsize (int): Maximum number of persistent connections saved per pool.
        warn_unclosed (bool): Emit ResourceWarning on garbage collection if session was not closed.
        max_retries (int): Maximum retry attempts for transient connection and HTTP errors.
    """

    ALLOWED_ROOT_DOMAIN: ClassVar[str] = "mailjet.com"

    version: str = "v3"
    api_url: str = "https://api.mailjet.com/"
    user_agent: str = f"mailjet-apiv3-python/v{__version__}"
    timeout: TimeoutType = _DEFAULT_TIMEOUT
    dry_run: bool = False
    enable_security_audit: bool = False
    verify: bool | str | Path = True
    auto_idempotency_mode: AutoIdempotencyMode = "fingerprint"
    pool_connections: int = 100
    pool_maxsize: int = 100
    warn_unclosed: bool = False
    max_retries: int = 3

    @staticmethod
    def _validate_int_min(name: str, value: int, minimum: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            msg = f"{name} must be an integer >= {minimum}, got {value!r}."
            raise ValueError(msg)

    def __post_init__(self) -> None:
        """Validate configuration for secure transport and resource limits (OWASP Input Validation)."""
        # Ensure trailing slash for API pathing consistency
        if not self.api_url.endswith("/"):
            self.api_url += "/"

        # 1. Validate the URL (Guardrail now naturally handles localhost for CI/CD!)
        SecurityGuard.validate_config_url(self.api_url, allowed_root_domain=self.ALLOWED_ROOT_DOMAIN)

        # 2. Validate the timeouts securely (Guardrail handles both scalars and tuples natively)
        self.timeout = SecurityGuard.validate_timeout(self.timeout)

        # 3. Validate TLS verification mode / custom CA bundle path (CWE-295)
        self.verify = SecurityGuard.resolve_tls_verify(self.verify)

        # 4. Validate auto-idempotency strategy
        if self.auto_idempotency_mode not in _VALID_IDEMPOTENCY_MODES:
            msg = f"Invalid auto_idempotency_mode {self.auto_idempotency_mode!r}; expected one of {sorted(_VALID_IDEMPOTENCY_MODES)}."
            raise ValueError(msg)

        # 5. Validate connection pool bounds, retry budget, and warning flags
        self._validate_int_min("pool_connections", self.pool_connections, 1)
        self._validate_int_min("pool_maxsize", self.pool_maxsize, 1)
        self._validate_int_min("max_retries", self.max_retries, 0)
        raw_warn: object = self.warn_unclosed
        if not isinstance(raw_warn, bool):
            msg = f"warn_unclosed must be a bool, got {type(raw_warn).__name__}."
            raise TypeError(msg)
