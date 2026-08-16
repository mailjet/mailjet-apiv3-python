"""Configuration settings for the Mailjet SDK."""

from dataclasses import dataclass
from typing import ClassVar

from mailjet_rest._version import __version__
from mailjet_rest.types import _DEFAULT_TIMEOUT, TimeoutType
from mailjet_rest.utils.guardrails import SecurityGuard


@dataclass(slots=True, kw_only=True)
class Config:
    """Configuration settings for interacting with the Mailjet API.

    Attributes:
        ALLOWED_ROOT_DOMAIN (ClassVar[str]): The permitted root domain to prevent SSRF.
        version (str): The API version to use (e.g., 'v3', 'v3.1', 'v1').
        api_url (str): The base URL for the Mailjet API.
        user_agent (str): The User-Agent string sent with API requests.
        timeout (TimeoutType): Request timeout in seconds.
    """

    ALLOWED_ROOT_DOMAIN: ClassVar[str] = "mailjet.com"

    version: str = "v3"
    api_url: str = "https://api.mailjet.com/"
    user_agent: str = f"mailjet-apiv3-python/v{__version__}"
    timeout: TimeoutType = _DEFAULT_TIMEOUT
    dry_run: bool = False
    enable_security_audit: bool = False

    def __post_init__(self) -> None:
        """Validate configuration for secure transport and resource limits (OWASP Input Validation)."""
        # Ensure trailing slash for API pathing consistency
        if not self.api_url.endswith("/"):
            self.api_url += "/"

        # 1. Validate the URL (Guardrail now naturally handles localhost for CI/CD!)
        SecurityGuard.validate_config_url(self.api_url, allowed_root_domain=self.ALLOWED_ROOT_DOMAIN)

        # 2. Validate the timeouts securely (Guardrail handles both scalars and tuples natively)
        self.timeout = SecurityGuard.validate_timeout(self.timeout)
