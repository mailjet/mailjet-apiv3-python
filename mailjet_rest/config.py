"""Configuration settings for the Mailjet SDK."""

import math
from dataclasses import dataclass
from typing import ClassVar

from mailjet_rest._version import __version__
from mailjet_rest.types import _DEFAULT_TIMEOUT, _JSON_HEADERS, _TEXT_HEADERS, TimeoutType
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
        """Validate configuration for secure transport and resource limits (OWASP Input Validation).

        Raises:
            ValueError: If the URL scheme is insecure or timeout bounds are violated.
        """
        SecurityGuard.validate_config_url(self.api_url, allowed_root_domain=self.ALLOWED_ROOT_DOMAIN)

        if not self.api_url.endswith("/"):
            self.api_url += "/"

        if self.timeout is not None:
            if isinstance(self.timeout, tuple):
                if len(self.timeout) != 2:
                    msg = "Timeout tuple must contain exactly two elements (connect, read)."
                    raise ValueError(msg)
                clean_tuple = []
                for t in self.timeout:
                    # 1. Scope type coercion strictly
                    try:
                        val = float(t)
                    except (ValueError, TypeError) as e:
                        msg = f"Invalid timeout tuple element: {t}"
                        raise ValueError(msg) from e

                    # 2. Scope invariant validation separately
                    if math.isnan(val) or math.isinf(val) or val <= 0:
                        msg = f"Timeout tuple values must be positive finite numbers, got {val}"
                        raise ValueError(msg)

                    clean_tuple.append(val)
                self.timeout = tuple(clean_tuple)  # type: ignore[assignment]
            else:
                # 1. Scope type coercion strictly
                try:
                    val = float(self.timeout)
                except (ValueError, TypeError) as e:
                    msg = f"Security Violation: Timeout must be numeric, got {type(self.timeout).__name__}."
                    raise ValueError(msg) from e

                # 2. Scope invariant validation separately
                if math.isnan(val) or math.isinf(val) or val <= 0:
                    msg = f"Timeout must be a strictly positive finite number, got {val}"
                    raise ValueError(msg)

                self.timeout = val

    def __getitem__(self, key: str) -> tuple[str, dict[str, str]]:
        """Retrieve the base API endpoint URL and default headers for a given key.

        Args:
            key (str): The raw endpoint key name.

        Returns:
            tuple[str, dict[str, str]]: A tuple containing the base URL and the headers dictionary.
        """
        action = key.split("_", maxsplit=1)[0]
        name_lower = key.lower()

        if name_lower == "send":
            url = f"{self.api_url}{self.version}/send"
        elif name_lower.endswith(("_csvdata", "_csverror")):
            url = f"{self.api_url}{self.version}/DATA/{action}"
        elif key.lower().startswith("data_"):
            action_path = key.replace("_", "/")
            url = f"{self.api_url}{self.version}/{action_path}"
        else:
            url = f"{self.api_url}{self.version}/REST/{action}"

        # Utilize the pre-allocated constants to save dictionary creation overhead
        headers = dict(_TEXT_HEADERS) if name_lower.endswith("_csvdata") else dict(_JSON_HEADERS)

        return url, headers
