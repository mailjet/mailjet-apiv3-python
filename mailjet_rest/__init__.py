"""The `mailjet_rest` package provides a Python client for interacting with the Mailjet API.

This package includes the main `Client` class for handling API requests, along with
utility functions for version management. The package exposes a consistent interface
for Mailjet API operations.

Attributes:
    __version__ (str): The current version of the `mailjet_rest` package.
    __all__ (list): Specifies the public API of the package, including `Client`
        for API interactions and `get_version` for retrieving version information.

Modules:
    - client: Defines the main API client.
    - utils.version: Provides version management functionality.
"""

from mailjet_rest.client import Client
from mailjet_rest.utils.version import get_version


__version__: str = get_version()

__all__ = ["Client", "get_version"]
