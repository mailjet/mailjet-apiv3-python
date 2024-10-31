from mailjet_rest.client import Client
from mailjet_rest.utils.version import get_version

__version__: str = get_version()

__all__ = ["Client", "get_version"]
