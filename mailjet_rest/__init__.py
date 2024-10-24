from mailjet_rest.client import Client
from mailjet_rest.utils.version import get_version


__version__ = get_version()

# TODO: E0604: Invalid object 'Client' and 'get_version' in __all__, must
# contain only strings (invalid-all-object)
__all__ = (Client, get_version)
