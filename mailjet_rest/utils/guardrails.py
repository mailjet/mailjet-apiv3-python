"""Utility module for attribute and routing guardrails."""


def validate_attribute_access(class_name: str, name: str) -> None:
    """Validate dynamic attribute access to prevent magic method traps and secret leakage.

    Args:
        class_name (str): The name of the calling class (used for standard error formatting).
        name (str): The name of the requested attribute.

    Raises:
        AttributeError: If attempting to access private/magic methods or explicitly blocked attributes.
    """
    # 1. Poka-Yoke: Reject Python internal magic methods and private attributes
    if name.startswith("_"):
        msg = f"'{class_name}' object has no attribute '{name}'"
        raise AttributeError(msg)

    # 2. Poka-Yoke: Reject explicitly removed attributes to guide the developer
    if name == "auth":
        msg = (
            "The 'auth' attribute was intentionally removed to prevent CWE-316 "
            "(Cleartext Storage of Secrets). Please source credentials directly "
            "from your environment configuration (e.g., os.environ)."
        )
        raise AttributeError(msg)
