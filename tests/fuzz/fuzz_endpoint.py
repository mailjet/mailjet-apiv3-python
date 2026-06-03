"""Atheris fuzzing target for registry-based URL construction and routing."""

import atheris
import sys
from unittest.mock import MagicMock

with atheris.instrument_imports():
    from mailjet_rest.endpoint import Endpoint
    from mailjet_rest.client import Client
    from mailjet_rest.errors import ValidationError

def TestOneInput(data: bytes) -> None:
    if len(data) < 5:
        return
    fdp = atheris.FuzzedDataProvider(data)

    mock_client = MagicMock(spec=Client)
    mock_client.api_call.return_value = MagicMock(status_code=200)

    url_choices = [
        "send", "contact", "contactslist_csvdata", "REST/contact", "DATA/contactslist",
        fdp.ConsumeUnicodeNoSurrogates(20)
    ]
    url = fdp.PickValueInList(url_choices)

    try:
        endpoint = Endpoint(name=url, client=mock_client)
        method_idx = fdp.ConsumeIntInRange(0, 3)

        id_type = fdp.ConsumeIntInRange(0, 2)
        if id_type == 0:
            id_val = ""
        elif id_type == 1:
            id_val = fdp.ConsumeInt(100)
        else:
            id_val = fdp.ConsumeUnicodeNoSurrogates(15)

        action_id = fdp.ConsumeUnicodeNoSurrogates(10) if fdp.ConsumeBool() else None

        # Aggressively Fuzz Pagination and Filters
        filters = {}
        if fdp.ConsumeBool():
            # Fuzz massive, negative, and 0 limits
            filters["limit"] = fdp.ConsumeIntInRange(-100, 1000000)
        if fdp.ConsumeBool():
            filters["offset"] = fdp.ConsumeIntInRange(-100, 1000000)
        if fdp.ConsumeBool():
            filters["sort"] = fdp.ConsumeUnicodeNoSurrogates(15)
        if fdp.ConsumeBool():
            filters["countOnly"] = fdp.ConsumeBool()

        # Add random noise payload
        payload = {fdp.ConsumeUnicodeNoSurrogates(5): fdp.ConsumeUnicodeNoSurrogates(10)}

        if method_idx == 0:
            endpoint.get(id=id_val, action_id=action_id, filters=filters)
        elif method_idx == 1:
            endpoint.create(data=payload, action_id=action_id)
        elif method_idx == 2:
            endpoint.update(id=id_val, data=payload, action_id=action_id)
        else:
            endpoint.delete(id=id_val, action_id=action_id)

    except (ValueError, TypeError, AttributeError, KeyError, ValidationError):
        # Invalid/malformed fuzz inputs are expected here; ignore and continue fuzzing.
        pass

def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
