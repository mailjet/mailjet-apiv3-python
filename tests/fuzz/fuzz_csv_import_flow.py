import sys
import atheris
from typing import Any

import logging
logging.getLogger().handlers.clear()
logging.disable(logging.CRITICAL)

with atheris.instrument_imports():
    from mailjet_rest import Client

# ==========================================
# GLOBAL SETUP (No network calls allowed)
# ==========================================
client = Client(auth=("test", "test"), version="v3")

class DumbResponse:
    def __init__(self, status_code, json_data):
        self.status_code = status_code
        self._json = json_data
        self.text = str(json_data)

    def json(self):
        return self._json

    def raise_for_status(self):
        # Mock successful status check
        pass

def dumb_mock_request(*args: Any, **kwargs: Any) -> DumbResponse:
    # Return a mocked 200 OK response with dummy json data
    return DumbResponse(200, {"ID": 12345, "Data": [{"ID": 67890}]})

# Intercept all outbound network requests
client.session.request = dumb_mock_request  # type: ignore[method-assign, assignment]

def TestOneInput(data: bytes) -> None:
    # Cap size to prevent memory bottlenecks during CSV string synthesis
    if len(data) > 4096:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # 1. Fuzz the CSV Upload Route
    # Here we simulate feeding entirely broken, malformed, or injected strings
    # instead of your clean data.csv file.
    fuzzed_csv_data = fdp.ConsumeUnicodeNoSurrogates(1000)
    list_id = fdp.ConsumeIntInRange(1, 99999999)

    try:
        client.contactslist_csvdata.create(id=list_id, data=fuzzed_csv_data)
    except (ValueError, TypeError):
        # Expected for malformed fuzz inputs; ignore and continue fuzzing.
        pass

    # 2. Fuzz the Import Job Creation Payload
    # Can the SDK handle weird types, SQL injection tokens, or massive integers?
    import_data = {
        "Method": fdp.ConsumeUnicodeNoSurrogates(20),
        "ContactsListID": list_id,
        "DataID": fdp.ConsumeIntInRange(1, 99999999) if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(10),
    }

    try:
        client.csvimport.create(data=import_data)
    except (ValueError, TypeError):
        # Expected for malformed fuzz inputs; ignore and continue fuzzing.
        pass

if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
