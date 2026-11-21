from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _load_edit_contact_data() -> object:
    """Import edit_contact_data regardless of whether repo root or samples/ is on sys.path."""
    repo_root = str(Path(__file__).resolve().parent.parent)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from samples.contacts_sample import edit_contact_data  # ruff: ignore[import-outside-top-level]

    return edit_contact_data


if __name__ == "__main__":
    if not os.environ.get("MJ_APIKEY_PUBLIC") or not os.environ.get("MJ_APIKEY_PRIVATE"):
        print("Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to run this sample.")
        raise SystemExit(0)

    edit_contact_data: object = _load_edit_contact_data()
    assert callable(edit_contact_data)
    result = edit_contact_data()
    print(result.status_code)
    try:
        print(json.dumps(result.json(), indent=4))
    except json.decoder.JSONDecodeError:
        print(result.text)
