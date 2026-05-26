from mailjet_rest.endpoint import _route_csv

def test_csv_routing_traversal_prevention()-> None:
    """Ensure path traversal payloads are handled/blocked in URL construction."""
    # This characterization test pins current behavior
    base = "https://api.mailjet.com"
    ver = "v3"
    # A path traversal attempt
    payload = ["../secret"]

    url = _route_csv(base, ver, payload, "123", "action", "filename")
    # Assert that the output URL does not contain an unencoded directory traversal
    assert ".." not in url
