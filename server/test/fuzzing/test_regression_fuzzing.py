import requests

API_URL = "http://server:5000/api"
HEADERS = {"Authorization": "Bearer VALID_TEST_TOKEN"}

# -------------------------------
# Regression tests: /get-document
# -------------------------------

def test_colon_id_does_not_crash():
    r = requests.get(f"{API_URL}/get-document/:", headers=HEADERS)
    assert r.status_code in (400, 404)
