from hypothesis import given, strategies as st
import requests

API_URL = "http://server:5000/api"
HEADERS = {"Authorization": "Bearer VALID_TEST_TOKEN"}

@given(st.text(min_size=1, max_size=64))
def test_fuzz_get_document_invalid_ids(fuzz_id):
    url_query = f"{API_URL}/get-document?id={fuzz_id}"
    r_query = requests.get(url_query, headers=HEADERS)
    assert r_query.status_code in (400, 401, 403, 404)

    url_path = f"{API_URL}/get-document/{fuzz_id}"
    r_path = requests.get(url_path, headers=HEADERS)
    assert r_path.status_code in (400, 401, 403, 404)