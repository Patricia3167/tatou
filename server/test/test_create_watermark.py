import pytest
import requests

API_URL = "http://server:5000/api"

@pytest.mark.usefixtures("auth_headers", "uploaded_document")
def test_create_watermark(auth_headers, uploaded_document):
    payload = {
        "method": "axel",  
        "position": "top-left",
        "key": "testkey",
        "secret": "mysecret",
        "intended_for": "recipient@example.com",
        "id": uploaded_document["id"]
    }
    r = requests.post(f"{API_URL}/create-watermark", json=payload, headers=auth_headers)
    assert r.status_code == 200 or r.status_code == 201
    data = r.json()
    for field in ["id", "documentid", "link", "intended_for", "method", "position", "filename", "size"]:
        assert field in data
    assert str(data["documentid"]) == str(uploaded_document["id"])

    # --- Test that anyone with the link can download the watermarked document ---
    # Assume the 'link' field is a URL or a token to be appended to a download endpoint
    link = data["link"]
    # If 'link' is a full URL, use it directly; otherwise, construct the URL
    if link.startswith("http"):
        download_url = link
    else:
        download_url = f"{API_URL}/get-version/{link}"

    # Try to download without authentication
    resp = requests.get(download_url)
    assert resp.status_code == 200
    # Check that the response is a PDF
    assert resp.headers.get("Content-Type", "").startswith("application/pdf")
    assert resp.content.startswith(b"%PDF-")