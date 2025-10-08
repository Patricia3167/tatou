import pytest
import requests
import uuid

API_URL = "http://server:5000/api"

@pytest.mark.usefixtures("auth_headers", "watermarked_document")
def test_read_watermark(auth_headers, watermarked_document):
    # Use the watermark info from the fixture
    payload = watermarked_document["watermark"]
    doc_id = watermarked_document["id"]

    # 1. Owner retrieves the secret using read-watermark
    read_payload = {
        "method": payload["method"],
        "key": payload["key"],
        "id": doc_id
    }
    r2 = requests.post(f"{API_URL}/read-watermark", json=read_payload, headers=auth_headers)
    assert r2.status_code in (200, 201), f"Read watermark failed: {r2.status_code} {r2.text}"
    result = r2.json()
    assert result["secret"] == payload["secret"]
    assert result["method"] == payload["method"]

    # 2. Another user should NOT be able to retrieve the secret
    other_unique = uuid.uuid4().hex[:8]
    other_user = {
        "login": f"otheruser_{other_unique}",
        "password": "otherpass123",
        "email": f"otheruser_{other_unique}@example.com"
    }
    r_create = requests.post(f"{API_URL}/create-user", json=other_user)
    assert r_create.status_code == 201
    r_login = requests.post(f"{API_URL}/login", json={
        "email": other_user["email"],
        "password": other_user["password"]
    })
    assert r_login.status_code == 200
    other_token = r_login.json()["token"]
    other_headers = {"Authorization": f"Bearer {other_token}"}

    r3 = requests.post(f"{API_URL}/read-watermark", json=read_payload, headers=other_headers)
    # Should be forbidden or not found
    assert r3.status_code in (401, 403, 404), f"Metadata leak: {r3.status_code}, {r3.text}"