import requests
import json
import uuid

def test_list_versions(auth_headers, uploaded_document, user2):
    # Check available watermarking methods
    r_methods = requests.get("http://localhost:5000/api/get-watermarking-methods", headers=auth_headers)
    print("Available methods:", r_methods.json())

    doc_id = uploaded_document["id"]

    watermark_data = {
        "method": "my-method-secure",
        "intended_for": user2["email"],
        "secret": "mysecret",
        "key": "mykey"
    }
    r = requests.post(
        f"http://localhost:5000/api/create-watermark/{doc_id}",
        json=watermark_data,
        headers=auth_headers
    )
    print(json.dumps(watermark_data, indent=2))
    print(r.status_code, r.text)
    assert r.status_code in (200, 201), f"Watermark creation failed: {r.status_code}, {r.text}"

    # Owner can list versions
    r = requests.get(f"http://localhost:5000/api/list-versions/{doc_id}", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "versions" in data
    assert isinstance(data["versions"], list)
    assert len(data["versions"]) >= 1

    # --- Confidentiality check: another user should NOT see versions or metadata ---
    # Register and login as a different user
    unique = uuid.uuid4().hex[:8]
    other_user = {
        "login": f"otheruser_{unique}",
        "password": "otherpass123",
        "email": f"otheruser_{unique}@example.com"
    }
    r_create = requests.post("http://localhost:5000/api/create-user", json=other_user)
    assert r_create.status_code == 201
    r_login = requests.post("http://localhost:5000/api/login", json={
        "email": other_user["email"],
        "password": other_user["password"]
    })
    assert r_login.status_code == 200
    other_token = r_login.json()["token"]
    other_headers = {"Authorization": f"Bearer {other_token}"}

    # Try to list versions as a different user
    r_other = requests.get(f"http://localhost:5000/api/list-versions/{doc_id}", headers=other_headers)
    # Should be forbidden or not found
    assert r_other.status_code in (401, 403, 404), f"Metadata leak: {r_other.status_code}, {r_other.text}"