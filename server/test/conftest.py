import io
import pytest
import requests
import uuid

API_URL = "http://server:5000/api"

@pytest.fixture
def new_user():
    unique = uuid.uuid4().hex[:8]
    user = {
        "login": f"testuser_{unique}",
        "password": "testpass123",
        "email": f"testuser_{unique}@example.com"
    }
    r = requests.post(f"{API_URL}/create-user", json=user)
    assert r.status_code == 201
    return user

@pytest.fixture
def auth_headers(new_user):
    r = requests.post(f"{API_URL}/login", json={
        "email": new_user["email"],
        "password": new_user["password"]
    })
    assert r.status_code == 200
    token = r.json()["token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def uploaded_document(auth_headers):
    dummy_pdf = io.BytesIO(b"%PDF-1.4\n%EOF\n")
    files = {
        "file": ("test.pdf", dummy_pdf, "application/pdf"),
        "name": (None, "test.pdf")
    }
    r = requests.post(f"{API_URL}/upload-document", files=files, headers=auth_headers)
    assert r.status_code == 201
    return r.json()
