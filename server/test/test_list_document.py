import requests
import uuid


def test_list_documents(auth_headers, uploaded_document):
    doc_id = uploaded_document["id"]

    # Owner can see their document metadata
    r = requests.get(f"http://localhost:5000/api/list-documents", headers=auth_headers)
    assert r.status_code == 200
    docs = r.json()["documents"]

    assert any(d["id"] == doc_id for d in docs)
    found = next(d for d in docs if d["id"] == doc_id)
    assert found["name"] == "test.pdf"
    assert "creation" in found
    assert "sha256" in found
    assert "size" in found

    # Confidentiality check: another user should not see this document's metadata
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

    # Other user should not see the document in their list
    r_other = requests.get(f"http://localhost:5000/api/list-documents", headers=other_headers)
    assert r_other.status_code == 200
    other_docs = r_other.json()["documents"]
    assert all(d["id"] != doc_id for d in other_docs), "Metadata leak: other user can see document info"
