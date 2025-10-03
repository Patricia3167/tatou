import requests


def test_list_documents(auth_headers, uploaded_document):
    doc_id = uploaded_document["id"]

    r = requests.get(f"http://server:5000/api/list-documents", headers=auth_headers)
    assert r.status_code == 200
    docs = r.json()["documents"]

    assert any(d["id"] == doc_id for d in docs)
    found = next(d for d in docs if d["id"] == doc_id)
    assert found["name"] == "test.pdf"
    assert "creation" in found
    assert "sha256" in found
    assert "size" in found
