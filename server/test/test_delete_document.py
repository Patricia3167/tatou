import requests
import pytest

API_URL = "http://server:5000/api"

def test_delete_document_owner(auth_headers, uploaded_document):
    """
    Testar att dokumentägaren kan ta bort sitt dokument.
    """
    doc_id = uploaded_document["id"]

    # DELETE via path parameter
    url_path = f"{API_URL}/delete-document/{doc_id}"
    r_path = requests.delete(url_path, headers=auth_headers)
    assert r_path.status_code == 200
    resp_json = r_path.json()
    assert resp_json["deleted"] is True
    assert resp_json["id"] == doc_id

    # Kontrollera att dokumentet inte längre finns för ägaren
    url_check = f"{API_URL}/get-document/{doc_id}"
    r_check = requests.get(url_check, headers=auth_headers)
    assert r_check.status_code == 404


def test_delete_document_other_user_forbidden(auth_headers, uploaded_document, new_user):
    """
    Testar att en annan användare inte kan ta bort dokument som tillhör någon annan.
    """
    doc_id = uploaded_document["id"]

    # Logga in som annan användare
    login_payload = {"email": new_user["email"], "password": new_user["password"]}
    login_resp = requests.post(f"{API_URL}/login", json=login_payload)
    assert login_resp.status_code == 200
    token = login_resp.json()["token"]
    other_headers = {"Authorization": f"Bearer {token}"}

    # Försök DELETE
    url = f"{API_URL}/delete-document/{doc_id}"
    r = requests.delete(url, headers=other_headers)

    # Eftersom dokumentet tillhör någon annan ska det inte gå
    assert r.status_code in (401, 403, 404)