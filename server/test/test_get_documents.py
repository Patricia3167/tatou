import requests
import pytest

API_URL = "http://server:5000/api"

def test_get_document_owner_access(auth_headers, uploaded_document):
    """
    Verifierar att dokumentet är åtkomligt för ägaren via både query- och path-param.
    Sparar filen för manuell kontroll.
    """
    doc_id = uploaded_document["id"]

    # GET med query parameter
    url_query = f"{API_URL}/get-document?id={doc_id}"
    r_query = requests.get(url_query, headers=auth_headers)
    assert r_query.status_code == 200
    assert r_query.headers["Content-Type"] == "application/pdf"
    assert len(r_query.content) > 0

    # GET med path parameter
    url_path = f"{API_URL}/get-document/{doc_id}"
    r_path = requests.get(url_path, headers=auth_headers)
    assert r_path.status_code == 200
    assert r_path.headers["Content-Type"] == "application/pdf"
    assert len(r_path.content) > 0

    # Spara filen lokalt för visuell kontroll
    with open("downloaded_test_owner.pdf", "wb") as f:
        f.write(r_path.content)


def test_get_document_other_user_restricted(auth_headers, uploaded_document, user2):
    """
    Verifierar att dokument utan watermark inte är åtkomliga för andra användare.
    """
    doc_id = uploaded_document["id"]

    # Logga in som annan användare
    login_payload = {"email": user2["email"], "password": user2["password"]}
    login_resp = requests.post(f"{API_URL}/login", json=login_payload)
    assert login_resp.status_code == 200
    token = login_resp.json()["token"]
    other_headers = {"Authorization": f"Bearer {token}"}

    # Försök hämta dokumentet med annan användare
    url = f"{API_URL}/get-document/{doc_id}"
    r = requests.get(url, headers=other_headers)

    # Dokument utan watermark ska inte vara åtkomliga för andra
    assert r.status_code in (401, 403, 404)


def test_get_document_watermark_owner(auth_headers, uploaded_document):
    """
    Valfritt: kontroll av watermark, kan utökas beroende på API-logik.
    Här kontrollerar vi åtkomst för ägaren.
    """
    doc_id = uploaded_document["id"]
    url = f"{API_URL}/get-document/{doc_id}"
    r = requests.get(url, headers=auth_headers)
    assert r.status_code == 200
    assert r.headers["Content-Type"] == "application/pdf"
    assert len(r.content) > 0