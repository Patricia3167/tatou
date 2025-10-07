import requests

API_URL = "http://server:5000/api"

def test_get_document(auth_headers, uploaded_document):
    doc_id = uploaded_document["id"]

    # Testa GET med query parameter
    url_query = f"{API_URL}/get-document?id={doc_id}"
    r_query = requests.get(url_query, headers=auth_headers)
    assert r_query.status_code == 200
    assert r_query.headers["Content-Type"] == "application/pdf"
    assert len(r_query.content) > 0  # PDF-filen innehåller data

    # Testa GET med path-parameter
    url_path = f"{API_URL}/get-document/{doc_id}"
    r_path = requests.get(url_path, headers=auth_headers)
    assert r_path.status_code == 200
    assert r_path.headers["Content-Type"] == "application/pdf"
    assert len(r_path.content) > 0

    # Valfritt: spara filen för manuell kontroll
    with open("downloaded_test.pdf", "wb") as f:
        f.write(r_path.content)