import requests
import json

def test_list_versions(auth_headers, uploaded_document, new_user):
    # Check available watermarking methods
    r_methods = requests.get("http://server:5000/api/get-watermarking-methods", headers=auth_headers)
    print("Available methods:", r_methods.json())

    doc_id = uploaded_document["id"]

    watermark_data = {
        "method": "axel",
        "intended_for": new_user["email"],
        "secret": "mysecret",
        "key": "mykey"
    }
    r = requests.post(
        f"http://server:5000/api/create-watermark/{doc_id}",
        json=watermark_data,
        headers=auth_headers
    )
    print(json.dumps(watermark_data, indent=2))
    print(r.status_code, r.text)
    assert r.status_code in (200, 201), f"Watermark creation failed: {r.status_code}, {r.text}"

    r = requests.get(f"http://server:5000/api/list-versions/{doc_id}", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "versions" in data
    assert isinstance(data["versions"], list)
    assert len(data["versions"]) >= 1