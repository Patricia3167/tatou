import requests

def test_list_versions(auth_headers, uploaded_document):
    doc_id = uploaded_document["id"]

    # Provide required params for axel method
    watermark_data = {
        "method": "axel",
        "params": {
            "secret": "mysecret",
            "key": "mykey"
            # Add "position": "..." if required by your API
        }
    }
    r = requests.post(
        f"http://server:5000/api/create-watermark/{doc_id}",
        json=watermark_data,
        headers=auth_headers
    )
    assert r.status_code in (200, 201)

    # Now list versions
    r = requests.get(f"http://server:5000/api/list-versions/{doc_id}", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "versions" in data
    assert isinstance(data["versions"], list)
    assert len(data["versions"]) >= 1  # There should be at least one version now