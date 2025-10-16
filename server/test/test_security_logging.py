import os
import io
import pytest
import requests
from time import sleep

SECURITY_LOG = os.path.join(os.path.dirname(__file__), "../src/security.log")

@pytest.fixture
def clear_security_log():
    """Rensar säkerhetsloggen före varje test."""
    if os.path.exists(SECURITY_LOG):
        os.remove(SECURITY_LOG)
    yield
    sleep(0.5)  # vänta lite för att låta loggern skriva färdigt
    if os.path.exists(SECURITY_LOG):
        with open(SECURITY_LOG, "r") as f:
            print("\n---- SECURITY LOG ----\n" + f.read() + "-----------------------")


def read_security_log():
    """Läser hela säkerhetsloggen."""
    if not os.path.exists(SECURITY_LOG):
        return ""
    with open(SECURITY_LOG, "r") as f:
        return f.read()


def test_failed_login_logs_warning(clear_security_log):
    data = {"email": "nonexistent@example.com", "password": "wrongpass"}
    r = requests.post("http://server:5000/api/login", json=data)
    assert r.status_code == 401

    log = read_security_log()
    assert "Failed login attempt" in log, "Should log failed login attempt"


def test_invalid_file_upload_logs_warning(auth_headers, clear_security_log):
    # Skapa en falsk .txt-fil i minnet
    fake_file = io.BytesIO(b"not a pdf")
    files = {"file": ("fake.txt", fake_file, "text/plain")}
    r = requests.post("http://server:5000/api/upload-document", headers=auth_headers, files=files)
    assert r.status_code == 400

    log = read_security_log()
    assert "Invalid file extension attempt" in log or "Invalid MIME type upload attempt" in log


def test_unauthorized_document_access_logs_warning(auth_headers, clear_security_log):
    # Försök läsa ett dokument som inte tillhör användaren
    r = requests.get("http://server:5000/api/get-document/99999", headers=auth_headers)
    assert r.status_code in [403, 404]

    log = read_security_log()
    assert "Unauthorized access attempt" in log


def test_unauthorized_delete_logs_warning(auth_headers, clear_security_log):
    # Försök ta bort ett dokument som inte finns
    r = requests.delete("http://server:5000/api/delete-document/99999", headers=auth_headers)
    assert r.status_code in [403, 404]

    log = read_security_log()
    assert "Unauthorized delete attempt" in log