import re
import pytest
import tempfile
import io
from pathlib import Path
from server import app, db_url, create_app, get_method
from watermarking_utils import get_method
from watermarking_method import load_pdf_bytes
from axel_watermark import AxelWatermark
from fitz import open as fitz_open

#for mutants server.x_db_url__mutmut_10 & server.x_db_url__mutmut_9
def test_db_url_uses_correct_db_name(monkeypatch):
    # Patch app.config to use a known db name
    test_db_name = "tatou_test_db"
    with app.app_context():
        app.config["DB_USER"] = "user"
        app.config["DB_PASSWORD"] = "pw"
        app.config["DB_HOST"] = "localhost"
        app.config["DB_PORT"] = 3306
        app.config["DB_NAME"] = test_db_name

        url = db_url()
        # The DB name should appear in the URL
        assert re.search(r"/{}[?]".format(test_db_name), url), f"DB name {test_db_name} not found in db_url: {url}"
        

#for mutant watermarking_utils.x_get_method__mutmut_1
def test_get_method_unknown_method_message():
    with pytest.raises(KeyError) as excinfo:
        get_method("not_a_method")
    # Check that the exception message contains the expected text
    assert "Unknown watermarking method" in str(excinfo.value)

#for mutant server.x_create_app__mutmut_1
def test_create_app_returns_flask_instance():
    app = create_app()
    assert isinstance(app, Flask), "create_app() should return a Flask app instance"

#for mutant server.x_create_app__mutmut_200
def test_sha256_file_reads_file_correctly():
    app = create_app()
    with app.app_context():
        # Create a temporary file with known content
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test content")
            tmp_path = Path(tmp.name)

        # Import the function
        from server import _sha256_file

        # Should not raise TypeError and should return a valid hash
        result = _sha256_file(tmp_path)
        assert isinstance(result, str)
        assert len(result) == 64  # SHA256 hex digest length

        tmp_path.unlink()  # Clean up

# for mutant server.x_get_engine__mutmut_6
def test_get_engine_returns_engine_instance():
    from server import get_engine
    from sqlalchemy.engine import Engine

    with app.app_context():
        engine = get_engine()
        assert engine is not None, "get_engine() should not return None"
        assert isinstance(engine, Engine), "get_engine() should return a SQLAlchemy Engine instance"

#for mutant server.x_get_engine__mutmut_16
def test_get_engine_caches_engine_instance():
    from server import get_engine
    from sqlalchemy.engine import Engine

    with app.app_context():
        # First call should create and cache the engine
        engine1 = get_engine()
        # Second call should return the same instance (from cache)
        engine2 = get_engine()
        assert engine1 is engine2, "get_engine() should cache and return the same engine instance"
        assert "_ENGINE" in app.config, "Engine should be cached in app.config['_ENGINE']"
        assert isinstance(app.config["_ENGINE"], Engine)

#for mutant watermarking_method.x_load_pdf_bytes__mutmut_1
def test_load_pdf_bytes_with_bytes():
    pdf_bytes = b"%PDF-1.4 test"
    result = load_pdf_bytes(pdf_bytes)
    assert result == pdf_bytes, "load_pdf_bytes should return the input bytes unchanged"

#for mutant watermarking_method.x_load_pdf_bytes__mutmut_17
def test_load_pdf_bytes_with_filelike():
    pdf_bytes = b"%PDF-1.4 test"
    filelike = io.BytesIO(pdf_bytes)
    result = load_pdf_bytes(filelike)
    assert result == pdf_bytes, "load_pdf_bytes should return the bytes from a file-like object unchanged"

# for mutant axel_watermark.x_add_watermark__mutmut_15
def test_add_watermark_requires_filetype(monkeypatch):
    # Create a minimal valid PDF
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    secret = "mysecret"
    key = "mykey"
    aw = AxelWatermark()

    # This should not raise and should return bytes
    result = aw.add_watermark(pdf=pdf_bytes, secret=secret, key=key)
    assert isinstance(result, bytes)

# for mutant axel_watermark.x_add_watermark__mutmut_3
def test_add_watermark_missing_key_message():
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    secret = "mysecret"
    aw = AxelWatermark()
    with pytest.raises(ValueError) as excinfo:
        aw.add_watermark(pdf=pdf_bytes, secret=secret, key=None)
    assert "key (master key) must be provided" in str(excinfo.value)

#for mutant axel_watermark.xǁAxelWatermarkǁis_watermark_applicable__mutmut_1
def test_is_watermark_applicable_with_valid_pdf():
    aw = AxelWatermark()
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    assert aw.is_watermark_applicable(pdf_bytes) is True

#for mutant axel_watermark.xǁAxelWatermarkǁis_watermark_applicable__mutmut_13
def test_is_watermark_applicable_with_invalid_pdf():
    aw = AxelWatermark()
    not_pdf_bytes = b"not a pdf"
    assert aw.is_watermark_applicable(not_pdf_bytes) is False

# for mutant axel_watermark.xǁAxelWatermarkǁread_secret__mutmut_2
def test_read_secret_missing_key_message():
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    aw = AxelWatermark()
    with pytest.raises(ValueError) as excinfo:
        aw.read_secret(pdf=pdf_bytes, key=None)
    assert "key (master key) must be provided" in str(excinfo.value)

# for mutant axel_watermark.xǁAxelWatermarkǁread_secret__mutmut_9
def test_read_secret_requires_filetype():
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    key = "mykey"
    aw = AxelWatermark()
    # This should not raise and should return a string
    result = aw.read_secret(pdf=pdf_bytes, key=key)
    assert isinstance(result, str)

#for mutant johan_watermark.xǁLogoWatermarkǁadd_watermark__mutmut_2
def test_logo_add_watermark_generates_secret_if_missing():
    from johan_watermark import LogoWatermark
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    key = "mykey"
    lw = LogoWatermark()
    # Call with secret=None
    result = lw.add_watermark(pdf=pdf_bytes, secret=None, key=key)
    assert isinstance(result, bytes)

#for mutant johan_watermark.xǁLogoWatermarkǁadd_watermark__mutmut_58
def test_logo_add_watermark_error_message():
    from johan_watermark import LogoWatermark, WatermarkingError
    lw = LogoWatermark()
    invalid_pdf = b"not a pdf"
    key = "mykey"
    with pytest.raises(WatermarkingError) as excinfo:
        lw.add_watermark(pdf=invalid_pdf, secret="secret", key=key)
    assert "Failed to add logo watermark" in str(excinfo.value)

#for mutant johan_watermark.xǁLogoWatermarkǁread_secret__mutmut_5
def test_logo_read_secret_requires_filetype():
    from johan_watermark import LogoWatermark
    lw = LogoWatermark()
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    key = "mykey"
    # This should not raise and should return a string
    result = lw.read_secret(pdf=pdf_bytes, key=key)
    assert isinstance(result, str)

#for mutant johan_watermark.xǁLogoWatermarkǁread_secret__mutmut_23
def test_logo_read_secret_error_message():
    from johan_watermark import LogoWatermark, InvalidKeyError
    lw = LogoWatermark()
    invalid_pdf = b"not a pdf"
    key = "mykey"
    with pytest.raises(InvalidKeyError) as excinfo:
        lw.read_secret(pdf=invalid_pdf, key=key)
    assert "Failed to read secret from logo watermark" in str(excinfo.value)

#for mutant johan_watermark.xǁLogoWatermarkǁis_watermark_applicable__mutmut_1
from johan_watermark import LogoWatermark

def test_logo_is_watermark_applicable_with_valid_pdf():
    lw = LogoWatermark()
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    assert lw.is_watermark_applicable(pdf_bytes) is True

def test_logo_is_watermark_applicable_with_invalid_pdf():
    lw = LogoWatermark()
    not_pdf_bytes = b"not a pdf"
    assert lw.is_watermark_applicable(not_pdf_bytes) is False

#for mutant pj_watermarking_method.xǁMyWatermarkingMethodǁadd_watermark__mutmut_7
def test_mywatermarkingmethod_add_watermark_zero_pages_message():
    from pj_watermarking_method import MyWatermarkingMethod, WatermarkingError
    from io import BytesIO
    # Create a minimal PDF with zero pages
    empty_pdf = b"%PDF-1.4\ntrailer\n<<>>\n%%EOF"
    mwm = MyWatermarkingMethod()
    with pytest.raises(WatermarkingError) as excinfo:
        mwm.add_watermark(pdf=empty_pdf, secret="secret", key="key")
    assert "Cannot add watermark: PDF has zero pages." in str(excinfo.value)

#for mutant pj_watermarking_method.xǁMyWatermarkingMethodǁadd_watermark__mutmut_52
def test_mywatermarkingmethod_watermark_text():
    from pj_watermarking_method import MyWatermarkingMethod
    from io import BytesIO
    import fitz # PyMuPDF

    # Create a minimal valid PDF with one page
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    mwm = MyWatermarkingMethod()
    result = mwm.add_watermark(pdf=pdf_bytes, secret="secret", key="key")

    # Open the result with PyMuPDF and extract text
    doc = fitz.open(stream=result, filetype="pdf")
    text = ""
    for page in doc:
        text += page.get_text()
    assert "Watermark" in text, "The watermark text should be present in the output PDF"

#for mutant pj_watermarking_method.xǁMyWatermarkingMethodǁis_watermark_applicable__mutmut_4
def test_mywatermarkingmethod_is_watermark_applicable():
    from pj_watermarking_method import MyWatermarkingMethod
    mwm = MyWatermarkingMethod()
    valid_pdf = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    invalid_pdf = b"not a pdf"
    assert mwm.is_watermark_applicable(valid_pdf) is True
    assert mwm.is_watermark_applicable(invalid_pdf) is False

#for mutant pj_watermarking_method.xǁMyWatermarkingMethodǁread_secret__mutmut_15
def test_mywatermarkingmethod_read_secret_no_watermark_message():
    from pj_watermarking_method import MyWatermarkingMethod, SecretNotFoundError
    mwm = MyWatermarkingMethod()
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    with pytest.raises(SecretNotFoundError) as excinfo:
        mwm.read_secret(pdf=pdf_bytes, key="key")
    assert "No watermark found." in str(excinfo.value)



