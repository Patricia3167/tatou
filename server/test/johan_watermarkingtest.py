import sys
from pathlib import Path

# Add server/src to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import fitz
from johan_watermark import LogoWatermark  # Now imports from server/src/johan_watermark.py

def create_sample_pdf(path: str):
    """Skapar en minimal PDF med en sida för test."""
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)  # A4
    page.insert_text(fitz.Point(72, 72), "Test PDF", fontsize=20)
    doc.save(path)

def test_logo_watermark():
    input_pdf_path = "test_input.pdf"
    output_pdf_path = "test_output.pdf"

    # Skapa test-PDF
    create_sample_pdf(input_pdf_path)

    # Läs PDF som bytes
    with open(input_pdf_path, "rb") as f:
        pdf_bytes = f.read()

    # Initiera watermarking
    wm = LogoWatermark()
    key = "hemlignyckel123"

    # Lägg watermark
    try:
        out_bytes = wm.add_watermark(pdf_bytes, secret=None, key=key)
    except Exception as e:
        print("Watermarking failed:", e)
        return

    # Spara PDF med watermark
    with open(output_pdf_path, "wb") as f:
        f.write(out_bytes)
    print("Watermark applied, saved to:", output_pdf_path)

    # Läs secret
    try:
        secret = wm.read_secret(out_bytes, key=key)
        print("Secret read from PDF:", secret)
    except Exception as e:
        print("Failed to read secret:", e)

if __name__ == "__main__":
    # Kontrollera att loggan finns i samma katalog
    logo_path = Path(__file__).parent / "unknown.jpg"
    if not logo_path.exists():
        raise FileNotFoundError(f"Logga saknas: {logo_path}")

    test_logo_watermark()