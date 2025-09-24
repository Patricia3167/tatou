import fitz  # PyMuPDF
from pathlib import Path
import hashlib

from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    WatermarkingError,
    SecretNotFoundError,
)



def _derive_key_stream(key: str, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        h = hashlib.sha256()
        h.update(key.encode("utf-8"))
        h.update(counter.to_bytes(4, "big"))
        out += h.digest()
        counter += 1
    return out[:length]

def _encrypt_secret(secret: str, key: str) -> str:
    plain = secret.encode("utf-8")
    ks = _derive_key_stream(key, len(plain))
    enc = bytes(a ^ b for a, b in zip(plain, ks))
    return enc.hex()

def _decrypt_secret(enc_hex: str, key: str) -> str:
    enc = bytes.fromhex(enc_hex)
    ks = _derive_key_stream(key, len(enc))
    plain = bytes(a ^ b for a, b in zip(enc, ks))
    return plain.decode("utf-8", errors="replace")


class LogoWatermark(WatermarkingMethod):
    name = "logo-watermark"

    @staticmethod
    def get_usage() -> str:
        return "Lägger till en logotyp som watermark på varje sida. position='center' eller 'bottom-right'."

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,   # här kan du t.ex. ignorera secret, eller använda för placering
        key: str,      # ev. framtida kryptering
        position: str | None = None,
    ) -> bytes:
        try:
            data = load_pdf_bytes(pdf)
            doc = fitz.open(stream=data, filetype="pdf")

            enc = _encrypt_secret(secret, key)
            meta = dict(doc.metadata) if doc.metadata else {}
            if "secret_enc" in meta:
                raise WatermarkingError("PDF already contains a secret key — refusing to overwrite.")
            meta["secret_enc"] = enc
            doc.set_metadata(meta)

            logo_path = Path(__file__).parent / "Unknown.jpg"
            rect = None

            for page in doc:
                if position == "center":
                    r = page.rect
                    rect = fitz.Rect(
                        r.width/2 - 50, r.height/2 - 50,
                        r.width/2 + 50, r.height/2 + 50
                    )
                else:  # default bottom-right
                    r = page.rect
                    rect = fitz.Rect(r.width - 120, r.height - 120, r.width - 20, r.height - 20)

                page.insert_image(rect, filename=str(logo_path), overlay=True, opacity=0.4)

                # Draw the secret text in the top-left corner with reduced opacity
                text_position = fitz.Point(20, 40)
                text_color = (0, 0, 0)  # black
                text_opacity = 0.3
                # Use a simple font and size
                page.insert_text(
                    text_position,
                    secret,
                    fontsize=12,
                    fontname="helv",
                    fill=text_color,
                    overlay=True,
                    render_mode=0,
                    opacity=text_opacity,
                )

            return doc.write()
        except Exception as e:
            raise WatermarkingError(f"Failed to add logo watermark: {e}") from e

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        try:
            _ = load_pdf_bytes(pdf)
            return True
        except Exception:
            return False

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        try:
            data = load_pdf_bytes(pdf)
            doc = fitz.open(stream=data, filetype="pdf")
            metadata = dict(doc.metadata) if doc.metadata else {}
            secret_enc = metadata.get("secret_enc")
            if not secret_enc:
                raise SecretNotFoundError("Encrypted secret not found in PDF metadata.")
            secret = _decrypt_secret(secret_enc, key)
            return secret
        except Exception as e:
            raise SecretNotFoundError(f"Failed to read secret from logo watermark: {e}") from e