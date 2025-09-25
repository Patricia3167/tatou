from __future__ import annotations
from io import BytesIO
from typing import Optional
import base64
import hashlib

import fitz  # PyMuPDF
from cryptography.fernet import Fernet, InvalidToken

from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
)


class AxelWatermark(WatermarkingMethod):
    name = "axel"

    @staticmethod
    def get_usage() -> str:
        return "Embeds an encrypted secret in visible and invisible watermarks. Key decrypts to reveal the secret."

    @staticmethod
    def _derive_fernet_key(key: str) -> bytes:
        """Derive a 32-byte urlsafe base64 key for Fernet from an arbitrary-length key."""
        h = hashlib.sha256(key.encode("utf-8")).digest()  # 32 bytes
        return base64.urlsafe_b64encode(h)  # Fernet expects base64-encoded 32 bytes

    @staticmethod
    def _encrypt_secret(secret: str, key: str) -> str:
        fkey = AxelWatermark._derive_fernet_key(key)
        f = Fernet(fkey)
        token = f.encrypt(secret.encode("utf-8"))
        return token.decode("utf-8")

    @staticmethod
    def _decrypt_secret(encrypted: str, key: str) -> str:
        fkey = AxelWatermark._derive_fernet_key(key)
        f = Fernet(fkey)
        try:
            plain = f.decrypt(encrypted.encode("utf-8"))
            return plain.decode("utf-8")
        except InvalidToken as e:
            raise ValueError("decryption failed") from e

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        if not key:
            raise ValueError("key must be a non-empty session key")
        if not secret:
            raise ValueError("secret must be provided to embed")

        data = load_pdf_bytes(pdf)
        doc = fitz.open(stream=data, filetype="pdf")

        # Encrypt the secret before embedding
        encrypted = self._encrypt_secret(secret, key)

        # Visible and invisible payloads contain the encrypted token (not the plaintext secret)
        visible_text = f"Watermarked with Axel-Watermark (encrypted)\n{encrypted}\nDo not distribute"
        invisible_text = f"Watermarked with Axel-Watermark (encrypted) {encrypted} Do not distribute"

        for page in doc:
            width, height = page.rect.width, page.rect.height
            diag = (width**2 + height**2) ** 0.5
            fontsize = max(int(diag * 0.02), 15)

            # -------------------------
            # VISIBLE WATERMARK
            # -------------------------
            x_step = width * 1.1
            y_step = height * 0.2
            y = -height
            while y < height * 1.5:
                x = -width
                while x < width * 1.5:
                    shape = page.new_shape()
                    shape.insert_text(
                        fitz.Point(x, y),
                        visible_text,
                        fontsize=fontsize,
                        fontname="helvetica",
                        rotate=0,
                        color=(0, 0, 0),
                        fill_opacity=0.45,  # semi-transparent visible watermark
                    )
                    shape.commit()
                    x += x_step
                y += y_step

            # -------------------------
            # INVISIBLE WATERMARK
            # -------------------------
            # smaller step so it repeats densely for copy detection
            x_step_inv = width * 0.5
            y_step_inv = height * 0.1
            y = 0
            while y < height:
                x = 0
                while x < width:
                    shape = page.new_shape()
                    shape.insert_text(
                        fitz.Point(x, y),
                        invisible_text,
                        fontsize=1,  # tiny font
                        fontname="helvetica",
                        rotate=0,
                        color=(1, 1, 1),  # white text
                        fill_opacity=0,  # fully invisible
                    )
                    shape.commit()
                    x += x_step_inv
                y += y_step_inv

        out = BytesIO()
        doc.save(out)
        doc.close()
        return out.getvalue()

    def is_watermark_applicable(self, pdf: PdfSource, position: Optional[str] = None) -> bool:
        try:
            data = load_pdf_bytes(pdf)
            doc = fitz.open(stream=data, filetype="pdf")
            ok = len(doc) > 0
            doc.close()
            return ok
        except Exception:
            return False

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        """
        Extract the encrypted token from visible or invisible watermark text,
        decrypt it with the provided key, and return the plaintext secret.

        Raises SecretNotFoundError if no watermark is found or if decryption fails.
        """
        if not key:
            raise ValueError("key must be provided to read the watermark")

        data = load_pdf_bytes(pdf)
        doc = fitz.open(stream=data, filetype="pdf")

        visible_marker = "Watermarked with Axel-Watermark (encrypted)"
        invisible_prefix = "Watermarked with Axel-Watermark (encrypted) "
        suffix = "Do not distribute"

        # helper to attempt decrypt and return plaintext or None
        def try_decrypt(token: str) -> Optional[str]:
            try:
                return self._decrypt_secret(token, key)
            except Exception:
                return None

        for page in doc:
            try:
                txt = page.get_text("text")
            except Exception:
                txt = ""
            if not txt:
                continue

            lines = txt.splitlines()

            # 1) Visible multiline format
            for i in range(len(lines) - 2):
                if lines[i] == visible_marker and lines[i + 2].strip() == suffix:
                    token = lines[i + 1].strip()
                    plain = try_decrypt(token)
                    if plain is not None:
                        doc.close()
                        return plain
                    # if decryption failed, continue searching

            # 2) Invisible single-line format
            for line in lines:
                line = line.strip()
                if line.startswith(invisible_prefix) and line.endswith(suffix):
                    token = line[len(invisible_prefix):-len(suffix)].strip()
                    plain = try_decrypt(token)
                    if plain is not None:
                        doc.close()
                        return plain

        doc.close()
        raise SecretNotFoundError("Encrypted watermark not found or decryption failed.")