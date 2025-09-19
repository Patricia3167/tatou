from __future__ import annotations
from io import BytesIO
from typing import Optional
import fitz  # PyMuPDF

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
        return "Embeds a visible, repeated watermark using the key and an invisible copy-deterrent watermark."

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        if not key:
            raise ValueError("key must be a non-empty recipient name")

        data = load_pdf_bytes(pdf)
        doc = fitz.open(stream=data, filetype="pdf")
        visible_text = f"Intended for {key} only, do not distribute"
        invisible_text = f"Intended for {key} only, do not distribute"

        for page in doc:
            width, height = page.rect.width, page.rect.height
            diag = (width**2 + height**2) ** 0.5
            fontsize = max(int(diag * 0.02), 20)

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
                        fill_opacity=0.45  # semi-transparent visible watermark
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
                        fontsize=1,              # tiny font
                        fontname="helvetica",
                        rotate=0,
                        color=(1, 1, 1),         # white text
                        fill_opacity=0            # fully invisible
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
        if not key:
            raise ValueError("key must be provided to read the watermark")

        data = load_pdf_bytes(pdf)
        doc = fitz.open(stream=data, filetype="pdf")
        expected_phrase = f"Intended for {key} only, do not distribute"

        for page in doc:
            try:
                txt = page.get_text("text")
            except Exception:
                txt = ""
            if expected_phrase in txt:
                doc.close()
                return key

        doc.close()
        raise SecretNotFoundError("Visible watermark text not found for the given key.")


__all__ = ["AxelWatermark"]
