from __future__ import annotations

import html
import logging
import re
import zipfile
from csv import DictReader, Sniffer
from dataclasses import dataclass
from io import BytesIO, StringIO
from pathlib import Path


@dataclass
class ExtractionResult:
    text: str
    file_format: str
    warnings: list[str]


TEXT_EXTENSIONS = {".txt", ".md", ".csv", ".json", ".xml", ".log"}
HTML_EXTENSIONS = {".html", ".htm"}
IMAGE_EXTENSIONS = {".tif", ".tiff", ".jpg", ".jpeg", ".png", ".gif"}
SUPPORTED_BINARY_EXTENSIONS = {".pdf", ".doc", ".docx", ".rtf", ".parquet", ".xls", ".xlsx", *IMAGE_EXTENSIONS}


def _limit_text(text: str, max_chars: int, warnings: list[str]) -> str:
    if max_chars > 0 and len(text) > max_chars:
        warnings.append(f"text truncated to {max_chars} characters")
        return text[:max_chars]
    return text


def _read_limited_bytes(path: Path, max_bytes: int, warnings: list[str]) -> bytes:
    size = path.stat().st_size
    read_size = size if max_bytes <= 0 else min(size, max_bytes)
    if max_bytes > 0 and size > max_bytes:
        warnings.append(f"file truncated to {max_bytes} bytes before extraction")
    with path.open("rb") as handle:
        return handle.read(read_size)


def _decode_bytes(data: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="ignore")


def _looks_like_text_bytes(data: bytes) -> bool:
    if not data:
        return True
    if data.startswith((b"\x7fELF", b"MZ", b"\x89PNG", b"\xff\xd8", b"GIF8", b"%PDF", b"PK\x03\x04")):
        return False
    sample = data[:8192]
    if b"\x00" in sample:
        return False
    printable = sum(1 for byte in sample if byte in b"\n\r\t" or 32 <= byte <= 126 or byte >= 128)
    return printable / max(len(sample), 1) > 0.85


def _strip_html(text: str) -> str:
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(text, "html.parser")
        for tag in soup(["script", "style"]):
            tag.decompose()
        return soup.get_text("\n")
    except Exception:
        return re.sub(r"<[^>]+>", " ", html.unescape(text))


def _strip_rtf(text: str) -> str:
    try:
        from striprtf.striprtf import rtf_to_text

        return rtf_to_text(text)
    except Exception:
        return text


class _LogCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def _extract_pdf(path: Path, max_pages: int, enable_ocr: bool, warnings: list[str]) -> str:
    from pypdf import PdfReader

    pypdf_logger = logging.getLogger("pypdf")
    old_level = pypdf_logger.level
    old_propagate = pypdf_logger.propagate
    capture = _LogCapture()
    pypdf_logger.addHandler(capture)
    pypdf_logger.setLevel(logging.WARNING)
    pypdf_logger.propagate = False
    chunks: list[str] = []
    try:
        reader = PdfReader(str(path))
        if reader.is_encrypted:
            try:
                reader.decrypt("")
                warnings.append("encrypted PDF opened with empty password")
            except Exception as exc:
                warnings.append(f"encrypted PDF could not be decrypted: {exc}")
                return _ocr_pdf(path, max_pages, warnings) if enable_ocr else ""
        pages = reader.pages if max_pages <= 0 else reader.pages[:max_pages]
        for index, page in enumerate(pages, start=1):
            try:
                chunks.append(page.extract_text() or "")
            except Exception as exc:
                warnings.append(f"PDF page {index} extraction failed: {exc}")
    finally:
        pypdf_logger.removeHandler(capture)
        pypdf_logger.setLevel(old_level)
        pypdf_logger.propagate = old_propagate

    if capture.messages:
        unique_messages = list(dict.fromkeys(capture.messages))
        warnings.extend(f"pypdf warning: {message}" for message in unique_messages[:5])
        if len(unique_messages) > 5:
            warnings.append(f"pypdf emitted {len(unique_messages) - 5} more warnings")

    text = "\n".join(chunks)
    needs_ocr_fallback = capture.messages or _looks_like_poor_pdf_text(text)
    if enable_ocr and needs_ocr_fallback:
        warnings.append("PDF OCR fallback enabled after text extraction warnings or low text quality")
        ocr_text = _ocr_pdf(path, max_pages, warnings)
        if ocr_text.strip():
            return "\n".join(part for part in (text, ocr_text) if part.strip())
    return text


def _looks_like_poor_pdf_text(text: str) -> bool:
    stripped = re.sub(r"\s+", "", text)
    if not stripped:
        return True
    letters = sum(1 for char in stripped if char.isalpha())
    return len(stripped) > 80 and letters / max(len(stripped), 1) < 0.25


def _ocr_pdf(path: Path, max_pages: int, warnings: list[str]) -> str:
    try:
        import fitz
        from PIL import Image
        import pytesseract
    except Exception as exc:
        warnings.append(f"PDF OCR fallback unavailable: {exc}")
        return ""

    try:
        document = fitz.open(path)
    except Exception as exc:
        warnings.append(f"PDF OCR open failed: {exc}")
        return ""

    page_count = len(document) if max_pages <= 0 else min(len(document), max_pages)
    chunks: list[str] = []
    for index in range(page_count):
        try:
            page = document.load_page(index)
            pixmap = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
            image = Image.open(BytesIO(pixmap.tobytes("png")))
            try:
                chunks.append(pytesseract.image_to_string(image, lang="rus+eng"))
            except Exception as exc:
                warnings.append(f"PDF OCR page {index + 1} rus+eng failed: {exc}; trying default OCR language")
                chunks.append(pytesseract.image_to_string(image))
        except Exception as exc:
            warnings.append(f"PDF OCR page {index + 1} failed: {exc}")
    document.close()
    return "\n".join(chunks)


def _extract_docx(path: Path, warnings: list[str]) -> str:
    try:
        from docx import Document

        document = Document(str(path))
        paragraphs = [paragraph.text for paragraph in document.paragraphs]
        table_cells = [cell.text for table in document.tables for row in table.rows for cell in row.cells]
        return "\n".join(paragraphs + table_cells)
    except Exception as exc:
        warnings.append(f"python-docx extraction failed: {exc}; trying XML fallback")
    try:
        with zipfile.ZipFile(path) as archive:
            xml = archive.read("word/document.xml").decode("utf-8", errors="ignore")
        text = re.sub(r"<[^>]+>", " ", xml)
        return html.unescape(text)
    except Exception as exc:
        warnings.append(f"DOCX XML fallback failed: {exc}")
        return ""


def _extract_table(path: Path, max_rows: int, warnings: list[str]) -> str:
    suffix = path.suffix.lower()
    if suffix == ".parquet":
        try:
            import pyarrow.parquet as pq

            table = pq.read_table(path)
            names = table.column_names
            rows = []
            for index, row in enumerate(table.to_pylist()):
                if max_rows > 0 and index >= max_rows:
                    warnings.append(f"table truncated to {max_rows} rows")
                    break
                rows.append(_format_record(row, names))
            return "\n".join(rows)
        except Exception as exc:
            warnings.append(f"Parquet extraction failed: {exc}")
            return ""
    elif suffix in {".xls", ".xlsx"}:
        return _extract_excel(path, max_rows, warnings)
    return ""


def _extract_csv(path: Path, max_rows: int, warnings: list[str]) -> str:
    text = _decode_bytes(_read_limited_bytes(path, 0, warnings))
    try:
        dialect = Sniffer().sniff(text[:4096])
    except Exception:
        dialect = "excel"
    reader = DictReader(StringIO(text), dialect=dialect)
    rows = []
    fieldnames = reader.fieldnames or []
    for index, record in enumerate(reader):
        if max_rows > 0 and index >= max_rows:
            warnings.append(f"CSV truncated to {max_rows} rows")
            break
        rows.append(_format_record(record, fieldnames))
    return "\n".join(rows)


def _format_record(record: dict, fieldnames: list[str]) -> str:
    parts = []
    for column in fieldnames:
        value = record.get(column)
        if value is None or value == "":
            continue
        parts.append(f"{column}: {value}")
    return " ".join(parts)


def _extract_excel(path: Path, max_rows: int, warnings: list[str]) -> str:
    if path.suffix.lower() == ".xlsx":
        try:
            from openpyxl import load_workbook

            workbook = load_workbook(path, read_only=True, data_only=True)
            chunks = []
            for sheet in workbook.worksheets:
                iterator = sheet.iter_rows(values_only=True)
                headers = [str(value) if value is not None else f"col_{index}" for index, value in enumerate(next(iterator, []), start=1)]
                for row_index, row in enumerate(iterator):
                    if max_rows > 0 and row_index >= max_rows:
                        warnings.append(f"sheet {sheet.title} truncated to {max_rows} rows")
                        break
                    record = {headers[index]: value for index, value in enumerate(row) if index < len(headers)}
                    chunks.append(f"sheet: {sheet.title} {_format_record(record, headers)}")
            return "\n".join(chunks)
        except Exception as exc:
            warnings.append(f"XLSX extraction failed: {exc}")
            return ""
    try:
        import xlrd

        workbook = xlrd.open_workbook(path)
        chunks = []
        for sheet in workbook.sheets():
            headers = [str(sheet.cell_value(0, col)) or f"col_{col + 1}" for col in range(sheet.ncols)]
            for row_index in range(1, sheet.nrows):
                if max_rows > 0 and row_index > max_rows:
                    warnings.append(f"sheet {sheet.name} truncated to {max_rows} rows")
                    break
                record = {headers[col]: sheet.cell_value(row_index, col) for col in range(sheet.ncols)}
                chunks.append(f"sheet: {sheet.name} {_format_record(record, headers)}")
        return "\n".join(chunks)
    except Exception as exc:
        warnings.append(f"XLS extraction failed: {exc}")
        return ""


def _extract_image(path: Path, warnings: list[str]) -> str:
    try:
        from PIL import Image
        import pytesseract

        image = Image.open(path)
        try:
            return pytesseract.image_to_string(image, lang="rus+eng")
        except Exception as exc:
            warnings.append(f"OCR rus+eng failed: {exc}; trying default OCR language")
            return pytesseract.image_to_string(image)
    except Exception as exc:
        warnings.append(f"OCR failed: {exc}")
        return ""


def _extract_binary_strings(path: Path, max_bytes: int, warnings: list[str]) -> str:
    data = _read_limited_bytes(path, max_bytes, warnings)
    if not _looks_like_text_bytes(data):
        warnings.append("binary file skipped; unsupported binary format")
        return ""
    decoded = _decode_bytes(data)
    chunks = re.findall(r"[A-Za-zА-Яа-яЁё0-9@._<>\-+/\\,;:() ]{5,}", decoded)
    return "\n".join(chunks)


def extract_text(
    path: Path,
    *,
    enable_ocr: bool = False,
    max_bytes: int = 20_000_000,
    max_chars: int = 2_000_000,
    max_rows: int = 200_000,
    max_pdf_pages: int = 0,
) -> ExtractionResult:
    warnings: list[str] = []
    suffix = path.suffix.lower()
    text = ""
    try:
        if suffix == ".csv":
            text = _extract_csv(path, max_rows, warnings)
        elif suffix in TEXT_EXTENSIONS:
            text = _decode_bytes(_read_limited_bytes(path, max_bytes, warnings))
        elif suffix in HTML_EXTENSIONS:
            raw = _decode_bytes(_read_limited_bytes(path, max_bytes, warnings))
            text = _strip_html(raw)
        elif suffix == ".rtf":
            raw = _decode_bytes(_read_limited_bytes(path, max_bytes, warnings))
            text = _strip_rtf(raw)
        elif suffix == ".pdf":
            text = _extract_pdf(path, max_pdf_pages, enable_ocr, warnings)
        elif suffix == ".docx":
            text = _extract_docx(path, warnings)
        elif suffix in {".parquet", ".xls", ".xlsx"}:
            text = _extract_table(path, max_rows, warnings)
        elif suffix in IMAGE_EXTENSIONS:
            if enable_ocr:
                text = _extract_image(path, warnings)
            else:
                warnings.append("image skipped; pass --ocr to enable OCR")
        elif suffix in {".doc"}:
            warnings.append("legacy binary office file processed with string fallback")
            text = _extract_binary_strings(path, max_bytes, warnings)
        else:
            warnings.append("unsupported extension processed as text only if bytes look textual")
            text = _extract_binary_strings(path, max_bytes, warnings)
    except Exception as exc:
        warnings.append(f"extraction failed: {exc}")
        text = ""
    return ExtractionResult(text=_limit_text(text, max_chars, warnings), file_format=suffix or "[no_ext]", warnings=warnings)
