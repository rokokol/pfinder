# PII Scanner Hackathon Utility

Terminal utility for the hackathon task in `ПДнDataset/HACKATHON_CASE.md`: scan a directory or file, detect personal-data categories, classify the required protection level, and write structured reports.

## Setup

```bash
uv sync
```

## Tesseract OCR Setup

`uv` installs the Python wrapper `pytesseract`, but it does not install the system `tesseract` binary. OCR mode requires both the binary and the Russian/English language data.

Check the current server:

```bash
tesseract --version
tesseract --list-langs
```

The language list should include `rus` and `eng`.

Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y tesseract-ocr tesseract-ocr-rus tesseract-ocr-eng
```

Nix shell:

```bash
nix shell nixpkgs#tesseract
```

After entering the shell, re-run `tesseract --list-langs`. If `rus` is missing, install or expose the Russian tessdata package available for the server's Nix channel.

## Run

```bash
uv run pii-scan "ПДнDataset/share" \
  --output reports/pii_report.json \
  --csv-output reports/pii_report.csv \
  --markdown-output reports/pii_report.md
```

Single full report with OCR enabled:

```bash
uv run pii-scan "ПДнDataset/share" \
  --output reports/pii_report.json \
  --csv-output reports/pii_report.csv \
  --markdown-output reports/pii_report.md \
  --workers 4 \
  --only-findings \
  --ocr \
  --verbose
```

Useful options:

- `--ocr` enables OCR for images through `pytesseract` and a system Tesseract installation.
- `--only-findings` keeps only files with detected PII in reports.
- `--workers 4` scans files concurrently.
- `--limit 100` scans only the first 100 files for smoke tests.

The scanner masks examples in reports and stores categories, counts, paths, file formats, and protection levels instead of raw personal-data values.

Notes:

- OCR requires a system Tesseract installation in addition to Python packages.
- When `--ocr` is enabled, PDFs with text-extraction warnings such as `SymbolSetEncoding` are rendered through PyMuPDF and passed to Tesseract as a fallback.
- Filenames are shown exactly as they exist on disk, including URL-encoded names such as `%D0%A2%D0%B5%D1%81%D1%82.pdf`.
- Unsupported binary files without a known extension, including ELF files recovered into `lost+found`, are skipped instead of scanning random printable strings.
- Parquet extraction uses `pyarrow`. If the runtime misses `libstdc++.so.6`, Parquet files are skipped with warnings instead of crashing the scan.
