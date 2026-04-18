# Repository Guidelines

## Project Structure & Module Organization

This repository contains hackathon case materials and test data for automatic personal-data detection.

- `HACKATHON_CASE.pdf` is the original case statement.
- `ПДнDataset/HACKATHON_CASE.md` is the readable Markdown version of the task.
- `ПДнDataset/share/` contains the mixed corporate-file dataset: scans, PDFs, CSV, JSON, Parquet, HTML assets, and media.
- `ПДнDataset/.ipynb_checkpoints/` contains generated notebook checkpoints; avoid treating it as source.

If you add implementation code, keep it outside the dataset tree. Prefer `src/` for scanner modules, `tests/` for automated tests, `reports/` for generated outputs, and `notebooks/` only for exploratory work.

## Build, Test, and Development Commands

There is no build system or package manifest yet. Run commands from the repository root.

- `rg --files "ПДнDataset/share"` lists dataset files without walking binary contents.
- `find "ПДнDataset/share" -type f | wc -l` checks dataset size after copying or filtering.
- `python -m pytest tests` should be the standard test command once tests are added.
- `python -m src.scanner --input "ПДнDataset/share" --output reports/pii_report.json` is the recommended CLI shape for future scanner code.

Document new dependency commands, such as `pip install -r requirements.txt` or `uv sync`, in the README when introduced.

## Coding Style & Naming Conventions

Use Python 3.7+ unless a later version is required. Keep modules small: extraction, detection, validation, classification, and reporting should be separate concerns. Use `snake_case` for files, functions, variables, and report fields. Prefer explicit parsers for CSV, JSON, and Parquet over ad hoc string processing. Preserve Cyrillic dataset paths in examples and tests.

## Testing Guidelines

Add focused tests for each detector and validator: passport patterns, SNILS, INN, card numbers with Luhn validation, contact data, and protected-category classification. Name tests `test_<behavior>.py` and keep fixtures small, synthetic, and committed under `tests/fixtures/`. Do not store full extracted personal-data values in expected reports.

## Commit & Pull Request Guidelines

This checkout has no Git history, so no existing commit convention is available. Use short imperative commit subjects, for example `add parquet extractor` or `mask report findings`. Pull requests should describe the detection change, affected file formats, test coverage, and performance impact on representative samples. Include screenshots only for UI/report changes.

## Security & Data Handling

Treat the dataset as sensitive even though the case states it is synthetic or public-source material. Do not copy raw findings into logs, PR text, or reports. Reports should store categories, counts, file paths, protection level, and masked evidence only.
