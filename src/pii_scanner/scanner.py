from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .extractors import extract_text
from .patterns import Finding, detect_pii


SKIP_DIRS = {".git", ".venv", "__pycache__", ".ipynb_checkpoints"}


@dataclass
class ScannerConfig:
    enable_ocr: bool = False
    max_bytes: int = 20_000_000
    max_chars: int = 2_000_000
    max_rows: int = 200_000
    max_pdf_pages: int = 0
    high_volume_threshold: int = 100
    max_examples: int = 3
    only_findings: bool = False
    limit: int = 0


@dataclass
class FileResult:
    path: str
    file_format: str
    categories: list[str]
    counts: dict[str, int]
    protection_level: str
    examples: dict[str, list[str]]
    warnings: list[str]
    error: str | None = None


def iter_files(input_path: Path) -> Iterable[Path]:
    if input_path.is_file():
        yield input_path
        return
    for path in input_path.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root if root.is_dir() else root.parent))
    except ValueError:
        return str(path)


def classify_protection_level(findings: list[Finding], high_volume_threshold: int = 100) -> str:
    if not findings:
        return "нет ПДн"
    totals_by_kind: dict[str, int] = {}
    for finding in findings:
        totals_by_kind[finding.kind] = totals_by_kind.get(finding.kind, 0) + finding.count
    if totals_by_kind.get("special", 0) or totals_by_kind.get("biometric", 0):
        return "УЗ-1"
    if totals_by_kind.get("payment", 0):
        return "УЗ-2"
    if totals_by_kind.get("government_id", 0) >= high_volume_threshold:
        return "УЗ-2"
    if totals_by_kind.get("government_id", 0) or totals_by_kind.get("ordinary", 0) >= high_volume_threshold:
        return "УЗ-3"
    return "УЗ-4"


def scan_file(path: Path, root: Path, config: ScannerConfig) -> FileResult:
    try:
        extracted = extract_text(
            path,
            enable_ocr=config.enable_ocr,
            max_bytes=config.max_bytes,
            max_chars=config.max_chars,
            max_rows=config.max_rows,
            max_pdf_pages=config.max_pdf_pages,
        )
        findings = detect_pii(extracted.text, max_examples=config.max_examples)
        categories = [finding.label for finding in findings]
        counts = {finding.label: finding.count for finding in findings}
        examples = {finding.label: finding.examples for finding in findings if finding.examples}
        return FileResult(
            path=display_path(path, root),
            file_format=extracted.file_format,
            categories=categories,
            counts=counts,
            protection_level=classify_protection_level(findings, config.high_volume_threshold),
            examples=examples,
            warnings=extracted.warnings,
        )
    except Exception as exc:
        return FileResult(
            path=str(path),
            file_format=path.suffix.lower() or "[no_ext]",
            categories=[],
            counts={},
            protection_level="ошибка",
            examples={},
            warnings=[],
            error=str(exc),
        )


def scan_path(input_path: Path, config: ScannerConfig, *, workers: int = 1, verbose: bool = False) -> dict:
    input_path = input_path.resolve()
    files = list(iter_files(input_path))
    if config.limit > 0:
        files = files[: config.limit]
    started_at = datetime.now(timezone.utc)
    results: list[FileResult] = []
    if workers <= 1:
        for index, path in enumerate(files, start=1):
            results.append(scan_file(path, input_path, config))
            if verbose and index % 25 == 0:
                print(f"scanned {index}/{len(files)} files", file=sys.stderr)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(scan_file, path, input_path, config) for path in files]
            for index, future in enumerate(as_completed(futures), start=1):
                results.append(future.result())
                if verbose and index % 25 == 0:
                    print(f"scanned {index}/{len(files)} files", file=sys.stderr)
    if config.only_findings:
        results = [result for result in results if result.counts or result.error]
    files_with_pii = sum(1 for result in results if result.counts)
    total_findings = sum(sum(result.counts.values()) for result in results)
    errors = sum(1 for result in results if result.error)
    finished_at = datetime.now(timezone.utc)
    return {
        "input_path": str(input_path),
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
        "files_scanned": len(files),
        "files_in_report": len(results),
        "files_with_pii": files_with_pii,
        "total_findings": total_findings,
        "errors": errors,
        "ocr_enabled": config.enable_ocr,
        "results": [asdict(result) for result in sorted(results, key=lambda item: item.path)],
    }
