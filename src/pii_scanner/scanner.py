from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .extractors import ExtractionResult, extract_text, normalize_ocr_languages
from .patterns import CONFIDENCE_ORDER, DetectionResult, Finding, detect_pii_with_suspicious


SKIP_DIRS = {".git", ".venv", "__pycache__", ".ipynb_checkpoints"}
MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
DEFAULT_HIGH_VOLUME_THRESHOLD = 100_000
DEFAULT_CONFIDENCE = "medium"


@dataclass
class ScannerConfig:
    enable_ocr: bool = False
    serial_ocr: bool = False
    ocr_languages: tuple[str, ...] = ()
    max_bytes: int = 20_000_000
    max_chars: int = 2_000_000
    max_rows: int = 200_000
    max_pdf_pages: int = 0
    high_volume_threshold: int = DEFAULT_HIGH_VOLUME_THRESHOLD
    confidence: str = DEFAULT_CONFIDENCE
    max_examples: int = 3
    only_findings: bool = False
    names_only: bool = False
    limit: int = 0


@dataclass
class FileResult:
    size: int
    time: str
    path: str
    file_format: str
    categories: list[str]
    counts: dict[str, int]
    confidence_counts: dict[str, int]
    suspicious_categories: list[str]
    suspicious_counts: dict[str, int]
    protection_level: str
    examples: dict[str, list[str]]
    confidence_by_category: dict[str, str]
    suspicious_examples: dict[str, list[str]]
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


def display_path(path: Path, root: Path, *, names_only: bool = False) -> str:
    if names_only:
        return path.name
    try:
        return str(path.relative_to(root if root.is_dir() else root.parent))
    except ValueError:
        return str(path)


def format_submission_time(timestamp: float) -> str:
    dt = datetime.fromtimestamp(timestamp)
    return f"{MONTHS[dt.month - 1]} {dt.day:02d} {dt.hour:02d}:{dt.minute:02d}"


def classify_protection_level(findings: list[Finding], high_volume_threshold: int = DEFAULT_HIGH_VOLUME_THRESHOLD) -> str:
    if not findings:
        return "нет ПДн"
    totals_by_kind: dict[str, int] = {}
    for finding in findings:
        totals_by_kind[finding.kind] = totals_by_kind.get(finding.kind, 0) + finding.count
    total_findings = sum(totals_by_kind.values())
    has_special_or_biometric = bool(totals_by_kind.get("special", 0) or totals_by_kind.get("biometric", 0))
    is_high_volume = total_findings > high_volume_threshold
    if has_special_or_biometric:
        return "УЗ-1" if is_high_volume else "УЗ-2"
    return "УЗ-3" if is_high_volume else "УЗ-4"


def confidence_at_least(confidence: str, minimum: str) -> bool:
    return CONFIDENCE_ORDER.get(confidence, 1) >= CONFIDENCE_ORDER.get(minimum, CONFIDENCE_ORDER[DEFAULT_CONFIDENCE])


def _promote_finding(finding: Finding, confidence: str) -> None:
    if CONFIDENCE_ORDER[confidence] > CONFIDENCE_ORDER.get(finding.confidence, 1):
        finding.confidence = confidence


def _spans_are_near(left: Finding, right: Finding, max_gap: int = 180) -> bool:
    for left_start, left_end in left.spans:
        for right_start, right_end in right.spans:
            if left_start <= right_end and right_start <= left_end:
                return True
            gap = min(abs(left_start - right_end), abs(right_start - left_end))
            if gap <= max_gap:
                return True
    return False


def apply_contextual_confidence(findings: list[Finding]) -> list[Finding]:
    direct_keys = {"passport_rf", "snils", "driver_license", "mrz", "bank_card"}
    person_keys = {*direct_keys, "full_name"}
    contact_keys = {"email", "phone", "birth_date", "birth_place", "address"}
    sensitive_keys = {"health", "religion", "politics", "ethnicity", "biometric"}
    payment_requisite_keys = {"bank_account", "bik", "cvv", "inn"}

    by_key: dict[str, list[Finding]] = {}
    for finding in findings:
        by_key.setdefault(finding.key, []).append(finding)

    person_findings = [finding for key in person_keys for finding in by_key.get(key, [])]
    full_name_findings = by_key.get("full_name", [])
    direct_findings = [finding for key in direct_keys for finding in by_key.get(key, [])]

    for full_name in full_name_findings:
        for key in contact_keys:
            for contact in by_key.get(key, []):
                if _spans_are_near(full_name, contact):
                    _promote_finding(contact, "strong")

    for key in sensitive_keys:
        for finding in by_key.get(key, []):
            if any(_spans_are_near(finding, direct, max_gap=220) for direct in direct_findings):
                _promote_finding(finding, "strong")
            elif any(_spans_are_near(finding, person, max_gap=220) for person in person_findings):
                _promote_finding(finding, "medium")

    for key in payment_requisite_keys:
        for finding in by_key.get(key, []):
            if any(_spans_are_near(finding, person, max_gap=220) for person in person_findings):
                _promote_finding(finding, "medium")

    return findings


def filter_findings_by_confidence(findings: list[Finding], minimum: str) -> list[Finding]:
    return [finding for finding in findings if confidence_at_least(finding.confidence, minimum)]


def aggregate_findings(findings: list[Finding], max_examples: int) -> tuple[list[str], dict[str, int], dict[str, list[str]], dict[str, str], dict[str, int]]:
    counts: dict[str, int] = {}
    examples: dict[str, list[str]] = {}
    confidence_by_category: dict[str, str] = {}
    confidence_counts = {level: 0 for level in CONFIDENCE_ORDER}
    for finding in findings:
        counts[finding.label] = counts.get(finding.label, 0) + finding.count
        confidence_counts[finding.confidence] = confidence_counts.get(finding.confidence, 0) + finding.count
        current_confidence = confidence_by_category.get(finding.label)
        if current_confidence is None or CONFIDENCE_ORDER[finding.confidence] > CONFIDENCE_ORDER[current_confidence]:
            confidence_by_category[finding.label] = finding.confidence
        if finding.examples:
            bucket = examples.setdefault(finding.label, [])
            for example in finding.examples:
                if example not in bucket and len(bucket) < max_examples:
                    bucket.append(example)
    categories = list(counts)
    return categories, counts, examples, confidence_by_category, confidence_counts


def _merge_findings(existing: dict[str, Finding], incoming: list[Finding], max_examples: int) -> None:
    for finding in incoming:
        finding_key = f"{finding.key}:{finding.confidence}"
        current = existing.get(finding_key)
        if current is None:
            existing[finding_key] = Finding(
                key=finding.key,
                label=finding.label,
                kind=finding.kind,
                count=finding.count,
                confidence=finding.confidence,
                examples=list(finding.examples[:max_examples]),
                spans=list(finding.spans),
            )
            continue
        current.count = max(current.count, finding.count)
        for example in finding.examples:
            if example not in current.examples and len(current.examples) < max_examples:
                current.examples.append(example)
        for span in finding.spans:
            if len(current.spans) < 50:
                current.spans.append(span)


def detect_extracted_pii(extracted: ExtractionResult, max_examples: int = 3) -> DetectionResult:
    scan_texts = extracted.scan_texts or [extracted.text]
    findings_by_key: dict[str, Finding] = {}
    suspicious_by_key: dict[str, Finding] = {}
    for text in scan_texts:
        detection = detect_pii_with_suspicious(text, max_examples=max_examples)
        _merge_findings(findings_by_key, detection.findings, max_examples)
        _merge_findings(suspicious_by_key, detection.suspicious, max_examples)
    return DetectionResult(findings=list(findings_by_key.values()), suspicious=list(suspicious_by_key.values()))


def scan_file(path: Path, root: Path, config: ScannerConfig) -> FileResult:
    stat = path.stat()
    try:
        extracted = extract_text(
            path,
            enable_ocr=config.enable_ocr,
            serial_ocr=config.serial_ocr,
            ocr_languages=config.ocr_languages,
            max_bytes=config.max_bytes,
            max_chars=config.max_chars,
            max_rows=config.max_rows,
            max_pdf_pages=config.max_pdf_pages,
        )
        detection = detect_extracted_pii(extracted, max_examples=config.max_examples)
        all_findings = apply_contextual_confidence(detection.findings)
        findings = filter_findings_by_confidence(all_findings, config.confidence)
        suspicious_findings = detection.suspicious
        categories, counts, examples, confidence_by_category, confidence_counts = aggregate_findings(findings, config.max_examples)
        suspicious_categories, suspicious_counts, suspicious_examples, _, _ = aggregate_findings(suspicious_findings, config.max_examples)
        return FileResult(
            size=stat.st_size,
            time=format_submission_time(stat.st_mtime),
            path=display_path(path, root, names_only=config.names_only),
            file_format=extracted.file_format,
            categories=categories,
            counts=counts,
            confidence_counts=confidence_counts,
            suspicious_categories=suspicious_categories,
            suspicious_counts=suspicious_counts,
            protection_level=classify_protection_level(findings, config.high_volume_threshold),
            examples=examples,
            confidence_by_category=confidence_by_category,
            suspicious_examples=suspicious_examples,
            warnings=extracted.warnings,
        )
    except Exception as exc:
        return FileResult(
            size=stat.st_size,
            time=format_submission_time(stat.st_mtime),
            path=display_path(path, root, names_only=config.names_only),
            file_format=path.suffix.lower() or "[no_ext]",
            categories=[],
            counts={},
            confidence_counts={level: 0 for level in CONFIDENCE_ORDER},
            suspicious_categories=[],
            suspicious_counts={},
            protection_level="ошибка",
            examples={},
            confidence_by_category={},
            suspicious_examples={},
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
        results = [result for result in results if result.counts or result.suspicious_counts or result.error]
    files_with_pii = sum(1 for result in results if result.counts)
    files_with_suspicious = sum(1 for result in results if result.suspicious_counts)
    total_findings = sum(sum(result.counts.values()) for result in results)
    total_by_confidence = {level: sum(result.confidence_counts.get(level, 0) for result in results) for level in CONFIDENCE_ORDER}
    total_suspicious = sum(sum(result.suspicious_counts.values()) for result in results)
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
        "files_with_suspicious": files_with_suspicious,
        "total_findings": total_findings,
        "total_by_confidence": total_by_confidence,
        "total_suspicious": total_suspicious,
        "errors": errors,
        "ocr_enabled": config.enable_ocr,
        "ocr_mode": "serial" if config.serial_ocr else ("standard" if config.enable_ocr else "off"),
        "ocr_languages": list(normalize_ocr_languages(config.ocr_languages)),
        "confidence_threshold": config.confidence,
        "names_only": config.names_only,
        "results": [asdict(result) for result in sorted(results, key=lambda item: item.path)],
    }
