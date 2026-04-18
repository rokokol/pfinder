from __future__ import annotations

import csv
import json
import os
from collections import Counter
from datetime import datetime, timezone
from os import PathLike
from pathlib import Path
from typing import Iterable

from .scanner import display_path, format_submission_time


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _report_name(result: dict, summary: dict) -> str:
    name = result["path"]
    return Path(name).name if summary.get("names_only") else name


def write_json_report(summary: dict, path: Path, *, include_suspicious: bool = False) -> None:
    _ensure_parent(path)
    path.write_text(
        json.dumps(submission_records(summary, include_suspicious=include_suspicious), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def submission_records(summary: dict, *, include_suspicious: bool = False) -> list[dict]:
    records = []
    for result in summary["results"]:
        if not result["counts"] and not (include_suspicious and result["suspicious_counts"]):
            continue
        record = {
            "size": result["size"],
            "time": result["time"],
            "name": _report_name(result, summary),
        }
        if include_suspicious:
            record["suspicious"] = result["suspicious_counts"]
            record["suspicious_count"] = sum(result["suspicious_counts"].values())
        records.append(record)
    return records


def write_csv_report(summary: dict, path: Path, *, include_suspicious: bool = False) -> None:
    _ensure_parent(path)
    fieldnames = ["size", "time", "name"]
    if include_suspicious:
        fieldnames.extend(["suspicious", "suspicious_count"])
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        for record in submission_records(summary, include_suspicious=include_suspicious):
            if include_suspicious:
                record["suspicious"] = json.dumps(record["suspicious"], ensure_ascii=False)
            writer.writerow(record)


def write_markdown_report(summary: dict, path: Path) -> None:
    _ensure_parent(path)
    level_counts = Counter(result["protection_level"] for result in summary["results"])
    category_counts: Counter[str] = Counter()
    suspicious_counts: Counter[str] = Counter()
    for result in summary["results"]:
        category_counts.update(result["counts"])
        suspicious_counts.update(result["suspicious_counts"])
    top_files = sorted(
        [result for result in summary["results"] if result["counts"]],
        key=lambda result: sum(result["counts"].values()),
        reverse=True,
    )[:20]
    top_suspicious_files = sorted(
        [result for result in summary["results"] if result["suspicious_counts"]],
        key=lambda result: sum(result["suspicious_counts"].values()),
        reverse=True,
    )[:20]
    lines = [
        "# PII Scan Report",
        "",
        f"- Input: `{summary['input_path']}`",
        f"- Files scanned: {summary['files_scanned']}",
        f"- Files in report: {summary['files_in_report']}",
        f"- Files with PII: {summary['files_with_pii']}",
        f"- Files with suspicious validation failures: {summary['files_with_suspicious']}",
        f"- Total findings: {summary['total_findings']}",
        f"- Total suspicious validation failures: {summary['total_suspicious']}",
        f"- OCR enabled: {summary['ocr_enabled']}",
        f"- OCR mode: {summary.get('ocr_mode', 'standard' if summary['ocr_enabled'] else 'off')}",
        f"- OCR languages: {', '.join(summary.get('ocr_languages') or ['default'])}",
        f"- Confidence threshold: {summary.get('confidence_threshold', 'medium')}",
        f"- Duration: {summary['duration_seconds']} seconds",
        "",
        "## Confidence",
        "",
        "| Confidence | Findings |",
        "| --- | ---: |",
    ]
    for confidence, count in summary.get("total_by_confidence", {}).items():
        lines.append(f"| {confidence} | {count} |")
    lines.extend(
        [
            "",
            "## Protection Levels",
            "",
            "| Level | Files |",
            "| --- | ---: |",
        ]
    )
    for level, count in level_counts.most_common():
        lines.append(f"| {level} | {count} |")
    lines.extend(["", "## Categories", "", "| Category | Findings |", "| --- | ---: |"])
    for category, count in category_counts.most_common():
        lines.append(f"| {category} | {count} |")
    lines.extend(["", "## Suspicious Validation Failures", "", "| Category | Candidates |", "| --- | ---: |"])
    for category, count in suspicious_counts.most_common():
        lines.append(f"| {category} | {count} |")
    lines.extend(["", "## Top Files", "", "| File | Level | Findings | Categories |", "| --- | --- | ---: | --- |"])
    for result in top_files:
        total = sum(result["counts"].values())
        categories = ", ".join(result["categories"])
        lines.append(f"| `{_report_name(result, summary)}` | {result['protection_level']} | {total} | {categories} |")
    lines.extend(
        [
            "",
            "## Top Suspicious Files",
            "",
            "| File | Suspicious Candidates | Categories |",
            "| --- | ---: | --- |",
        ]
    )
    for result in top_suspicious_files:
        total = sum(result["suspicious_counts"].values())
        categories = ", ".join(result["suspicious_categories"])
        lines.append(f"| `{_report_name(result, summary)}` | {total} | {categories} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_reports(
    summary: dict,
    json_path: Path,
    csv_path: Path | None,
    markdown_path: Path | None,
    *,
    include_suspicious: bool = False,
) -> None:
    write_json_report(summary, json_path, include_suspicious=include_suspicious)
    if csv_path:
        write_csv_report(summary, csv_path, include_suspicious=include_suspicious)
    if markdown_path:
        write_markdown_report(summary, markdown_path)


def example_summary_from_files(
    files: Iterable[str | PathLike[str]],
    *,
    root: str | PathLike[str] | None = None,
    names_only: bool = False,
) -> dict:
    paths = [Path(file) for file in files]
    if not paths:
        input_root = Path.cwd()
    elif root is not None:
        input_root = Path(root)
    else:
        common_root = os.path.commonpath([str(path.parent.resolve()) for path in paths])
        input_root = Path(common_root)

    results = []
    for path in paths:
        stat = path.stat()
        results.append(
            {
                "size": stat.st_size,
                "time": format_submission_time(stat.st_mtime),
                "path": display_path(path.resolve(), input_root.resolve(), names_only=names_only),
                "file_format": path.suffix.lower() or "[no_ext]",
                "categories": ["example"],
                "counts": {"example": 1},
                "confidence_counts": {"weak": 0, "medium": 1, "strong": 0},
                "suspicious_categories": [],
                "suspicious_counts": {},
                "protection_level": "example",
                "examples": {},
                "confidence_by_category": {"example": "medium"},
                "suspicious_examples": {},
                "warnings": ["example report entry; no detection was run"],
                "error": None,
            }
        )

    now = datetime.now(timezone.utc)
    return {
        "input_path": str(input_root),
        "started_at": now.isoformat(),
        "finished_at": now.isoformat(),
        "duration_seconds": 0,
        "files_scanned": len(results),
        "files_in_report": len(results),
        "files_with_pii": len(results),
        "files_with_suspicious": 0,
        "total_findings": len(results),
        "total_by_confidence": {"weak": 0, "medium": len(results), "strong": 0},
        "total_suspicious": 0,
        "errors": 0,
        "ocr_enabled": False,
        "ocr_mode": "off",
        "ocr_languages": [],
        "confidence_threshold": "medium",
        "names_only": names_only,
        "results": sorted(results, key=lambda item: item["path"]),
    }


def write_example_reports(
    files: Iterable[str | PathLike[str]],
    *,
    json_path: str | PathLike[str],
    csv_path: str | PathLike[str] | None = None,
    markdown_path: str | PathLike[str] | None = None,
    root: str | PathLike[str] | None = None,
    names_only: bool = False,
    include_suspicious: bool = False,
) -> dict:
    summary = example_summary_from_files(files, root=root, names_only=names_only)
    write_reports(
        summary,
        Path(json_path),
        Path(csv_path) if csv_path is not None else None,
        Path(markdown_path) if markdown_path is not None else None,
        include_suspicious=include_suspicious,
    )
    return summary
