from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_json_report(summary: dict, path: Path) -> None:
    _ensure_parent(path)
    path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


def write_csv_report(summary: dict, path: Path) -> None:
    _ensure_parent(path)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "путь",
                "категории_ПДн",
                "количество_находок",
                "УЗ",
                "формат_файла",
                "примеры_маскированные",
                "ошибки",
                "предупреждения",
            ],
        )
        writer.writeheader()
        for result in summary["results"]:
            writer.writerow(
                {
                    "путь": result["path"],
                    "категории_ПДн": "; ".join(result["categories"]),
                    "количество_находок": json.dumps(result["counts"], ensure_ascii=False),
                    "УЗ": result["protection_level"],
                    "формат_файла": result["file_format"],
                    "примеры_маскированные": json.dumps(result["examples"], ensure_ascii=False),
                    "ошибки": result["error"] or "",
                    "предупреждения": "; ".join(result["warnings"]),
                }
            )


def write_markdown_report(summary: dict, path: Path) -> None:
    _ensure_parent(path)
    level_counts = Counter(result["protection_level"] for result in summary["results"])
    category_counts: Counter[str] = Counter()
    for result in summary["results"]:
        category_counts.update(result["counts"])
    top_files = sorted(summary["results"], key=lambda result: sum(result["counts"].values()), reverse=True)[:20]
    lines = [
        "# PII Scan Report",
        "",
        f"- Input: `{summary['input_path']}`",
        f"- Files scanned: {summary['files_scanned']}",
        f"- Files in report: {summary['files_in_report']}",
        f"- Files with PII: {summary['files_with_pii']}",
        f"- Total findings: {summary['total_findings']}",
        f"- OCR enabled: {summary['ocr_enabled']}",
        f"- Duration: {summary['duration_seconds']} seconds",
        "",
        "## Protection Levels",
        "",
        "| Level | Files |",
        "| --- | ---: |",
    ]
    for level, count in level_counts.most_common():
        lines.append(f"| {level} | {count} |")
    lines.extend(["", "## Categories", "", "| Category | Findings |", "| --- | ---: |"])
    for category, count in category_counts.most_common():
        lines.append(f"| {category} | {count} |")
    lines.extend(["", "## Top Files", "", "| File | Level | Findings | Categories |", "| --- | --- | ---: | --- |"])
    for result in top_files:
        total = sum(result["counts"].values())
        categories = ", ".join(result["categories"])
        lines.append(f"| `{result['path']}` | {result['protection_level']} | {total} | {categories} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_reports(summary: dict, json_path: Path, csv_path: Path | None, markdown_path: Path | None) -> None:
    write_json_report(summary, json_path)
    if csv_path:
        write_csv_report(summary, csv_path)
    if markdown_path:
        write_markdown_report(summary, markdown_path)

