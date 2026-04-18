from __future__ import annotations

import argparse
from pathlib import Path

from .reports import write_reports
from .scanner import DEFAULT_CONFIDENCE, DEFAULT_HIGH_VOLUME_THRESHOLD, ScannerConfig, scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii-scan",
        description="Scan files for personal data and produce JSON/CSV/Markdown reports.",
    )
    parser.add_argument("input_path", type=Path, help="File or directory to analyze.")
    parser.add_argument("--output", type=Path, default=Path("reports/result.json"), help="Submission JSON report path.")
    parser.add_argument("--csv-output", type=Path, default=Path("reports/result.csv"), help="Submission CSV report path.")
    parser.add_argument("--markdown-output", type=Path, default=Path("reports/result.md"), help="Markdown summary report path.")
    parser.add_argument("--no-csv", action="store_true", help="Do not write the CSV report.")
    parser.add_argument("--no-markdown", action="store_true", help="Do not write the Markdown report.")
    parser.add_argument(
        "--include-suspicious",
        action="store_true",
        help="Add failed-validation candidates to JSON/CSV. This changes the strict leaderboard CSV shape.",
    )
    parser.add_argument("--only-findings", action="store_true", help="Exclude files with no detected PII from reports.")
    parser.add_argument("--names-only", action="store_true", help="Write only base filenames in reports instead of relative paths.")
    parser.add_argument(
        "--ocr",
        nargs="*",
        metavar="LANG",
        help="Enable OCR. Without LANG, use Tesseract default language; with LANG, use them together, e.g. --ocr ru en.",
    )
    parser.add_argument(
        "--serial-ocr",
        nargs="*",
        metavar="LANG",
        help="Enable serial OCR. Without LANG, use Tesseract default; with LANG, run each language and then all together.",
    )
    parser.add_argument("--workers", type=int, default=1, help="Number of files to scan concurrently.")
    parser.add_argument("--limit", type=int, default=0, help="Scan only the first N files, useful for smoke tests.")
    parser.add_argument(
        "--confidence",
        choices=("weak", "medium", "strong"),
        default=DEFAULT_CONFIDENCE,
        help="Minimum confidence required for confirmed findings in CSV/JSON/Markdown reports.",
    )
    parser.add_argument("--max-bytes", type=int, default=20_000_000, help="Maximum bytes read from fallback/text files.")
    parser.add_argument("--max-chars", type=int, default=2_000_000, help="Maximum extracted characters scanned per file.")
    parser.add_argument("--max-rows", type=int, default=200_000, help="Maximum rows read from tabular files.")
    parser.add_argument("--max-pdf-pages", type=int, default=0, help="Maximum PDF pages to extract; 0 means all pages.")
    parser.add_argument(
        "--high-volume-threshold",
        type=int,
        default=DEFAULT_HIGH_VOLUME_THRESHOLD,
        help="Finding count threshold used as a subject-count proxy for protection-level classification.",
    )
    parser.add_argument("--verbose", action="store_true", help="Print progress to stderr.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.input_path.exists():
        parser.error(f"input path does not exist: {args.input_path}")
    if args.ocr is not None and args.serial_ocr is not None:
        parser.error("use either --ocr or --serial-ocr, not both")
    ocr_languages = tuple(args.serial_ocr if args.serial_ocr is not None else args.ocr or ())
    config = ScannerConfig(
        enable_ocr=args.ocr is not None or args.serial_ocr is not None,
        serial_ocr=args.serial_ocr is not None,
        ocr_languages=ocr_languages,
        max_bytes=args.max_bytes,
        max_chars=args.max_chars,
        max_rows=args.max_rows,
        max_pdf_pages=args.max_pdf_pages,
        high_volume_threshold=args.high_volume_threshold,
        confidence=args.confidence,
        only_findings=args.only_findings,
        names_only=args.names_only,
        limit=args.limit,
    )
    summary = scan_path(args.input_path, config, workers=max(1, args.workers), verbose=args.verbose)
    csv_path = None if args.no_csv else args.csv_output
    markdown_path = None if args.no_markdown else args.markdown_output
    write_reports(summary, args.output, csv_path, markdown_path, include_suspicious=args.include_suspicious)
    print(
        "Scanned {files_scanned} files, found {total_findings} PII matches in {files_with_pii} files. "
        "JSON: {output}".format(output=args.output, **summary)
    )
    if csv_path:
        print(f"CSV: {csv_path}")
    if markdown_path:
        print(f"Markdown: {markdown_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
