from __future__ import annotations

import argparse
from pathlib import Path

from .reports import write_example_reports


def _read_file_list(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii-example-report",
        description="Generate example JSON/CSV/Markdown reports from an explicit file list without running detectors.",
    )
    parser.add_argument("files", nargs="*", type=Path, help="Files to include in the example report.")
    parser.add_argument(
        "--file-list",
        type=Path,
        action="append",
        default=[],
        help="Text file with one path per line. Can be passed multiple times.",
    )
    parser.add_argument("--root", type=Path, default=None, help="Root used to compute relative names in reports.")
    parser.add_argument("--output", type=Path, default=Path("reports/example.json"), help="JSON report path.")
    parser.add_argument("--csv-output", type=Path, default=Path("reports/example.csv"), help="CSV report path.")
    parser.add_argument("--markdown-output", type=Path, default=Path("reports/example.md"), help="Markdown report path.")
    parser.add_argument("--no-csv", action="store_true", help="Do not write the CSV report.")
    parser.add_argument("--no-markdown", action="store_true", help="Do not write the Markdown report.")
    parser.add_argument("--names-only", action="store_true", help="Write only base filenames in reports.")
    parser.add_argument(
        "--include-suspicious",
        action="store_true",
        help="Include empty suspicious columns in JSON/CSV for format demonstration.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    files: list[Path] = list(args.files)
    for file_list in args.file_list:
        files.extend(Path(item) for item in _read_file_list(file_list))

    if not files:
        parser.error("provide at least one file path or --file-list")

    missing = [str(path) for path in files if not path.exists()]
    if missing:
        parser.error("these files do not exist: " + ", ".join(missing[:10]))

    csv_path = None if args.no_csv else args.csv_output
    markdown_path = None if args.no_markdown else args.markdown_output
    summary = write_example_reports(
        files,
        json_path=args.output,
        csv_path=csv_path,
        markdown_path=markdown_path,
        root=args.root,
        names_only=args.names_only,
        include_suspicious=args.include_suspicious,
    )

    print(f"Generated example report for {summary['files_in_report']} files. JSON: {args.output}")
    if csv_path:
        print(f"CSV: {csv_path}")
    if markdown_path:
        print(f"Markdown: {markdown_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
