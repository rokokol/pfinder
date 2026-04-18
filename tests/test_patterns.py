from datetime import datetime
import csv
import json

import pytest

from pii_scanner.patterns import Finding, detect_pii, detect_pii_with_suspicious, is_inn_valid, is_luhn_valid, is_snils_valid
from pii_scanner.reports import submission_records, write_example_reports
from pii_scanner.scanner import (
    apply_contextual_confidence,
    classify_protection_level,
    detect_extracted_pii,
    display_path,
    filter_findings_by_confidence,
    format_submission_time,
)
from pii_scanner.extractors import (
    ExtractionResult,
    _pdf_image_page_indexes,
    _serial_ocr_language_specs,
    extract_text,
    normalize_ocr_languages,
)


def labels(text: str) -> set[str]:
    return {finding.label for finding in detect_pii(text)}


def test_validators_accept_known_synthetic_values() -> None:
    assert is_luhn_valid("4111 1111 1111 1111")
    assert is_snils_valid("112-233-445 95")
    assert is_inn_valid("500100732259")


def test_ocr_language_normalization_and_serial_specs() -> None:
    languages = normalize_ocr_languages(["ru", "en", "deu", "ru"])
    assert languages == ("rus", "eng", "deu")
    assert _serial_ocr_language_specs(languages) == [
        ("rus", "rus"),
        ("eng", "eng"),
        ("deu", "deu"),
        ("rus+eng+deu", "rus+eng+deu"),
    ]
    assert _serial_ocr_language_specs(()) == [(None, "default")]


def test_detects_common_and_government_categories() -> None:
    text = "ФИО: Иванов Иван Иванович, email ivan@example.com, СНИЛС 112-233-445 95"
    found = labels(text)
    assert "ФИО" in found
    assert "email" in found
    assert "СНИЛС" in found


def test_abstract_policy_words_are_weak_confidence_only() -> None:
    detection = detect_pii_with_suspicious(
        "We may process address, religion, religious beliefs, political opinions, ethnicity and race."
    )
    assert {finding.label for finding in detection.findings} == {
        "религиозные убеждения",
        "политические убеждения",
        "расовая/национальная принадлежность",
    }
    assert filter_findings_by_confidence(detection.findings, "medium") == []


def test_valid_document_identifier_is_strong_confidence() -> None:
    detection = detect_pii_with_suspicious("СНИЛС 112-233-445 95")
    strong = filter_findings_by_confidence(detection.findings, "strong")
    assert {finding.label for finding in strong} == {"СНИЛС"}


def test_valid_card_is_strong_without_context() -> None:
    bare = detect_pii_with_suspicious("4111111111111111")
    formatted = detect_pii_with_suspicious("4111 1111 1111 1111")
    assert {finding.label for finding in filter_findings_by_confidence(bare.findings, "strong")} == {"банковская карта"}
    assert {finding.label for finding in filter_findings_by_confidence(formatted.findings, "strong")} == {"банковская карта"}


def test_adjacent_contact_data_is_promoted_by_full_name_context() -> None:
    detection = detect_pii_with_suspicious("Иванов Иван Иванович, email ivan@example.com")
    findings = apply_contextual_confidence(detection.findings)
    strong = filter_findings_by_confidence(findings, "strong")
    assert "email" in {finding.label for finding in strong}


def test_other_data_under_subject_threshold_is_level_4() -> None:
    findings = detect_pii("Карта 4111 1111 1111 1111, CVV 123")
    assert classify_protection_level(findings) == "УЗ-4"


def test_special_category_under_subject_threshold_is_level_2() -> None:
    findings = detect_pii("В анкете указан медицинский диагноз и состояние здоровья.")
    assert classify_protection_level(findings) == "УЗ-2"


def test_special_category_over_subject_threshold_is_level_1() -> None:
    findings = [Finding(key="health", label="состояние здоровья", kind="special", count=100_001)]
    assert classify_protection_level(findings) == "УЗ-1"


def test_other_category_over_subject_threshold_is_level_3() -> None:
    findings = [Finding(key="email", label="email", kind="ordinary", count=100_001)]
    assert classify_protection_level(findings) == "УЗ-3"


def test_csv_extraction_adds_column_context(tmp_path) -> None:
    csv_file = tmp_path / "customers.csv"
    csv_file.write_text("customer_name,email\nИванов Иван Иванович,ivan@example.com\n", encoding="utf-8")
    extracted = extract_text(csv_file)
    assert "customer_name: Иванов Иван Иванович" in extracted.text
    assert "email: ivan@example.com" in extracted.text


def test_binary_unknown_file_is_skipped(tmp_path) -> None:
    binary_file = tmp_path / "#958615"
    binary_file.write_bytes(b"\x7fELF\x00fake email test@example.com address Moscow")
    extracted = extract_text(binary_file)
    assert extracted.text == ""
    assert "binary file skipped" in " ".join(extracted.warnings)


def test_display_path_keeps_real_filename(tmp_path) -> None:
    encoded = tmp_path / "%D0%A2%D0%B5%D1%81%D1%82.pdf"
    encoded.write_text("", encoding="utf-8")
    assert display_path(encoded, tmp_path) == "%D0%A2%D0%B5%D1%81%D1%82.pdf"


def test_display_path_can_use_only_filename(tmp_path) -> None:
    nested = tmp_path / "nested" / "CA01_01.tif"
    nested.parent.mkdir()
    nested.write_text("", encoding="utf-8")
    assert display_path(nested, tmp_path) == "nested/CA01_01.tif"
    assert display_path(nested, tmp_path, names_only=True) == "CA01_01.tif"


def test_submission_time_format_is_lowercase_ls_style() -> None:
    timestamp = datetime(2024, 9, 26, 18, 31).timestamp()
    assert format_submission_time(timestamp) == "sep 26 18:31"


def test_submission_records_have_required_fields_only() -> None:
    summary = {
        "results": [
            {
                "size": 10,
                "time": "sep 26 18:31",
                "path": "CA01_01.tif",
                "counts": {"ФИО": 1},
                "suspicious_counts": {},
            },
            {
                "size": 20,
                "time": "sep 26 18:32",
                "path": "clean.txt",
                "counts": {},
                "suspicious_counts": {"банковская карта": 1},
            },
        ]
    }
    assert submission_records(summary) == [{"size": 10, "time": "sep 26 18:31", "name": "CA01_01.tif"}]


def test_submission_records_force_basename_when_summary_is_names_only() -> None:
    summary = {
        "names_only": True,
        "results": [
            {
                "size": 10,
                "time": "sep 26 18:31",
                "path": "nested/CA01_01.tif",
                "counts": {"ФИО": 1},
                "suspicious_counts": {},
            }
        ],
    }
    assert submission_records(summary) == [{"size": 10, "time": "sep 26 18:31", "name": "CA01_01.tif"}]


def test_suspicious_records_are_separate_from_valid_findings() -> None:
    detection = detect_pii_with_suspicious("Карта 4111 1111 1111 1112, СНИЛС 112-233-445 96")
    assert detection.findings == []
    assert {finding.label: finding.count for finding in detection.suspicious} == {
        "СНИЛС": 1,
        "банковская карта": 1,
    }


def test_submission_records_can_include_suspicious_with_flag() -> None:
    summary = {
        "results": [
            {
                "size": 20,
                "time": "sep 26 18:32",
                "path": "ocr_noise.tif",
                "counts": {},
                "suspicious_counts": {"банковская карта": 2},
            },
        ]
    }
    assert submission_records(summary, include_suspicious=True) == [
        {
            "size": 20,
            "time": "sep 26 18:32",
            "name": "ocr_noise.tif",
            "suspicious": {"банковская карта": 2},
            "suspicious_count": 2,
        }
    ]


def test_serial_ocr_scan_texts_are_checked_without_triple_counting() -> None:
    extracted = ExtractionResult(
        text="",
        file_format=".tif",
        warnings=[],
        scan_texts=[
            "email ivan@example.com",
            "email ivan@example.com",
            "email ivan@example.com",
        ],
    )
    detection = detect_extracted_pii(extracted)
    assert {finding.label: finding.count for finding in detection.findings} == {"email": 1}


def test_write_example_reports_from_file_list(tmp_path) -> None:
    first = tmp_path / "nested" / "CA01_01.tif"
    second = tmp_path / "CB02_02.pdf"
    first.parent.mkdir()
    first.write_bytes(b"abc")
    second.write_bytes(b"pdf")

    write_example_reports(
        [first, second],
        json_path=tmp_path / "result.json",
        csv_path=tmp_path / "result.csv",
        markdown_path=tmp_path / "result.md",
        root=tmp_path,
    )

    with (tmp_path / "result.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert list(rows[0]) == ["size", "time", "name"]
    assert [row["name"] for row in rows] == ["CB02_02.pdf", "nested/CA01_01.tif"]

    with (tmp_path / "result.json").open(encoding="utf-8") as handle:
        payload = json.load(handle)
    assert sorted(payload[0]) == ["name", "size", "time"]
    assert (tmp_path / "result.md").exists()


def test_pdf_image_page_detection(tmp_path) -> None:
    pytest.importorskip("pypdfium2", exc_type=ImportError)
    from PIL import Image

    pdf = tmp_path / "with_image.pdf"
    Image.new("RGB", (20, 20), "white").save(pdf, "PDF")

    warnings: list[str] = []
    assert _pdf_image_page_indexes(pdf, 0, warnings) == [0]
