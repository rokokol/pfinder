from pii_scanner.patterns import detect_pii, is_inn_valid, is_luhn_valid, is_snils_valid
from pii_scanner.scanner import classify_protection_level, display_path
from pii_scanner.extractors import extract_text


def labels(text: str) -> set[str]:
    return {finding.label for finding in detect_pii(text)}


def test_validators_accept_known_synthetic_values() -> None:
    assert is_luhn_valid("4111 1111 1111 1111")
    assert is_snils_valid("112-233-445 95")
    assert is_inn_valid("500100732259")


def test_detects_common_and_government_categories() -> None:
    text = "ФИО: Иванов Иван Иванович, email ivan@example.com, СНИЛС 112-233-445 95"
    found = labels(text)
    assert "ФИО" in found
    assert "email" in found
    assert "СНИЛС" in found


def test_payment_data_escalates_to_level_2() -> None:
    findings = detect_pii("Карта 4111 1111 1111 1111, CVV 123")
    assert classify_protection_level(findings) == "УЗ-2"


def test_special_category_escalates_to_level_1() -> None:
    findings = detect_pii("В анкете указан медицинский диагноз и состояние здоровья.")
    assert classify_protection_level(findings) == "УЗ-1"


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
