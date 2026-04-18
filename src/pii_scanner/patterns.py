from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


Validator = Callable[[str], bool]
ConfidenceResolver = Callable[[str], str]
CONFIDENCE_LEVELS = ("weak", "medium", "strong")
CONFIDENCE_ORDER = {level: index for index, level in enumerate(CONFIDENCE_LEVELS)}


@dataclass(frozen=True)
class PatternSpec:
    key: str
    label: str
    kind: str
    regex: re.Pattern[str]
    group: int = 0
    validator: Validator | None = None
    suspicious_on_failed_validation: bool = False
    confidence: str = "medium"
    confidence_resolver: ConfidenceResolver | None = None


@dataclass
class Finding:
    key: str
    label: str
    kind: str
    count: int = 0
    confidence: str = "medium"
    examples: list[str] = field(default_factory=list)
    spans: list[tuple[int, int]] = field(default_factory=list)


@dataclass
class DetectionResult:
    findings: list[Finding]
    suspicious: list[Finding]


def digits_only(value: str) -> str:
    return re.sub(r"\D", "", value)


def is_luhn_valid(value: str) -> bool:
    digits = digits_only(value)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        number = int(char)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def has_known_card_prefix(value: str) -> bool:
    digits = digits_only(value)
    if not digits:
        return False
    if digits[0] == "4":
        return True
    if digits[:2] in {"34", "37"}:
        return True
    if len(digits) >= 4 and 3528 <= int(digits[:4]) <= 3589:
        return True
    if len(digits) >= 2 and 50 <= int(digits[:2]) <= 59:
        return True
    if digits[0] == "6":
        return True
    if len(digits) >= 4 and 2200 <= int(digits[:4]) <= 2204:
        return True
    if len(digits) >= 4 and 2221 <= int(digits[:4]) <= 2720:
        return True
    return False


def is_bank_card_valid(value: str) -> bool:
    return is_luhn_valid(value) and has_known_card_prefix(value)


def is_snils_valid(value: str) -> bool:
    digits = digits_only(value)
    if len(digits) != 11:
        return False
    number = digits[:9]
    check = int(digits[9:])
    checksum = sum(int(digit) * weight for digit, weight in zip(number, range(9, 0, -1)))
    if checksum < 100:
        expected = checksum
    elif checksum in (100, 101):
        expected = 0
    else:
        expected = checksum % 101
        if expected == 100:
            expected = 0
    return check == expected


def is_inn_valid(value: str) -> bool:
    digits = digits_only(value)
    if len(digits) == 10:
        coeffs = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        control = sum(int(digits[i]) * coeffs[i] for i in range(9)) % 11 % 10
        return control == int(digits[9])
    if len(digits) == 12:
        coeffs_1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        coeffs_2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        control_1 = sum(int(digits[i]) * coeffs_1[i] for i in range(10)) % 11 % 10
        control_2 = sum(int(digits[i]) * coeffs_2[i] for i in range(11)) % 11 % 10
        return control_1 == int(digits[10]) and control_2 == int(digits[11])
    return False


def has_reasonable_length(value: str) -> bool:
    return len(value.strip()) >= 4


FLAGS = re.IGNORECASE | re.MULTILINE | re.UNICODE


PATTERNS: list[PatternSpec] = [
    PatternSpec(
        "email",
        "email",
        "ordinary",
        re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", FLAGS),
        confidence="medium",
    ),
    PatternSpec(
        "phone",
        "телефон",
        "ordinary",
        re.compile(r"(?<!\d)(?:\+7|8)[\s\-.(]*\d{3}[\s\-.)]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}(?!\d)", FLAGS),
        confidence="medium",
    ),
    PatternSpec(
        "full_name",
        "ФИО",
        "ordinary",
        re.compile(
            r"\b(?:"
            r"[А-ЯЁ][а-яё]{2,}\s+[А-ЯЁ][а-яё]+(?:ович|евич|ич|овна|евна|ична|инична)\s+[А-ЯЁ][а-яё]{2,}|"
            r"[А-ЯЁ][а-яё]{2,}\s+[А-ЯЁ][а-яё]{2,}\s+[А-ЯЁ][а-яё]+(?:ович|евич|ич|овна|евна|ична|инична)"
            r")\b",
            FLAGS,
        ),
        confidence="medium",
    ),
    PatternSpec(
        "birth_date",
        "дата рождения",
        "ordinary",
        re.compile(r"(?:дата\s+рождения|родил[а-я\s]{0,18}|birth\s*date)\D{0,25}(\d{1,2}[.\-/]\d{1,2}[.\-/]\d{2,4})", FLAGS),
        group=1,
        confidence="medium",
    ),
    PatternSpec(
        "birth_place",
        "место рождения",
        "ordinary",
        re.compile(r"(?:место\s+рождения|place\s+of\s+birth)\D{0,20}([^\n;,]{5,100})", FLAGS),
        group=1,
        validator=has_reasonable_length,
        confidence="medium",
    ),
    PatternSpec(
        "address",
        "адрес",
        "ordinary",
        re.compile(
            r"(?:адрес\s+(?:регистрации|проживания)|место\s+жительства|registered\s+address|residential\s+address)"
            r"\D{0,30}[^\n;]{10,160}|"
            r"\b(?:г\.|город)\s*[А-ЯЁA-Z][^\n;]{0,80}\b(?:ул\.|улица|пр-т|проспект|пер\.|переулок|д\.|дом)\b[^\n;]{5,120}|"
            r"\b(?:ул\.|улица|пр-т|проспект|пер\.|переулок)\s*[А-ЯЁA-Z0-9][^\n;]{3,100}"
            r"\b(?:д\.|дом|кв\.|квартира)\b[^\n;]{0,80}",
            FLAGS,
        ),
        validator=has_reasonable_length,
        confidence="medium",
    ),
    PatternSpec(
        "passport_rf",
        "паспорт РФ",
        "government_id",
        re.compile(r"(?:паспорт|passport|серия\s+и\s+номер)\D{0,30}(\d{2}\s?\d{2}\s?\d{6})", FLAGS),
        group=1,
        confidence="strong",
    ),
    PatternSpec(
        "snils",
        "СНИЛС",
        "government_id",
        re.compile(r"\b\d{3}[-\s]\d{3}[-\s]\d{3}[-\s]?\d{2}\b", FLAGS),
        validator=is_snils_valid,
        suspicious_on_failed_validation=True,
        confidence="strong",
    ),
    PatternSpec(
        "inn",
        "ИНН",
        "government_id",
        re.compile(r"(?:инн|inn)\D{0,20}(\d(?:[\s-]?\d){9,11})", FLAGS),
        group=1,
        validator=is_inn_valid,
        suspicious_on_failed_validation=True,
        confidence="strong",
    ),
    PatternSpec(
        "driver_license",
        "водительское удостоверение",
        "government_id",
        re.compile(r"(?:водительское|вод\.?\s*удостоверение|driver)\D{0,30}(\d{2}\s?\d{2}\s?\d{6})", FLAGS),
        group=1,
        confidence="strong",
    ),
    PatternSpec(
        "mrz",
        "MRZ",
        "government_id",
        re.compile(r"\b[A-Z0-9<]{30,44}\b\s*\n?\s*\b[A-Z0-9<]{30,44}\b", re.MULTILINE),
        confidence="strong",
    ),
    PatternSpec(
        "bank_card",
        "банковская карта",
        "payment",
        re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", FLAGS),
        validator=is_bank_card_valid,
        suspicious_on_failed_validation=True,
        confidence="strong",
    ),
    PatternSpec(
        "bank_account",
        "банковский счет",
        "payment",
        re.compile(r"(?:р/с|расчетный\s+счет|расч[её]тный\s+сч[её]т|account)\D{0,20}(\d(?:[\s-]?\d){19})", FLAGS),
        group=1,
        confidence="weak",
    ),
    PatternSpec(
        "bik",
        "БИК",
        "payment",
        re.compile(r"(?:бик|bik)\D{0,20}(\d{9})", FLAGS),
        group=1,
        confidence="weak",
    ),
    PatternSpec(
        "cvv",
        "CVV/CVC",
        "payment",
        re.compile(r"(?:cvv|cvc|код\s+безопасности)\D{0,10}(\d{3,4})", FLAGS),
        group=1,
        confidence="weak",
    ),
    PatternSpec(
        "biometric",
        "биометрические данные",
        "biometric",
        re.compile(r"\b(?:биометр\w+|отпечат(?:ок|ки)\s+пальц\w+|радужн\w+\s+оболочк\w+|голосов\w+\s+образц\w+|fingerprint|face\s?id)\b", FLAGS),
        confidence="weak",
    ),
    PatternSpec(
        "health",
        "состояние здоровья",
        "special",
        re.compile(
            r"\b(?:диагноз\w*|заболевани\w+|инвалидност\w+|анамнез|полис\s+омс|состояни\w+\s+здоровь\w+|"
            r"медицинск\w+\s+(?:карта|справка|заключени\w+|данные|сведения)|health\s+condition|medical\s+record)\b",
            FLAGS,
        ),
        confidence="weak",
    ),
    PatternSpec(
        "religion",
        "религиозные убеждения",
        "special",
        re.compile(r"\b(?:религиоз\w+|вероисповедани\w+|religion|religious)\b", FLAGS),
        confidence="weak",
    ),
    PatternSpec(
        "politics",
        "политические убеждения",
        "special",
        re.compile(r"\b(?:политическ\w+\s+убеждени\w+|партийн\w+|член\s+партии|political)\b", FLAGS),
        confidence="weak",
    ),
    PatternSpec(
        "ethnicity",
        "расовая/национальная принадлежность",
        "special",
        re.compile(r"\b(?:национальност\w+|расов\w+|этническ\w+|ethnicity|race)\b", FLAGS),
        confidence="weak",
    ),
]


def mask_value(value: str) -> str:
    value = re.sub(r"\s+", " ", value.strip())
    if not value:
        return ""
    if "@" in value:
        name, _, domain = value.partition("@")
        masked_name = (name[:2] if len(name) > 2 else name[:1]) + "***"
        masked_domain = domain[:1] + "***" if domain else "***"
        return f"{masked_name}@{masked_domain}"
    digit_count = len(digits_only(value))
    if digit_count >= 5:
        digits = digits_only(value)
        return f"{digits[:2]}***{digits[-2:]}"
    words = []
    for word in value.split(" ")[:10]:
        if re.search(r"[A-Za-zА-Яа-яЁё]", word):
            words.append(word[:1] + "***")
        else:
            words.append("***")
    return " ".join(words)[:120]


def _add_example(finding: Finding, seen_examples: set[str], value: str, max_examples: int) -> None:
    masked = mask_value(value)
    if masked and masked not in seen_examples and len(finding.examples) < max_examples:
        finding.examples.append(masked)
        seen_examples.add(masked)


def _add_span(finding: Finding, span: tuple[int, int], max_spans: int = 50) -> None:
    if len(finding.spans) < max_spans:
        finding.spans.append(span)


def _confidence_for(spec: PatternSpec, value: str) -> str:
    if spec.confidence_resolver:
        confidence = spec.confidence_resolver(value)
    else:
        confidence = spec.confidence
    if confidence not in CONFIDENCE_ORDER:
        return "medium"
    return confidence


def detect_pii_with_suspicious(text: str, max_examples: int = 3) -> DetectionResult:
    findings: list[Finding] = []
    suspicious: list[Finding] = []
    if not text:
        return DetectionResult(findings=findings, suspicious=suspicious)
    for spec in PATTERNS:
        findings_by_confidence: dict[str, Finding] = {}
        suspicious_by_confidence: dict[str, Finding] = {}
        seen_examples_by_confidence: dict[str, set[str]] = {}
        seen_suspicious_examples_by_confidence: dict[str, set[str]] = {}
        for match in spec.regex.finditer(text):
            try:
                value = match.group(spec.group)
            except IndexError:
                value = match.group(0)
            confidence = _confidence_for(spec, value)
            if spec.validator and not spec.validator(value):
                if spec.suspicious_on_failed_validation:
                    suspicious_finding = suspicious_by_confidence.setdefault(
                        confidence,
                        Finding(key=spec.key, label=spec.label, kind=spec.kind, confidence=confidence),
                    )
                    suspicious_finding.count += 1
                    _add_example(
                        suspicious_finding,
                        seen_suspicious_examples_by_confidence.setdefault(confidence, set()),
                        value,
                        max_examples,
                    )
                    _add_span(suspicious_finding, match.span(spec.group))
                continue
            finding = findings_by_confidence.setdefault(
                confidence,
                Finding(key=spec.key, label=spec.label, kind=spec.kind, confidence=confidence),
            )
            finding.count += 1
            _add_example(finding, seen_examples_by_confidence.setdefault(confidence, set()), value, max_examples)
            _add_span(finding, match.span(spec.group))
        findings.extend(finding for finding in findings_by_confidence.values() if finding.count)
        suspicious.extend(finding for finding in suspicious_by_confidence.values() if finding.count)
    return DetectionResult(findings=findings, suspicious=suspicious)


def detect_pii(text: str, max_examples: int = 3) -> list[Finding]:
    return detect_pii_with_suspicious(text, max_examples=max_examples).findings
