from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


Validator = Callable[[str], bool]


@dataclass(frozen=True)
class PatternSpec:
    key: str
    label: str
    kind: str
    regex: re.Pattern[str]
    group: int = 0
    validator: Validator | None = None


@dataclass
class Finding:
    key: str
    label: str
    kind: str
    count: int = 0
    examples: list[str] = field(default_factory=list)


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
    ),
    PatternSpec(
        "phone",
        "телефон",
        "ordinary",
        re.compile(r"(?<!\d)(?:\+7|8)[\s\-.(]*\d{3}[\s\-.)]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}(?!\d)", FLAGS),
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
    ),
    PatternSpec(
        "birth_date",
        "дата рождения",
        "ordinary",
        re.compile(r"(?:дата\s+рождения|родил[а-я\s]{0,18}|birth\s*date)\D{0,25}(\d{1,2}[.\-/]\d{1,2}[.\-/]\d{2,4})", FLAGS),
        group=1,
    ),
    PatternSpec(
        "birth_place",
        "место рождения",
        "ordinary",
        re.compile(r"(?:место\s+рождения|place\s+of\s+birth)\D{0,20}([^\n;,]{5,100})", FLAGS),
        group=1,
        validator=has_reasonable_length,
    ),
    PatternSpec(
        "address",
        "адрес",
        "ordinary",
        re.compile(
            r"(?:адрес(?:\s+(?:регистрации|проживания))?|место\s+жительства|address)\D{0,20}[^\n;]{10,140}|"
            r"\b(?:г\.|город|с\.|п\.|ул\.|улица|наб\.|пер\.|алл\.)[^\n;]{10,140}",
            FLAGS,
        ),
        validator=has_reasonable_length,
    ),
    PatternSpec(
        "passport_rf",
        "паспорт РФ",
        "government_id",
        re.compile(r"(?:паспорт|passport|серия\s+и\s+номер)\D{0,30}(\d{2}\s?\d{2}\s?\d{6})", FLAGS),
        group=1,
    ),
    PatternSpec(
        "snils",
        "СНИЛС",
        "government_id",
        re.compile(r"\b\d{3}[-\s]\d{3}[-\s]\d{3}[-\s]?\d{2}\b", FLAGS),
        validator=is_snils_valid,
    ),
    PatternSpec(
        "inn",
        "ИНН",
        "government_id",
        re.compile(r"(?:инн|inn)\D{0,20}(\d(?:[\s-]?\d){9,11})", FLAGS),
        group=1,
        validator=is_inn_valid,
    ),
    PatternSpec(
        "driver_license",
        "водительское удостоверение",
        "government_id",
        re.compile(r"(?:водительское|вод\.?\s*удостоверение|driver)\D{0,30}(\d{2}\s?\d{2}\s?\d{6})", FLAGS),
        group=1,
    ),
    PatternSpec(
        "mrz",
        "MRZ",
        "government_id",
        re.compile(r"\b[A-Z0-9<]{30,44}\b\s*\n?\s*\b[A-Z0-9<]{30,44}\b", re.MULTILINE),
    ),
    PatternSpec(
        "bank_card",
        "банковская карта",
        "payment",
        re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", FLAGS),
        validator=is_luhn_valid,
    ),
    PatternSpec(
        "bank_account",
        "банковский счет",
        "payment",
        re.compile(r"(?:р/с|расчетный\s+счет|расч[её]тный\s+сч[её]т|account)\D{0,20}(\d(?:[\s-]?\d){19})", FLAGS),
        group=1,
    ),
    PatternSpec(
        "bik",
        "БИК",
        "payment",
        re.compile(r"(?:бик|bik)\D{0,20}(\d{9})", FLAGS),
        group=1,
    ),
    PatternSpec(
        "cvv",
        "CVV/CVC",
        "payment",
        re.compile(r"(?:cvv|cvc|код\s+безопасности)\D{0,10}(\d{3,4})", FLAGS),
        group=1,
    ),
    PatternSpec(
        "biometric",
        "биометрические данные",
        "biometric",
        re.compile(r"\b(?:биометр\w+|отпечат(?:ок|ки)\s+пальц\w+|радужн\w+\s+оболочк\w+|голосов\w+\s+образц\w+|fingerprint|face\s?id)\b", FLAGS),
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
    ),
    PatternSpec(
        "religion",
        "религиозные убеждения",
        "special",
        re.compile(r"\b(?:религиоз\w+|вероисповедани\w+|religion|religious)\b", FLAGS),
    ),
    PatternSpec(
        "politics",
        "политические убеждения",
        "special",
        re.compile(r"\b(?:политическ\w+\s+убеждени\w+|партийн\w+|член\s+партии|political)\b", FLAGS),
    ),
    PatternSpec(
        "ethnicity",
        "расовая/национальная принадлежность",
        "special",
        re.compile(r"\b(?:национальност\w+|расов\w+|этническ\w+|ethnicity|race)\b", FLAGS),
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


def detect_pii(text: str, max_examples: int = 3) -> list[Finding]:
    findings: list[Finding] = []
    if not text:
        return findings
    for spec in PATTERNS:
        finding = Finding(key=spec.key, label=spec.label, kind=spec.kind)
        seen_examples: set[str] = set()
        for match in spec.regex.finditer(text):
            try:
                value = match.group(spec.group)
            except IndexError:
                value = match.group(0)
            if spec.validator and not spec.validator(value):
                continue
            finding.count += 1
            masked = mask_value(value)
            if masked and masked not in seen_examples and len(finding.examples) < max_examples:
                finding.examples.append(masked)
                seen_examples.add(masked)
        if finding.count:
            findings.append(finding)
    return findings
