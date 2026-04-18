# Утилита поиска ПДн для хакатона

Терминальная утилита для задания из `ПДнDataset/HACKATHON_CASE.md`: рекурсивно сканирует файл или директорию, извлекает текст из разных форматов, ищет категории персональных данных, определяет уровень защищенности и формирует отчеты.

## Установка Python-зависимостей

```bash
uv sync
```

`uv` создает виртуальное окружение и устанавливает Python-библиотеки, включая парсеры PDF/DOCX/RTF/XLS/XLSX, OCR-обертку `pytesseract` и `PyMuPDF` для рендера PDF-страниц.

## Установка Tesseract OCR

`uv` устанавливает только Python-обертку `pytesseract`, но не системную программу `tesseract`. Для режима OCR нужен установленный бинарник Tesseract. Если запускаете `--ocr ru en` или `--serial-ocr ru en`, также нужны языковые данные для русского и английского.

Проверка сервера:

```bash
tesseract --version
tesseract --list-langs
```

Для явного запуска `ru en` в списке языков должны быть `rus` и `eng`.

Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y tesseract-ocr tesseract-ocr-rus tesseract-ocr-eng
```

Nix shell:

```bash
nix shell nixpkgs#tesseract
```

После входа в shell повторно проверьте `tesseract --list-langs`. Если `rus` отсутствует, нужно установить или подключить пакет с русскими tessdata, доступный в Nix-канале сервера.

## Запуск

Базовый запуск без OCR:

```bash
uv run pii-scan "ПДнDataset/share" \
  --output reports/pii_report.json \
  --csv-output reports/pii_report.csv \
  --markdown-output reports/pii_report.md
```

Полный итоговый запуск с OCR:

```bash
uv run pii-scan "ПДнDataset/share" \
  --output reports/result.json \
  --csv-output reports/result.csv \
  --markdown-output reports/result.md \
  --workers 4 \
  --only-findings \
  --confidence strong \
  --ocr ru en \
  --verbose
```

Более тщательный OCR по языкам:

```bash
uv run pii-scan "ПДнDataset/share" \
  --output reports/result.json \
  --csv-output reports/result.csv \
  --markdown-output reports/result.md \
  --workers 4 \
  --only-findings \
  --confidence strong \
  --serial-ocr \
  --verbose
```

Если нужно явно задать языки Tesseract, укажите их после OCR-флага:

```bash
uv run pii-scan "ПДнDataset/share" --ocr ru en
uv run pii-scan "ПДнDataset/share" --serial-ocr ru en
```

Без списка языков используется язык Tesseract по умолчанию. Алиасы `ru` и `en` автоматически превращаются в tesseract-коды `rus` и `eng`.

## Результат

Команда выше делает один общий проход по всему `ПДнDataset/share`. Разбиения отчета по папкам, форматам или отдельным файлам нет.

Итоговые файлы:

- `reports/result.csv` - основной табличный отчет для сдачи по ТЗ;
- `reports/result.md` - краткая человекочитаемая сводка;
- `reports/result.json` - тот же список файлов в JSON-формате.

`result.csv` строго соответствует шаблону задания:

```csv
size,time,name
3068287,sep 26 18:31,CA01_01.tif
```

В `result.csv` попадают только файлы, в которых найдены ПДн. Других строк в файле нет. Поля не заполняются пустыми значениями:

- `size` - размер файла в байтах;
- `time` - время изменения файла в формате `mon dd HH:MM`;
- `name` - имя или относительный путь файла без изменения регистра.

`result.json` содержит массив объектов с теми же полями `size`, `time`, `name`.

`result.md` содержит общую статистику, распределение по уровням защищенности, распределение по категориям ПДн, подозрительные кандидаты и список файлов с наибольшим числом находок.

Для сдачи обязательно используйте файл с точным именем `result.csv`.

## Подозрительные кандидаты

Для сущностей с контрольной проверкой программа отдельно считает кандидатов, которые похожи на ПДн, но не прошли валидатор. Сейчас это:

- банковские карты, не прошедшие алгоритм Луна;
- СНИЛС с неверной контрольной суммой;
- ИНН с неверными контрольными цифрами.

Такие кандидаты полезны при OCR: Tesseract может ошибиться в одной цифре, из-за чего реальная карта или СНИЛС не пройдет контрольную сумму. По умолчанию подозрительные кандидаты не попадают в `result.csv` и `result.json`, чтобы не ухудшать лидерборд ложноположительными строками. Они отображаются только в `result.md` в отдельных секциях `Suspicious Validation Failures` и `Top Suspicious Files`.

Для ручной проверки можно явно добавить подозрительные данные в CSV/JSON:

```bash
uv run pii-scan "ПДнDataset/share" \
  --output reports/result_with_suspicious.json \
  --csv-output reports/result_with_suspicious.csv \
  --markdown-output reports/result_with_suspicious.md \
  --workers 8 \
  --only-findings \
  --ocr ru en \
  --include-suspicious \
  --verbose
```

Важно: `--include-suspicious` меняет строгий формат CSV, добавляя столбцы `suspicious` и `suspicious_count`. Такой файл нужен для анализа, но не для отправки в лидерборд.

Файл с английскими колонками `suspicious` и `suspicious_count`:

```csv
size,time,name,suspicious,suspicious_count
2963,sep 26 22:01,plan.json,"{""банковская карта"": 18}",18
```

Если в отчетах нужны только имена файлов без относительных путей, добавьте `--names-only`:

```bash
uv run pii-scan "ПДнDataset/share" \
  --output reports/result_names_only.json \
  --csv-output reports/result_names_only.csv \
  --markdown-output reports/result_names_only.md \
  --workers 8 \
  --only-findings \
  --ocr ru en \
  --names-only \
  --verbose
```

## Основные параметры

- `--ocr [LANG ...]` включает OCR для изображений, embedded images внутри PDF и fallback OCR для проблемных PDF. Без языков используется default Tesseract, например `--ocr ru en` запускает `rus+eng`.
- `--serial-ocr [LANG ...]` включает более медленный OCR. Без языков используется default Tesseract; с языками, например `--serial-ocr ru en`, запускаются `rus`, `eng`, затем `rus+eng`, и каждый результат проверяется отдельно.
- `--only-findings` оставляет в отчетах только файлы, где найдены ПДн.
- `--confidence weak|medium|strong` задает минимальную уверенность находок для отчетов; по умолчанию `medium`, для уменьшения FP используйте `strong`.
- `--include-suspicious` добавляет в CSV/JSON кандидатов, которые не прошли контрольные валидаторы.
- `--names-only` пишет только базовое имя файла в `name`, без относительного пути.
- `--workers 4` обрабатывает несколько файлов параллельно.
- `--limit 100` сканирует только первые 100 файлов для быстрой проверки.
- `--max-pdf-pages N` ограничивает число страниц PDF.
- `--high-volume-threshold 100000` задает порог большого объема для классификации УЗ. Утилита использует число находок как приближение числа субъектов.

## Уверенность находок

Детектор делит подтвержденные находки на уровни:

- `weak` - одиночные упоминания категорий или реквизиты без признаков физлица, например `religion`, `political`, `БИК`, расчетный счет;
- `medium` - обычные ПДн и контактные данные: ФИО, телефон, email, дата рождения, строгий адрес проживания/регистрации;
- `strong` - валидированные или контекстно сильные признаки: паспорт, СНИЛС, MRZ, водительское удостоверение, валидный ИНН, банковская карта с алгоритмом Луна и проверкой платежного префикса.

Флаг `--confidence` фильтрует то, что попадет в `result.csv`, `result.json` и Markdown-сводку. Для лидерборда обычно лучше начинать со строгого режима:

```bash
uv run pii-scan "ПДнDataset/share" \
  --output reports/result.json \
  --csv-output reports/result.csv \
  --markdown-output reports/result.md \
  --workers 8 \
  --only-findings \
  --confidence strong \
  --ocr ru en \
  --names-only \
  --verbose
```

## Генерация примера отчетов из списка файлов

Если нужно быстро сгенерировать пример `CSV`, `JSON` и `Markdown` без запуска детекторов, используйте `write_example_reports`. Все переданные файлы будут считаться найденными.

CLI-обертка:

```bash
uv run pii-example-report \
  "ПДнDataset/share/Архив сканы/z/zzz97c00/527802957+-2958.tif" \
  "ПДнDataset/share/Документы партнеров/rules.pdf" \
  --root "ПДнDataset/share" \
  --output reports/example.json \
  --csv-output reports/example.csv \
  --markdown-output reports/example.md
```

Если пути лежат в текстовом файле, по одному пути на строку:

```bash
uv run pii-example-report \
  --file-list files.txt \
  --root "ПДнDataset/share" \
  --output reports/example.json \
  --csv-output reports/example.csv \
  --markdown-output reports/example.md
```

Для вывода только базовых имен файлов добавьте `--names-only`.

Python API:

```python
from pii_scanner.reports import write_example_reports

write_example_reports(
    [
        "ПДнDataset/share/Архив сканы/z/zzz97c00/527802957+-2958.tif",
        "ПДнDataset/share/Документы партнеров/rules.pdf",
    ],
    json_path="reports/example.json",
    csv_path="reports/example.csv",
    markdown_path="reports/example.md",
    root="ПДнDataset/share",
)
```

Для вывода только базовых имен файлов:

```python
write_example_reports(
    files,
    json_path="reports/example.json",
    csv_path="reports/example.csv",
    markdown_path="reports/example.md",
    names_only=True,
)
```

## Форматы и поведение

Утилита поддерживает best-effort извлечение текста из `CSV`, `JSON`, `Parquet`, `PDF`, `DOCX`, `RTF`, `XLS/XLSX`, `HTML`, текстовых файлов и изображений. Для изображений нужен `--ocr`.

Если `--ocr` или `--serial-ocr` включен, PDF-страницы с embedded images дополнительно рендерятся и читаются Tesseract. PDF с предупреждениями текстового извлечения, например `SymbolSetEncoding`, или с плохим извлеченным текстом OCRятся целиком. Для рендера используется `PyMuPDF`, а если он недоступен - fallback через `pypdfium2`.

В режиме `--serial-ocr ru en` каждая OCR-страница читается тремя проходами: `rus`, `eng`, `rus+eng`. Если языки не переданы, используется один проход с языком Tesseract по умолчанию. Детектор ПДн запускается по каждому OCR-результату отдельно, а одинаковые категории объединяются без тройного увеличения счетчиков.

Имена файлов в отчетах выводятся ровно так, как они лежат на диске. URL-encoded имена вроде `%D0%A2%D0%B5%D1%81%D1%82.pdf` не декодируются.

Неподдерживаемые бинарные файлы без известного расширения, включая ELF-файлы из `lost+found`, пропускаются. Случайные строки из бинарников не используются для поиска ПДн.

Parquet читается через `pyarrow`. Если в окружении не хватает системных библиотек, например `libstdc++.so.6`, такие файлы пропускаются с предупреждением, но весь скан не падает.

## Безопасность отчета

В отчеты не записываются полные найденные значения ПДн. Программа сохраняет путь, категории, количество находок, уровень защищенности, формат файла, предупреждения и несколько маскированных примеров.
