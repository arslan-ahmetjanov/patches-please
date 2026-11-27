"""Совпадение фирменного стиля приложения и сайта документации (T-037, CON-004).

Общий блок между маркерами `shared:brand` лежит копией в двух файлах: в CSS
приложения и в CSS сайта. Сайт публикуется отдельно, поэтому файлы не общие,
и без проверки они разойдутся. Тест сравнивает блоки и следит, чтобы шапка
приложения несла тот же логотип и favicon, что и сайт.
"""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
APP_CSS = PROJECT_ROOT / "patches_please" / "templates" / "static" / "brand.css"
SITE_CSS = PROJECT_ROOT / "site" / "assets" / "style.css"
TEMPLATES = PROJECT_ROOT / "patches_please" / "templates"
START = "/* >>> shared:brand >>> */"
END = "/* <<< shared:brand <<< */"
PAGE_TEMPLATES = (
    "login.html",
    "projects.html",
    "project.html",
    "scan.html",
    "settings.html",
    "report.html",
)


def _shared_block(path: Path) -> str:
    """Кусок CSS между маркерами, с переносами строк в LF."""
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    start = text.index(START)
    finish = text.index(END) + len(END)
    return text[start:finish]


def test_con_004_site_reuses_app_brand_block() -> None:
    """Общий блок фирменного стиля у приложения и сайта совпадает побайтно."""
    assert _shared_block(APP_CSS) == _shared_block(SITE_CSS), (
        "общий блок shared:brand разошёлся: правку переносите во второй файл"
    )


def test_con_004_brand_block_has_tokens_and_fonts() -> None:
    """Общий блок держит палитру, шрифты и компоненты фирменного стиля."""
    block = _shared_block(APP_CSS)

    for token in (
        "--paper: #faf7f0",
        "--ink: #14120f",
        "--stamp-fail: #b3261e",
        "--stamp-pass: #1f6b3d",
        "--terminal-bg: #0c120c",
        "Pixelify Sans",
        "IBM Plex Sans",
        "JetBrains Mono",
        ".stamp",
        ".terminal",
        ".brand",
    ):
        assert token in block


def test_con_004_app_pages_carry_logo_and_favicon() -> None:
    """Шапка приложения повторяет шапку сайта: логотип-штамп и favicon."""
    for name in PAGE_TEMPLATES:
        text = (TEMPLATES / name).read_text(encoding="utf-8")

        assert '<img src="/static/logo.svg" alt="" width="28" height="28">' in text, name

        if name == "report.html":
            # Отчёт открывают файлом с диска: иконка встроена, а не по /static.
            assert 'rel="icon" href="data:image/svg+xml;base64,' in text, name
        else:
            assert 'rel="icon" href="/static/favicon.svg"' in text, name
