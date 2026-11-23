"""HTML-отчёт прогона (T-020, FR-008, S-002, S-004).

HTML — артефакт для человека: его открывают из пайплайна и с диска, поэтому
страница самодостаточна, без внешних стилей и скриптов. Данные берутся из той
же модели `ScanReport`, что и JSON: два отчёта не могут рассказать разное.

Шаблон лежит в пакете (`patches_please/templates/report.html`), поэтому
работает и из исходников, и из установленного wheel. Jinja2 экранирует
значения по умолчанию: текст находки может содержать `<`, `>` и кавычки.
Содержимое находок не пишется в лог (NFR-004).
"""

from pathlib import Path

from fastapi.templating import Jinja2Templates

from patches_please.reports.json_report import ScanReport

# Шаблоны лежат в пакете: от `patches_please/reports` это один уровень вверх.
TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
TEMPLATE_NAME = "report.html"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def render_html(report: ScanReport) -> str:
    """Страница отчёта как строка: рендер не зависит от HTTP-запроса."""
    template = templates.env.get_template(TEMPLATE_NAME)
    return template.render(report=report)


def write_html(report: ScanReport, path: Path) -> None:
    """Пишет HTML-отчёт в файл целиком, в UTF-8 и с переводами строк LF."""
    path.write_text(render_html(report), encoding="utf-8", newline="\n")
