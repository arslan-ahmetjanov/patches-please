"""Маскирование секретов во всех выходах прогона (T-021, NFR-004).

Проверка идёт по всей цепочке «SARIF → нормализация → БД → JSON/HTML → лог»:
тестовый секрет из фикстуры Gitleaks не должен встречаться ни в одном выходе, а
правило, путь и строка обязаны сохраниться. Fingerprint сверяется с расчётом по
исходному сообщению, поэтому baseline прошлых прогонов не ломается.
"""

import json
import logging
import uuid
from contextlib import nullcontext
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from patches_please.normalize.fingerprint import compute_fingerprint
from patches_please.normalize.mask import MASKED_SECRET, mask_finding
from patches_please.normalize.model import Finding, FindingType, Severity
from patches_please.normalize.sarif import normalize_run
from patches_please.projects.models import Project
from patches_please.scanners.base import ScannerRun, ScannerStatus
from patches_please.scans.findings import load_records
from patches_please.scans.models import Scan
from patches_please.scans.pipeline import execute_scan
from patches_please.scans.service import ScanStatus, mark_running

FIXTURES = Path(__file__).parent / "fixtures"
GITLEAKS_SARIF = FIXTURES / "gitleaks.sarif"
SECRET = "AKIAIOSFODNN7EXAMPLE"
SECRET_MESSAGE = f"Найден ключ доступа AWS: {SECRET}"
RULE_ID = "aws-access-token"
SECRET_PATH = "config/credentials.example"
SHA = "e" * 40


def _run(scanner: str, filename: str) -> ScannerRun:
    """Успешный запуск сканера на фикстуре из `tests/fixtures`."""
    return ScannerRun(
        scanner=scanner,
        status=ScannerStatus.OK,
        duration_ms=0,
        sarif_path=FIXTURES / filename,
    )


def _finding(finding_type: FindingType = FindingType.SECRETS) -> Finding:
    """Находка для проверки самой функции маскирования."""
    return Finding(
        scanner="gitleaks",
        rule_id=RULE_ID,
        severity=Severity.HIGH,
        path=SECRET_PATH,
        line=7,
        message=SECRET_MESSAGE,
        finding_type=finding_type,
        fingerprint="fingerprint",
    )


# --- Нормализация -----------------------------------------------------------------


def test_nfr_004_secret_message_is_masked() -> None:
    """Находка Gitleaks приходит с заглушкой, а правило, путь и строка — на месте."""
    findings = normalize_run(_run("gitleaks", GITLEAKS_SARIF.name), FIXTURES)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.message == MASKED_SECRET
    assert SECRET not in finding.message
    assert finding.rule_id == RULE_ID
    assert finding.path == SECRET_PATH
    assert finding.line == 1


def test_nfr_004_fingerprint_is_computed_from_original_snippet() -> None:
    """Fingerprint совпадает с расчётом по исходному сообщению: baseline не ломается."""
    finding = normalize_run(_run("gitleaks", GITLEAKS_SARIF.name), FIXTURES)[0]

    expected = compute_fingerprint("gitleaks", RULE_ID, SECRET_PATH, SECRET_MESSAGE)
    assert finding.fingerprint == expected


def test_nfr_004_non_secret_finding_is_untouched() -> None:
    """Сообщения SAST не маскируются: заглушка только у находок типа `secrets`."""
    sast = _finding(FindingType.SAST)

    assert mask_finding(sast) is sast
    assert mask_finding(sast).message == SECRET_MESSAGE


def test_nfr_004_masking_keeps_fingerprint_and_location() -> None:
    """Маскирование меняет только сообщение."""
    masked = mask_finding(_finding())

    assert masked.message == MASKED_SECRET
    assert masked.fingerprint == "fingerprint"
    assert (masked.rule_id, masked.path, masked.line) == (RULE_ID, SECRET_PATH, 7)


# --- Прогон целиком: БД, отчёты и лог ---------------------------------------------


class _SarifAdapter:
    """Адаптер без инструмента: кладёт готовый SARIF в каталог артефактов."""

    def __init__(self, name: str, document: dict[str, object] | None = None) -> None:
        self.name = name
        self.document = document or {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": name}}, "results": []}],
        }

    def run(self, workdir: Path, output_dir: Path, timeout_sec: float) -> ScannerRun:
        path = output_dir / f"{self.name}.sarif"
        path.write_text(json.dumps(self.document), encoding="utf-8")
        return ScannerRun(
            scanner=self.name,
            status=ScannerStatus.OK,
            duration_ms=0,
            sarif_path=path,
            tool_version="test",
        )


def _clone(repo_url: str, commit_sha: str, workdir: Path) -> None:
    """Фейковый клон: каталог с файлом находки, git не нужен."""
    assert repo_url and commit_sha
    (workdir / "config").mkdir(parents=True)
    (workdir / "config" / "credentials.example").write_text("demo\n", encoding="utf-8")


def _queued_scan(session: Session) -> Scan:
    """Проект с адресом репозитория и прогон в очереди."""
    project = Project(
        name="Демо",
        slug=f"mask-{uuid.uuid4().hex[:8]}",
        repo_url="https://example.test/demo.git",
    )
    session.add(project)
    session.flush()
    scan = Scan(project_id=project.id, commit_sha=SHA, ref="refs/heads/main", provider="github")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


@pytest.mark.integration
def test_nfr_004_secret_absent_from_database_reports_and_log(
    db_session: Session, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Секрет не попадает ни в `findings.message`, ни в отчёты, ни в лог прогона."""
    scan = _queued_scan(db_session)
    document = json.loads(GITLEAKS_SARIF.read_text(encoding="utf-8"))
    directory = tmp_path / "reports"
    mark_running(db_session, scan)

    with caplog.at_level(logging.DEBUG):
        execute_scan(
            str(scan.id),
            session_scope=lambda: nullcontext(db_session),
            adapters=[
                _SarifAdapter("semgrep"),
                _SarifAdapter("gitleaks", document),
                _SarifAdapter("trivy"),
            ],
            clone=_clone,
            workspace=tmp_path / "work",
            reports_dir=directory,
        )

    assert scan.status == ScanStatus.DONE
    records = load_records(db_session, scan.id)
    assert len(records) == 1
    record = records[0]
    assert record.message == MASKED_SECRET
    assert SECRET not in record.message
    assert (record.rule_id, record.path, record.line) == (RULE_ID, SECRET_PATH, 1)
    assert record.fingerprint == compute_fingerprint(
        "gitleaks", RULE_ID, SECRET_PATH, SECRET_MESSAGE
    )

    json_text = (directory / f"{scan.id}.json").read_text(encoding="utf-8")
    html_text = (directory / f"{scan.id}.html").read_text(encoding="utf-8")
    assert SECRET not in json_text
    assert SECRET not in html_text
    assert MASKED_SECRET in json_text
    assert MASKED_SECRET in html_text
    assert RULE_ID in html_text
    assert SECRET_PATH in html_text

    assert SECRET not in caplog.text
