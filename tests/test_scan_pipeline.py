"""Конвейер прогона в воркере от очереди до `done` (T-038, FR-002, FR-005, FR-019).

Проверяется один проход из `queued` в `done`: клон коммита, три сканера,
нормализация, классификация, метрики и вердикт. Вместо git и реальных
инструментов подставляются фейковый клон и адаптеры с SARIF в каталог
артефактов — база нужна, бинарники и сеть нет.
"""

import json
import logging
import uuid
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager, nullcontext
from functools import partial
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from patches_please.metrics.service import load_metrics
from patches_please.normalize.model import FindingType, Severity
from patches_please.policy.verdict import FailMode, Verdict, upsert_policy
from patches_please.projects.models import Project
from patches_please.scanners.base import ScannerAdapter, ScannerRun, ScannerStatus
from patches_please.scans.findings import load_findings
from patches_please.scans.models import Scan
from patches_please.scans.pipeline import CloneError, clone_repository, execute_scan
from patches_please.scans.queue import process_scan
from patches_please.scans.service import ScanStatus, mark_running

SHA = "c" * 40
PIPELINE_LOGGER = "patches_please.scans.pipeline"
REPO_URL = "https://example.test/demo.git"
CLONE_FAILURE = "Не удалось получить код коммита: git fetch завершился с кодом 128"


def _result(
    rule_id: str,
    severity: str,
    path: str = "src/app.py",
    line: int = 1,
) -> dict[str, object]:
    """Один result SARIF с важностью в `properties.severity`, как пишет trivy."""
    return {
        "ruleId": rule_id,
        "message": {"text": f"Находка {rule_id}"},
        "properties": {"severity": severity},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def _document(name: str, results: Sequence[dict[str, object]]) -> dict[str, object]:
    """Минимальный SARIF 2.1.0: один run и заданные results."""
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": name}}, "results": list(results)}],
    }


class SarifAdapter:
    """Адаптер без инструмента: пишет SARIF в каталог артефактов и возвращает `ok`."""

    def __init__(
        self,
        name: str,
        *results: dict[str, object],
        raw: str | None = None,
    ) -> None:
        self.name = name
        self.results = results
        self.raw = raw
        self.received_timeout: float | None = None

    def run(self, workdir: Path, output_dir: Path, timeout_sec: float) -> ScannerRun:
        self.received_timeout = timeout_sec
        path = output_dir / f"{self.name}.sarif"
        text = self.raw if self.raw is not None else json.dumps(_document(self.name, self.results))
        path.write_text(text, encoding="utf-8")
        return ScannerRun(
            scanner=self.name,
            status=ScannerStatus.OK,
            duration_ms=0,
            sarif_path=path,
            tool_version="test",
        )


class FailedAdapter:
    """Адаптер, который сообщает об отказе инструмента без исключения."""

    def __init__(self, name: str, reason: str = "Инструмент завершился с кодом 1") -> None:
        self.name = name
        self.reason = reason

    def run(self, workdir: Path, output_dir: Path, timeout_sec: float) -> ScannerRun:
        return ScannerRun(
            scanner=self.name,
            status=ScannerStatus.FAILED,
            duration_ms=0,
            error=self.reason,
        )


def _scan(
    session: Session,
    *,
    repo_url: str | None = REPO_URL,
    provider: str = "github",
) -> tuple[Project, Scan]:
    """Проект и прогон в статусе `queued`."""
    project = Project(
        name="Демо",
        slug=f"pipeline-{uuid.uuid4().hex[:8]}",
        repo_url=repo_url,
    )
    session.add(project)
    session.flush()
    scan = Scan(
        project_id=project.id,
        commit_sha=SHA,
        ref="refs/heads/main",
        provider=provider,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return project, scan


def _clone(repo_url: str, commit_sha: str, workdir: Path) -> None:
    """Фейковый клон: создаёт рабочий каталог с одним файлом, git не нужен."""
    assert repo_url and commit_sha
    (workdir / "src").mkdir(parents=True)
    (workdir / "src" / "app.py").write_text("print('demo')\n", encoding="utf-8")


def _execute(
    session: Session,
    scan: Scan,
    adapters: Sequence[ScannerAdapter],
    workspace: Path,
    *,
    clone: Callable[[str, str, Path], None] = _clone,
) -> None:
    """Запускает конвейер на тестовой сессии: база стенда не затрагивается.

    В бою `queued → running` делает `process_scan`; тесты прямого вызова
    повторяют этот переход, чтобы конвейер получил прогон в работе.
    """
    if ScanStatus(scan.status) is ScanStatus.QUEUED:
        mark_running(session, scan)
    execute_scan(
        str(scan.id),
        session_scope=lambda: nullcontext(session),
        adapters=adapters,
        clone=clone,
        workspace=workspace,
        # Отчёты (T-020) — во временный каталог теста, а не в `reports/` репозитория.
        reports_dir=workspace / "reports",
    )


# --- FR-002, FR-019: три проверки и одинаковый путь для двух провайдеров -----------


@pytest.mark.integration
@pytest.mark.parametrize("provider", ["github", "gitlab"])
def test_fr_002_pipeline_saves_findings_metrics_and_verdict(
    db_session: Session, tmp_path: Path, provider: str
) -> None:
    """Прогон доходит до `done`: находки трёх типов, метрики и вердикт записаны."""
    _, scan = _scan(db_session, provider=provider)
    adapters: list[ScannerAdapter] = [
        SarifAdapter("semgrep", _result("rule-sast", "medium")),
        SarifAdapter("gitleaks", _result("rule-secret", "low", "src/settings.py")),
        SarifAdapter("trivy", _result("rule-dep", "medium", "requirements.txt")),
    ]

    _execute(db_session, scan, adapters, tmp_path)

    assert scan.status == ScanStatus.DONE
    assert scan.started_at is not None and scan.finished_at is not None
    assert scan.error is None

    findings = load_findings(db_session, scan.id)
    assert len(findings) == 3
    assert {finding.finding_type for finding in findings} == {
        FindingType.SAST,
        FindingType.SECRETS,
        FindingType.DEPENDENCIES,
    }
    metrics = load_metrics(scan)
    assert sum(metrics.findings_by_severity.values()) == 3
    assert metrics.new == 3
    assert metrics.fixed == 0
    assert metrics.excluded_ratio == 0.0
    assert scan.verdict == Verdict.PASS


@pytest.mark.integration
def test_t_038_queue_run_reaches_done(db_session: Session, tmp_path: Path) -> None:
    """Обработчик очереди проводит прогон от `queued` до `done` с вердиктом."""
    _, scan = _scan(db_session)
    handler = partial(
        execute_scan,
        adapters=[
            SarifAdapter("semgrep", _result("rule-sast", "medium")),
            SarifAdapter("gitleaks"),
            SarifAdapter("trivy"),
        ],
        clone=_clone,
        workspace=tmp_path,
        reports_dir=tmp_path / "reports",
    )

    process_scan(str(scan.id), lambda: nullcontext(db_session), handler)

    assert scan.status == ScanStatus.DONE
    assert scan.verdict == Verdict.PASS
    assert len(load_findings(db_session, scan.id)) == 1


# --- FR-005: новая блокирующая находка --------------------------------------------


@pytest.mark.integration
def test_fr_005_new_critical_fails_under_critical_policy(
    db_session: Session, tmp_path: Path
) -> None:
    """Новая `critical` при политике `critical` даёт `fail` и остаётся в находках."""
    project, scan = _scan(db_session)
    upsert_policy(db_session, project.id, block_severities=[Severity.CRITICAL])
    adapters: list[ScannerAdapter] = [
        SarifAdapter("semgrep", _result("rule-critical", "critical")),
        SarifAdapter("gitleaks"),
        SarifAdapter("trivy", _result("rule-dep", "medium", "requirements.txt")),
    ]

    _execute(db_session, scan, adapters, tmp_path)

    assert scan.status == ScanStatus.DONE
    assert scan.verdict == Verdict.FAIL
    assert len(load_findings(db_session, scan.id)) == 2


@pytest.mark.integration
def test_fr_005_finding_below_threshold_passes(db_session: Session, tmp_path: Path) -> None:
    """`medium` при пороге `critical` вердикт не меняет."""
    project, scan = _scan(db_session)
    upsert_policy(db_session, project.id, block_severities=[Severity.CRITICAL])
    adapters: list[ScannerAdapter] = [
        SarifAdapter("semgrep", _result("rule-medium", "medium")),
        SarifAdapter("gitleaks"),
        SarifAdapter("trivy"),
    ]

    _execute(db_session, scan, adapters, tmp_path)

    assert scan.verdict == Verdict.PASS


# --- FR-013, S-004: деградация проверки -------------------------------------------


@pytest.mark.integration
def test_fr_013_failed_scanner_does_not_block_when_fail_open(
    db_session: Session, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """S-004: упавший сканер при fail-open не блокирует, но виден в логе."""
    _, scan = _scan(db_session)
    adapters: list[ScannerAdapter] = [
        SarifAdapter("semgrep", _result("rule-sast", "low")),
        FailedAdapter("gitleaks"),
        SarifAdapter("trivy"),
    ]

    with caplog.at_level(logging.WARNING, logger=PIPELINE_LOGGER):
        _execute(db_session, scan, adapters, tmp_path)

    assert scan.status == ScanStatus.DONE
    assert scan.verdict == Verdict.PASS
    assert any("проверка деградировала: gitleaks" in record.message for record in caplog.records)


@pytest.mark.integration
def test_fr_013_failed_scanner_blocks_when_fail_closed(db_session: Session, tmp_path: Path) -> None:
    """При fail-closed неполная проверка даёт `fail` даже без находок."""
    project, scan = _scan(db_session)
    upsert_policy(
        db_session,
        project.id,
        block_severities=[Severity.CRITICAL],
        fail_mode=FailMode.CLOSED,
    )
    adapters: list[ScannerAdapter] = [
        SarifAdapter("semgrep"),
        FailedAdapter("gitleaks"),
        SarifAdapter("trivy"),
    ]

    _execute(db_session, scan, adapters, tmp_path)

    assert scan.status == ScanStatus.DONE
    assert scan.verdict == Verdict.FAIL


@pytest.mark.integration
@pytest.mark.parametrize(
    ("fail_mode", "expected"),
    [(FailMode.OPEN, Verdict.PASS), (FailMode.CLOSED, Verdict.FAIL)],
)
def test_fr_013_broken_sarif_counts_as_degraded(
    db_session: Session, tmp_path: Path, fail_mode: FailMode, expected: Verdict
) -> None:
    """Битый SARIF — деградация проверки, а не падение прогона."""
    project, scan = _scan(db_session)
    upsert_policy(
        db_session,
        project.id,
        block_severities=[Severity.CRITICAL],
        fail_mode=fail_mode,
    )
    adapters: list[ScannerAdapter] = [
        SarifAdapter("semgrep", raw="{ не json"),
        SarifAdapter("gitleaks"),
        SarifAdapter("trivy"),
    ]

    _execute(db_session, scan, adapters, tmp_path)

    assert scan.status == ScanStatus.DONE
    assert scan.verdict == expected


@pytest.mark.integration
def test_t_038_scanner_timeout_comes_from_policy(db_session: Session, tmp_path: Path) -> None:
    """Конвейер передаёт сканерам таймаут из политики проекта (FR-014)."""
    project, scan = _scan(db_session)
    upsert_policy(
        db_session,
        project.id,
        block_severities=[Severity.CRITICAL],
        scanner_timeout_sec=7,
    )
    semgrep = SarifAdapter("semgrep")

    _execute(db_session, scan, [semgrep], tmp_path)

    assert semgrep.received_timeout == 7


# --- Конфигурация и клон: прогон в `error`, а не `fail` ---------------------------


@pytest.mark.integration
def test_t_038_empty_repo_url_marks_error(
    db_session: Session, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Без адреса репозитория прогон завершается `error` с причиной, а не вердиктом."""
    _, scan = _scan(db_session, repo_url=None)
    handler = partial(
        execute_scan,
        adapters=[SarifAdapter("semgrep")],
        clone=_clone,
        workspace=tmp_path,
        reports_dir=tmp_path / "reports",
    )

    with caplog.at_level(logging.WARNING, logger=PIPELINE_LOGGER):
        process_scan(str(scan.id), lambda: nullcontext(db_session), handler)

    assert scan.status == ScanStatus.ERROR
    assert scan.error is not None and "адрес репозитория" in scan.error
    assert scan.verdict is None
    assert load_findings(db_session, scan.id) == []


@pytest.mark.integration
def test_t_038_clone_failure_marks_error_without_credentials(
    db_session: Session, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Сбой клона — `error`; адрес с токеном не попадает ни в причину, ни в лог."""
    _, scan = _scan(db_session, repo_url="https://user:секретный-токен@example.test/demo.git")

    def failing_clone(repo_url: str, commit_sha: str, workdir: Path) -> None:
        raise CloneError(CLONE_FAILURE)

    with caplog.at_level(logging.WARNING, logger=PIPELINE_LOGGER):
        _execute(db_session, scan, [SarifAdapter("semgrep")], tmp_path, clone=failing_clone)

    assert scan.status == ScanStatus.ERROR
    assert scan.error == CLONE_FAILURE
    assert "секрет" not in scan.error
    assert "секрет" not in caplog.text
    assert scan.verdict is None


# --- Защита от некорректного входа ------------------------------------------------


def test_t_038_clone_rejects_empty_url(tmp_path: Path) -> None:
    """Пустой адрес не доходит до git: причина понятна без вывода команды."""
    with pytest.raises(CloneError, match="пустой адрес"):
        clone_repository("   ", SHA, tmp_path / "repo")


def test_t_038_clone_rejects_empty_commit(tmp_path: Path) -> None:
    """Пустой SHA — такая же ошибка конфигурации, а не вызов git."""
    with pytest.raises(CloneError, match="пустой идентификатор"):
        clone_repository(REPO_URL, "  ", tmp_path / "repo")


def test_t_038_malformed_scan_id_does_not_open_session(caplog: pytest.LogCaptureFixture) -> None:
    """Неверный идентификатор — ошибка в лог без открытия сессии."""

    def unused_scope() -> AbstractContextManager[Session]:
        raise AssertionError("сессия не должна открываться")

    with caplog.at_level(logging.ERROR, logger=PIPELINE_LOGGER):
        execute_scan("not-a-uuid", session_scope=unused_scope)

    assert caplog.records[-1].scan_id == "not-a-uuid"
