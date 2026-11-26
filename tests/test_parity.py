"""Паритет провайдеров: один коммит из GitHub и GitLab даёт один результат (T-028, FR-019).

Проверяется путь целиком: запуск через `POST /api/v1/scans` с токеном проекта,
прогон через обработчик очереди и чтение вердикта через `GET /api/v1/scans/{id}`.
Дедупликация API идёт по паре «проект + коммит», поэтому у провайдеров два
проекта с одинаковым `repo_url` и одинаковой политикой: один и тот же коммит
даёт две строки `scans`, а не одну.

Вместо git и настоящих сканеров подставляются фейковый клон и адаптеры с SARIF —
как в `tests/test_scan_pipeline.py`: база нужна, сеть и бинарники нет. Совпадать
обязаны не только вердикт и число находок, но и полный набор полей FR-003
(сканер, правило, тип, severity, путь, строка): при равном количестве находок
расхождение в правилах или файлах всё ещё возможно.
"""

import json
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any

import pytest
from conftest import AppClient
from sqlalchemy.orm import Session

from patches_please.main import app
from patches_please.normalize.model import Severity
from patches_please.policy.verdict import Verdict, upsert_policy
from patches_please.projects.models import Project
from patches_please.scanners.base import ScannerAdapter, ScannerRun, ScannerStatus
from patches_please.scans.findings import load_findings
from patches_please.scans.models import Scan
from patches_please.scans.pipeline import execute_scan
from patches_please.scans.queue import get_scan_queue, process_scan
from patches_please.scans.service import ScanStatus
from patches_please.tokens import service as tokens_service

SHA = "c" * 40
REF = "refs/heads/main"
REPO_URL = "https://example.test/parity.git"
EXPECTED_SCANNERS = frozenset({"semgrep", "gitleaks", "trivy"})

# Ключ находки по полям FR-003: он и должен совпасть у двух провайдеров.
FindingKey = tuple[str, str, str, str, str, int]
Clone = Callable[[str, str, Path], None]

# `critical` при политике, блокирующей `critical` и `high`, даёт `fail` (S-002).
EXPECTED_FINDINGS: tuple[FindingKey, ...] = (
    ("gitleaks", "rule-secret", "secrets", "low", "src/settings.py", 3),
    ("semgrep", "rule-sast", "sast", "critical", "src/app.py", 12),
    ("trivy", "rule-dep", "dependencies", "medium", "requirements.txt", 1),
)


@dataclass(frozen=True, slots=True)
class Outcome:
    """Итог прогона в виде, который обязан совпасть у двух провайдеров."""

    status: ScanStatus
    verdict: Verdict | None
    error: str | None
    findings: tuple[FindingKey, ...]
    scanners: frozenset[str]


class FakeQueue:
    """Подмена RQ: запоминает поставленные задачи, в Redis не ходит."""

    def __init__(self) -> None:
        self.calls: list[tuple[object, str]] = []

    def enqueue(self, func: object, scan_id: str, **options: object) -> None:
        self.calls.append((func, scan_id))


@pytest.fixture
def scan_queue() -> Iterator[FakeQueue]:
    """Очередь, которую видит приложение: тест проверяет две поставленные задачи."""
    fake = FakeQueue()
    app.dependency_overrides[get_scan_queue] = lambda: fake
    try:
        yield fake
    finally:
        app.dependency_overrides.pop(get_scan_queue, None)


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

    def __init__(self, name: str, *results: dict[str, object]) -> None:
        self.name = name
        self.results = results

    def run(self, workdir: Path, output_dir: Path, timeout_sec: float) -> ScannerRun:
        path = output_dir / f"{self.name}.sarif"
        path.write_text(json.dumps(_document(self.name, self.results)), encoding="utf-8")
        return ScannerRun(
            scanner=self.name,
            status=ScannerStatus.OK,
            duration_ms=0,
            sarif_path=path,
            tool_version="test",
        )


def _adapters() -> list[ScannerAdapter]:
    """Одинаковый набор из трёх проверок: SARIF задан заранее, инструменты не нужны."""
    return [
        SarifAdapter("semgrep", _result("rule-sast", "critical", "src/app.py", 12)),
        SarifAdapter("gitleaks", _result("rule-secret", "low", "src/settings.py", 3)),
        SarifAdapter("trivy", _result("rule-dep", "medium", "requirements.txt")),
    ]


def _clone(repo_url: str, commit_sha: str, workdir: Path) -> None:
    """Фейковый клон: создаёт рабочий каталог с одним файлом, git не нужен."""
    assert repo_url and commit_sha
    (workdir / "src").mkdir(parents=True)
    (workdir / "src" / "app.py").write_text("print('demo')\n", encoding="utf-8")


def _prepared_project(session: Session, provider: str) -> tuple[Project, str]:
    """Проект с общим для обоих провайдеров адресом, политикой и токеном."""
    project = Project(
        name=f"Демо {provider}",
        slug=f"parity-{provider}",
        repo_url=REPO_URL,
    )
    session.add(project)
    session.flush()
    upsert_policy(
        session,
        project.id,
        block_severities=[Severity.CRITICAL, Severity.HIGH],
    )
    token, _ = tokens_service.create_token(session, project.id, "CI")
    session.refresh(project)
    return project, token


def _start_scan(client: AppClient, token: str, provider: str) -> dict[str, Any]:
    """Запуск прогона через API тем же набором полей, что присылает любой CI."""
    response = client.post(
        "/api/v1/scans",
        json={"commit_sha": SHA, "ref": REF, "provider": provider},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 202, response.text
    return response.json()


def _read_scan(client: AppClient, token: str, scan_id: str) -> dict[str, Any]:
    """Поллинг статуса: CI завершает job по вердикту из этого ответа."""
    response = client.get(
        f"/api/v1/scans/{scan_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _run(session: Session, scan_id: str, workspace: Path, clone: Clone = _clone) -> None:
    """Проводит прогон через обработчик очереди на тестовой сессии.

    Каталог у каждого прогона свой: клон пишется в `repo/`, SARIF — в
    `artifacts/`, отчёты — в `reports/`, и две проверки не должны делить файлы.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    process_scan(
        scan_id,
        lambda: nullcontext(session),
        partial(
            execute_scan,
            adapters=_adapters(),
            clone=clone,
            workspace=workspace,
            reports_dir=workspace / "reports",
        ),
    )


def _outcome(session: Session, scan_id: str) -> Outcome:
    """Читает завершённый прогон: вердикт, статус и находки."""
    scan = session.get(Scan, uuid.UUID(scan_id))
    assert scan is not None
    findings = load_findings(session, scan.id)
    keys = sorted(
        (
            finding.scanner,
            finding.rule_id,
            str(finding.finding_type),
            str(finding.severity),
            finding.path,
            finding.line,
        )
        for finding in findings
    )
    return Outcome(
        status=ScanStatus(scan.status),
        verdict=Verdict(scan.verdict) if scan.verdict is not None else None,
        error=scan.error,
        findings=tuple(keys),
        scanners=frozenset(finding.scanner for finding in findings),
    )


@pytest.mark.integration
def test_fr_019_same_commit_gives_same_result_for_both_providers(
    db_client: AppClient,
    db_session: Session,
    scan_queue: FakeQueue,
    tmp_path: Path,
) -> None:
    """GitHub и GitLab на одном коммите дают те же проверки, находки и вердикт."""
    github_project, github_token = _prepared_project(db_session, "github")
    gitlab_project, gitlab_token = _prepared_project(db_session, "gitlab")
    assert github_project.repo_url == gitlab_project.repo_url == REPO_URL

    github = _start_scan(db_client, github_token, "github")
    gitlab = _start_scan(db_client, gitlab_token, "gitlab")

    # Дедупликация по паре «проект + коммит» два запуска не схлопывает:
    # провайдер только записывается в историю, а задач в очереди две.
    assert github["provider"] == "github"
    assert gitlab["provider"] == "gitlab"
    assert github["commit_sha"] == gitlab["commit_sha"] == SHA
    assert github["status"] == gitlab["status"] == "queued"
    assert github["id"] != gitlab["id"]
    assert [call[1] for call in scan_queue.calls] == [github["id"], gitlab["id"]]

    clones: list[tuple[str, str]] = []

    def recording_clone(repo_url: str, commit_sha: str, workdir: Path) -> None:
        """Запоминает вход конвейера: у двух прогонов он обязан совпасть."""
        clones.append((repo_url, commit_sha))
        _clone(repo_url, commit_sha, workdir)

    _run(db_session, github["id"], tmp_path / "github", recording_clone)
    _run(db_session, gitlab["id"], tmp_path / "gitlab", recording_clone)

    assert clones == [(REPO_URL, SHA), (REPO_URL, SHA)]

    github_result = _outcome(db_session, github["id"])
    gitlab_result = _outcome(db_session, gitlab["id"])

    assert github_result.status == gitlab_result.status == ScanStatus.DONE
    assert github_result.error is None
    assert gitlab_result.error is None
    assert github_result.verdict == gitlab_result.verdict == Verdict.FAIL
    assert github_result.scanners == gitlab_result.scanners == EXPECTED_SCANNERS
    assert github_result.findings == gitlab_result.findings == EXPECTED_FINDINGS

    # Тот же вердикт виден и в ответе API, по которому CI завершает job.
    github_polled = _read_scan(db_client, github_token, github["id"])
    gitlab_polled = _read_scan(db_client, gitlab_token, gitlab["id"])
    assert github_polled["status"] == gitlab_polled["status"] == "done"
    assert github_polled["verdict"] == gitlab_polled["verdict"] == "fail"
