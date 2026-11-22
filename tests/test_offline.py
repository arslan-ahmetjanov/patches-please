"""Офлайн-проверка адаптеров и её сводка (T-013, FR-030).

Docker в тестах не нужен: адаптеры подменяются заглушками, которые пишут SARIF
или возвращают отказ. Проверяется правило успеха: все три `ok`, SARIF разобран
нормализатором, с `--require-findings` — ещё и непустой.
"""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from patches_please.scanners import offline
from patches_please.scanners.base import ScannerRun, ScannerStatus


def _result(rule_id: str = "fixture.rule") -> dict[str, Any]:
    """Результат SARIF, который проходит нормализатор T-012."""
    return {
        "ruleId": rule_id,
        "message": {"text": "описание находки"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 1, "snippet": {"text": "опасный вызов"}},
                }
            }
        ],
    }


class StubAdapter:
    """Адаптер-заглушка: пишет заданный SARIF или возвращает отказ."""

    def __init__(
        self,
        name: str,
        *,
        results: list[dict[str, Any]] | None = None,
        failed: bool = False,
    ) -> None:
        self.name = name
        self._results = results
        self._failed = failed

    def run(self, workdir: Path, output_dir: Path, timeout_sec: float) -> ScannerRun:
        if self._failed:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                duration_ms=0,
                error="Инструмент завершился с кодом 2",
            )
        path = output_dir / f"{self.name}.sarif"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {"tool": {"driver": {"name": self.name}}, "results": self._results or []}
                    ],
                }
            ),
            encoding="utf-8",
        )
        return ScannerRun(
            scanner=self.name,
            status=ScannerStatus.OK,
            duration_ms=0,
            sarif_path=path,
            tool_version="9.9.9",
        )


def _adapters(**kwargs: Any) -> list[StubAdapter]:
    """Три заглушки; `kwargs` применяются ко всем."""
    return [StubAdapter(name, **kwargs) for name in ("semgrep", "gitleaks", "trivy")]


def test_fr_030_offline_success_requires_three_ok_and_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Все три SARIF разобраны и дали находки — проверка успешна."""
    monkeypatch.setattr(
        offline, "default_adapters", lambda: _adapters(results=[_result(), _result("other")])
    )

    success, summary = offline.scan_offline(tmp_path, tmp_path / "out", require_findings=True)

    assert success
    assert [item["scanner"] for item in summary] == ["semgrep", "gitleaks", "trivy"]
    assert [item["status"] for item in summary] == ["ok", "ok", "ok"]
    assert [item["findings"] for item in summary] == [2, 2, 2]
    assert [item["tool_version"] for item in summary] == ["9.9.9", "9.9.9", "9.9.9"]
    assert all("_ok" not in item for item in summary)


def test_fr_030_offline_failure_marks_check_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Один упавший сканер делает проверку неуспешной, остальные остаются в сводке."""
    adapters = _adapters(results=[_result()])
    adapters[1] = StubAdapter("gitleaks", failed=True)
    monkeypatch.setattr(offline, "default_adapters", lambda: adapters)

    success, summary = offline.scan_offline(tmp_path, tmp_path / "out")

    assert not success
    assert summary[1]["status"] == "failed"
    assert summary[1]["findings"] is None
    assert summary[1]["error"]
    assert summary[0]["status"] == "ok"
    assert summary[2]["status"] == "ok"
    assert all("_ok" not in item for item in summary)


def test_fr_030_require_findings_rejects_empty_sarif(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Пустой SARIF валиден, но офлайн-проверка с флагом требует находок."""
    monkeypatch.setattr(offline, "default_adapters", lambda: _adapters(results=[]))

    optional, _ = offline.scan_offline(tmp_path, tmp_path / "out")
    strict, summary = offline.scan_offline(tmp_path, tmp_path / "out", require_findings=True)

    assert optional
    assert not strict
    assert all(item["findings"] == 0 for item in summary)
    assert all(item["error"] == "Сканер не нашёл ни одной находки" for item in summary)


def test_fr_030_offline_summary_contains_no_finding_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Сводка печатает счётчики и метаданные, а не сообщения находок."""
    monkeypatch.setattr(offline, "default_adapters", lambda: _adapters(results=[_result()]))

    _, summary = offline.scan_offline(tmp_path, tmp_path / "out")

    serialized = json.dumps(summary, ensure_ascii=False)
    assert "описание находки" not in serialized
    assert "опасный вызов" not in serialized


def test_fr_030_main_prints_json_and_returns_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Точка входа печатает JSON-сводку и код 0 при успехе."""
    monkeypatch.setattr(offline, "default_adapters", lambda: _adapters(results=[_result()]))

    code = offline.main(["--workdir", str(tmp_path), "--output", str(tmp_path / "out")])
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["ok"] is True
    assert len(payload["runs"]) == 3


def test_fr_030_main_returns_one_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Точка входа возвращает код 1, если хотя бы один сканер не дал SARIF."""
    adapters: Sequence[StubAdapter] = _adapters(results=[_result()])
    adapters = [adapters[0], StubAdapter("gitleaks", failed=True), adapters[2]]
    monkeypatch.setattr(offline, "default_adapters", lambda: list(adapters))

    code = offline.main(["--workdir", str(tmp_path), "--output", str(tmp_path / "out")])
    payload = json.loads(capsys.readouterr().out)

    assert code == 1
    assert payload["ok"] is False


def test_fr_030_main_rejects_missing_workdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Несуществующий каталог — ошибка вызова, а не пустой «успешный» прогон."""
    monkeypatch.setattr(offline, "default_adapters", lambda: _adapters(results=[_result()]))

    with pytest.raises(SystemExit) as exc:
        offline.main(["--workdir", str(tmp_path / "missing")])

    assert exc.value.code == 2
