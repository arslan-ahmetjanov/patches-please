"""Замер полного прогона проверки репозитория (T-030, NFR-002).

Скрипт запускает через API столько прогонов, сколько дано токенов (по умолчанию
три), ждёт терминального статуса каждого и печатает длительности и максимум.
В замер входит весь путь прогона: клон закреплённого коммита, три сканера,
нормализация, классификация, находки, метрики, вердикт и отчёты. Время считается
от ответа `POST /api/v1/scans` до момента, когда поллинг увидел `done` или
`error`, поэтому включает до одного интервала опроса.

Прогоны идут последовательно и на разных проектах: API дедуплицирует прогоны
по паре «проект + коммит», и повторный запрос вернул бы уже завершённый прогон,
измерив ноль. Если проект уже проверял этот коммит, скрипт сообщает об этом и
завершается с ошибкой, а не подставляет чужой результат.

Параметры берутся из окружения, секретов в файле нет:

    MEASURE_API_URL     адрес API, по умолчанию http://localhost:8000
    MEASURE_TOKENS      проекты и их токены через запятую, по одному на повтор:
                        «проект=pp_...» или просто «pp_...» без метки
    MEASURE_COMMIT_SHA  полный SHA коммита (40 или 64 символа)
    MEASURE_REF         ref для истории, по умолчанию main
    MEASURE_PROVIDER    github или gitlab, по умолчанию github
    MEASURE_REPEATS     число повторов, по умолчанию 3
    MEASURE_LIMIT_SEC   порог NFR-002 в секундах, по умолчанию 600
    MEASURE_TIMEOUT_SEC предел ожидания одного прогона, по умолчанию 900
    MEASURE_POLL_SEC    интервал опроса статуса, по умолчанию 2

Код возврата: 0 — все повторы `done` и максимум не выше порога; 1 — иначе
(в том числе при ошибке прогона, таймауте ожидания или неверных параметрах).

Запуск из корня репозитория:

    MEASURE_TOKENS=repo-1=pp_...,repo-2=pp_...,repo-3=pp_... \
    MEASURE_COMMIT_SHA=<40 символов> \
    uv run python scripts/measure_scan.py

Проект задаётся токеном: отдельного поля проекта в `POST /api/v1/scans` нет,
токен привязан к проекту. Метка перед токеном нужна для отчёта и проверки, что
повторы идут на разных проектах.
"""

import os
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final, TypedDict

import httpx

DEFAULT_API_URL: Final = "http://localhost:8000"
DEFAULT_REF: Final = "main"
DEFAULT_PROVIDER: Final = "github"
DEFAULT_REPEATS: Final = 3
DEFAULT_LIMIT_SEC: Final = 600.0
DEFAULT_TIMEOUT_SEC: Final = 900.0
DEFAULT_POLL_SEC: Final = 2.0
TERMINAL_STATUSES: Final = frozenset({"done", "error"})
SUPPORTED_PROVIDERS: Final = frozenset({"github", "gitlab"})
# Допуск на расхождение часов клиента и API при проверке «прогон уже был».
# Часы у контейнера и хоста общие, поэтому допуск маленький: иначе повторный
# запуск скрипта сразу после первого принял бы старый прогон за новый.
CREATED_AT_TOLERANCE: Final = timedelta(seconds=2)
HTTP_TIMEOUT_SEC: Final = 30.0


class MeasurementError(Exception):
    """Параметры или ответ API не позволяют получить честный замер."""


class ScanState(TypedDict):
    """Поля ответа API, нужные для замера."""

    id: str
    status: str
    verdict: str | None
    created_at: str


class RunResult(TypedDict):
    """Итог одного повтора."""

    repeat: int
    project: str
    scan_id: str
    status: str
    verdict: str | None
    duration_sec: float


@dataclass(frozen=True, slots=True)
class Target:
    """Проект и его токен: проект определяет сам токен, метка — для отчёта."""

    project: str
    token: str


@dataclass(frozen=True, slots=True)
class Settings:
    """Параметры замера из переменных окружения."""

    api_url: str
    targets: tuple[Target, ...]
    commit_sha: str
    ref: str
    provider: str
    repeats: int
    limit_sec: float
    timeout_sec: float
    poll_sec: float

    @classmethod
    def from_env(cls) -> "Settings":
        """Читает и проверяет окружение до первого запроса к API."""
        targets = _parse_targets(os.environ.get("MEASURE_TOKENS", ""))
        if not targets:
            raise MeasurementError("MEASURE_TOKENS не задан: нужен токен на каждый повтор")

        commit_sha = os.environ.get("MEASURE_COMMIT_SHA", "").strip()
        if not commit_sha:
            raise MeasurementError("MEASURE_COMMIT_SHA не задан: нужен полный SHA коммита")

        provider = os.environ.get("MEASURE_PROVIDER", DEFAULT_PROVIDER).strip()
        if provider not in SUPPORTED_PROVIDERS:
            supported = ", ".join(sorted(SUPPORTED_PROVIDERS))
            raise MeasurementError(f"MEASURE_PROVIDER: допустимо {supported}")

        repeats = _env_int("MEASURE_REPEATS", DEFAULT_REPEATS)
        if repeats < 1:
            raise MeasurementError("MEASURE_REPEATS должен быть положительным")
        if len(targets) < repeats:
            raise MeasurementError(
                f"проектов {len(targets)}, а повторов {repeats}: нужен отдельный проект на повтор"
            )

        settings = cls(
            api_url=os.environ.get("MEASURE_API_URL", DEFAULT_API_URL).rstrip("/"),
            targets=targets[:repeats],
            commit_sha=commit_sha,
            ref=os.environ.get("MEASURE_REF", DEFAULT_REF).strip() or DEFAULT_REF,
            provider=provider,
            repeats=repeats,
            limit_sec=_env_float("MEASURE_LIMIT_SEC", DEFAULT_LIMIT_SEC),
            timeout_sec=_env_float("MEASURE_TIMEOUT_SEC", DEFAULT_TIMEOUT_SEC),
            poll_sec=_env_float("MEASURE_POLL_SEC", DEFAULT_POLL_SEC),
        )
        if settings.limit_sec <= 0 or settings.timeout_sec <= 0 or settings.poll_sec <= 0:
            raise MeasurementError("Порог, таймаут и интервал опроса должны быть положительными")
        if settings.timeout_sec < settings.limit_sec:
            raise MeasurementError("MEASURE_TIMEOUT_SEC меньше порога: прогон не дождёмся")
        return settings


def _env_float(name: str, default: float) -> float:
    """Число из окружения; пустое значение — умолчание."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise MeasurementError(f"{name}: ожидается число, получено {raw!r}") from exc


def _env_int(name: str, default: int) -> int:
    """Целое из окружения; пустое значение — умолчание."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise MeasurementError(f"{name}: ожидается целое число, получено {raw!r}") from exc


def _parse_targets(raw: str) -> tuple[Target, ...]:
    """Разбирает «проект=токен» через запятую; метка необязательна.

    Открытое значение токена не попадает ни в вывод, ни в сообщения об ошибках:
    метка нужна только для сводки, а проект API определяет по токену.
    """
    targets: list[Target] = []
    for item in raw.split(","):
        value = item.strip()
        if not value:
            continue
        project, separator, token = value.partition("=")
        if separator:
            if not project.strip() or not token.strip():
                raise MeasurementError(
                    "MEASURE_TOKENS: формат «проект=токен» заполнен не полностью"
                )
            targets.append(Target(project=project.strip(), token=token.strip()))
        else:
            targets.append(Target(project=f"повтор {len(targets) + 1}", token=value))
    return tuple(targets)


def _start_scan(client: httpx.Client, settings: Settings, token: str) -> tuple[ScanState, datetime]:
    """Ставит прогон и возвращает его состояние и время отправки запроса."""
    payload = {
        "commit_sha": settings.commit_sha,
        "ref": settings.ref,
        "provider": settings.provider,
    }
    started_at = datetime.now(UTC)
    response = client.post(
        "/api/v1/scans",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    response.raise_for_status()
    scan: ScanState = response.json()
    created_at = datetime.fromisoformat(scan["created_at"])
    if created_at < started_at - CREATED_AT_TOLERANCE:
        raise MeasurementError(
            "проект уже проверял этот коммит: API вернул существующий прогон "
            f"{scan['id']} от {scan['created_at']}; нужен отдельный проект на повтор"
        )
    return scan, started_at


def _wait_scan(
    client: httpx.Client,
    settings: Settings,
    token: str,
    scan_id: str,
    started_at: datetime,
) -> tuple[ScanState, float]:
    """Поллит статус до терминального и возвращает состояние и длительность."""
    deadline = time.monotonic() + settings.timeout_sec
    while True:
        response = client.get(
            f"/api/v1/scans/{scan_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        response.raise_for_status()
        scan: ScanState = response.json()
        if scan["status"] in TERMINAL_STATUSES:
            elapsed = (datetime.now(UTC) - started_at).total_seconds()
            return scan, elapsed
        if time.monotonic() >= deadline:
            raise MeasurementError(
                f"прогон {scan_id} не завершился за {settings.timeout_sec:g} с: "
                f"статус {scan['status']}"
            )
        time.sleep(settings.poll_sec)


def _measure(client: httpx.Client, settings: Settings) -> list[RunResult]:
    """Последовательные прогоны: отдельный проект и токен на каждый повтор."""
    results: list[RunResult] = []
    for index, target in enumerate(settings.targets, start=1):
        print(f"повтор {index} ({target.project}): запуск", flush=True)
        scan, started_at = _start_scan(client, settings, target.token)
        print(
            f"повтор {index} ({target.project}): прогон {scan['id']}, ждём завершения", flush=True
        )
        final, duration = _wait_scan(client, settings, target.token, scan["id"], started_at)
        result: RunResult = {
            "repeat": index,
            "project": target.project,
            "scan_id": final["id"],
            "status": final["status"],
            "verdict": final["verdict"],
            "duration_sec": round(duration, 2),
        }
        results.append(result)
        verdict = final["verdict"] if final["verdict"] is not None else "—"
        print(
            f"повтор {index} ({target.project}): {result['duration_sec']:.2f} с, "
            f"статус {final['status']}, вердикт {verdict}",
            flush=True,
        )
    return results


def _report(results: list[RunResult], settings: Settings) -> int:
    """Печатает сводку и возвращает код: 0 — порог пройден, 1 — нет."""
    durations = [result["duration_sec"] for result in results]
    maximum = max(durations)
    print()
    print(f"Прогон репозитория, коммит {settings.commit_sha}:")
    for result in results:
        print(
            f"  повтор {result['repeat']} ({result['project']}): {result['duration_sec']:.2f} с "
            f"({result['status']}, вердикт {result['verdict'] or '—'})"
        )
    print(f"Максимум: {maximum:.2f} с; порог NFR-002: {settings.limit_sec:.0f} с")

    failed = [result for result in results if result["status"] != "done"]
    if failed:
        print("Порог не проверен: не все повторы завершились done", file=sys.stderr)
        return 1
    if maximum > settings.limit_sec:
        print(
            f"Порог превышен: {maximum:.2f} с больше {settings.limit_sec:.0f} с",
            file=sys.stderr,
        )
        return 1
    print("Порог пройден")
    return 0


def main() -> int:
    """Точка входа: параметры из окружения, три повтора, сводка и код возврата."""
    try:
        settings = Settings.from_env()
    except MeasurementError as exc:
        print(f"Ошибка параметров: {exc}", file=sys.stderr)
        return 1

    print(
        f"Замер NFR-002: повторов {settings.repeats}, API {settings.api_url}, "
        f"коммит {settings.commit_sha}"
    )
    try:
        with httpx.Client(base_url=settings.api_url, timeout=HTTP_TIMEOUT_SEC) as client:
            results = _measure(client, settings)
    except (MeasurementError, httpx.HTTPError) as exc:
        print(f"Замер не выполнен: {exc}", file=sys.stderr)
        return 1
    return _report(results, settings)


if __name__ == "__main__":
    raise SystemExit(main())
