"""CLI-клиент CI: коды выхода, ожидание, повторы и защита токена (T-036, delta-008).

Тесты идут через шов `httpx.MockTransport` (план, «Швы тестирования», п. 3):
подменяется сервер, а не разбор аргументов или внутренние функции клиента.
Проверяется протокол снаружи — что ушло в запросе, что вернулось и с каким
кодом завершился процесс. Настоящая сеть и API не нужны: тесты быстрые и
не входят в маркер `integration`.

Требования FR-031…FR-037 и NFR-007 из delta-008; имена тестов начинаются с ID.
Токен в тестах — синтетический `pp_...`, но проверяется он как настоящий:
значение не должно встречаться ни в stdout, ни в stderr.
"""

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from patches_please import cli

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "pp_7HGf4kLmN0pQrStUvWxYz1234567890abcdef"
SHA = "a" * 40
SCAN_ID = "2f1c9a54-0d7e-4c1b-9f5a-6e2d8c3b1a90"
SERVER = "http://api.test"
PROVIDER = "github"
REF = "main"


def _payload(status: str = "queued", verdict: str | None = None, **extra: object) -> dict[str, Any]:
    """Ответ API в форме `ScanResponse`; лишние поля — для проверки FR-037."""
    payload: dict[str, Any] = {
        "id": SCAN_ID,
        "status": status,
        "commit_sha": SHA,
        "ref": REF,
        "provider": PROVIDER,
        "created_at": "2026-11-23T10:00:00Z",
        "verdict": verdict,
    }
    payload.update(extra)
    return payload


def _scan_args(*extra: str) -> list[str]:
    """Полный набор аргументов `scan`; тест добавляет только то, что проверяет."""
    return [
        "scan",
        "--server",
        SERVER,
        "--token",
        TOKEN,
        "--provider",
        PROVIDER,
        "--commit",
        SHA,
        "--ref",
        REF,
        "--interval",
        "0.01",
        *extra,
    ]


def _run(
    monkeypatch: Any,
    handler: Callable[[httpx.Request], httpx.Response],
    *extra: str,
) -> int:
    """Запускает CLI с подменённым транспортом; паузы повторов выключены."""
    monkeypatch.setattr(cli, "RETRY_BASE_DELAY", 0.0)
    return cli.main(_scan_args(*extra), transport=httpx.MockTransport(handler))


def _clean_env() -> dict[str, str]:
    """Окружение без доступа к базе и без токена: проверка самостоятельности клиента."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if key
        not in {
            "DATABASE_URL",
            "REDIS_URL",
            "PATCHES_PLEASE_URL",
            "PATCHES_PLEASE_TOKEN",
        }
    }
    environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def test_fr_031_creates_scan_and_prints_id(monkeypatch: Any, capsys: Any) -> None:
    """Полный набор аргументов — один POST с телом прогона и идентификатор в выводе."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(202, json=_payload())

    code = _run(monkeypatch, handler)
    captured = capsys.readouterr()

    assert code == cli.EXIT_PASS
    assert len(calls) == 1
    request = calls[0]
    assert request.method == "POST"
    assert str(request.url) == f"{SERVER}/api/v1/scans"
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert json.loads(request.content) == {
        "commit_sha": SHA,
        "ref": REF,
        "provider": PROVIDER,
    }
    assert SCAN_ID in captured.out


def test_fr_031_accepts_existing_scan_with_200(monkeypatch: Any, capsys: Any) -> None:
    """Повторный коммит: сервер ответил 200 существующим прогоном — это не ошибка."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json=_payload("done", "pass"))

    code = _run(monkeypatch, handler)
    captured = capsys.readouterr()

    assert code == cli.EXIT_PASS
    assert len(calls) == 1
    assert SCAN_ID in captured.out


def test_fr_031_reuses_terminal_verdict_without_wait(monkeypatch: Any) -> None:
    """200 с уже завершённым прогоном: ждать нечего, код по вердикту, без GET."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json=_payload("done", "fail"))

    code = _run(monkeypatch, handler)

    assert code == cli.EXIT_FAIL
    assert [request.method for request in calls] == ["POST"]


def test_fr_031_uses_environment_defaults(monkeypatch: Any, capsys: Any) -> None:
    """Без --server и --token значения берутся из PATCHES_PLEASE_URL и PATCHES_PLEASE_TOKEN."""
    monkeypatch.setenv(cli.SERVER_ENV, "http://env.test")
    monkeypatch.setenv(cli.TOKEN_ENV, TOKEN)
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(202, json=_payload())

    argv = ["scan", "--provider", PROVIDER, "--commit", SHA, "--ref", REF]
    code = cli.main(argv, transport=httpx.MockTransport(handler))

    assert code == cli.EXIT_PASS
    assert str(calls[0].url) == "http://env.test/api/v1/scans"
    assert calls[0].headers["Authorization"] == f"Bearer {TOKEN}"


def test_fr_031_flag_overrides_environment(monkeypatch: Any) -> None:
    """Флаг важнее переменной: в CI секрет подставляется, но отладка переопределяет."""
    monkeypatch.setenv(cli.SERVER_ENV, "http://env.test")
    monkeypatch.setenv(cli.TOKEN_ENV, "pp_из-окружения")
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(202, json=_payload())

    code = _run(monkeypatch, handler)

    assert code == cli.EXIT_PASS
    assert str(calls[0].url) == f"{SERVER}/api/v1/scans"
    assert calls[0].headers["Authorization"] == f"Bearer {TOKEN}"


def test_fr_031_help_lists_documented_arguments(capsys: Any) -> None:
    """`scan --help` печатает аргументы из delta-008 и завершается кодом 0."""
    code = cli.main(["scan", "--help"])
    output = capsys.readouterr().out

    assert code == cli.EXIT_PASS
    for flag in (
        "--server",
        "--token",
        "--provider",
        "--commit",
        "--ref",
        "--wait",
        "--timeout",
        "--interval",
        "--json",
        "--fail-on-degraded",
    ):
        assert flag in output


def test_fr_032_polls_until_done(monkeypatch: Any, capsys: Any) -> None:
    """Ожидание идёт до терминального статуса, а не до первого ответа."""
    calls: list[httpx.Request] = []
    polls = [_payload("queued"), _payload("running"), _payload("done", "pass")]

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(200, json=polls.pop(0))

    code = _run(monkeypatch, handler, "--wait")

    assert code == cli.EXIT_PASS
    gets = [request for request in calls if request.method == "GET"]
    assert len(gets) == 3
    assert str(gets[0].url) == f"{SERVER}/api/v1/scans/{SCAN_ID}"


def test_fr_032_polls_before_first_interval(monkeypatch: Any) -> None:
    """Первый опрос — сразу: при timeout меньше interval прогон всё равно виден."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(200, json=_payload("done", "pass"))

    code = _run(monkeypatch, handler, "--wait", "--interval", "5", "--timeout", "0.5")
    gets = [request for request in calls if request.method == "GET"]

    assert code == cli.EXIT_PASS
    assert len(gets) == 1


def test_fr_032_stops_polling_on_timeout(monkeypatch: Any, capsys: Any) -> None:
    """Нетерминальный прогон и истёкший дедлайн — код 5, опрос прекращается."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(200, json=_payload("running"))

    code = _run(monkeypatch, handler, "--wait", "--timeout", "0.5")
    captured = capsys.readouterr()

    assert code == cli.EXIT_TIMEOUT
    assert "не завершился" in captured.err
    gets = [request for request in calls if request.method == "GET"]
    assert len(gets) >= 1


def test_fr_033_exit_zero_on_pass(monkeypatch: Any, capsys: Any) -> None:
    """Вердикт pass — код 0 (FR-020)."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(200, json=_payload("done", "pass"))

    assert _run(monkeypatch, handler, "--wait") == cli.EXIT_PASS


def test_fr_033_exit_one_on_fail(monkeypatch: Any, capsys: Any) -> None:
    """Вердикт fail — код 1 (FR-020)."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(200, json=_payload("done", "fail"))

    assert _run(monkeypatch, handler, "--wait") == cli.EXIT_FAIL


def test_fr_033_exit_two_without_provider(monkeypatch: Any, capsys: Any) -> None:
    """Без --provider клиент не угадывает провайдера и не идёт в сеть."""
    monkeypatch.setattr(cli, "RETRY_BASE_DELAY", 0.0)

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("сеть не должна вызываться без провайдера")

    argv = ["scan", "--server", SERVER, "--token", TOKEN, "--commit", SHA, "--ref", REF]
    code = cli.main(argv, transport=httpx.MockTransport(handler))
    captured = capsys.readouterr()

    assert code == cli.EXIT_USAGE
    assert "provider" in captured.err.lower()


def test_fr_033_exit_two_without_token(monkeypatch: Any, capsys: Any) -> None:
    """Нет токена — ошибка аргументов, а не приглашение ввести его (без интерактива)."""
    monkeypatch.delenv(cli.TOKEN_ENV, raising=False)
    monkeypatch.setattr(cli, "RETRY_BASE_DELAY", 0.0)

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("сеть не должна вызываться без токена")

    argv = [
        "scan",
        "--server",
        SERVER,
        "--provider",
        PROVIDER,
        "--commit",
        SHA,
        "--ref",
        REF,
    ]
    code = cli.main(argv, transport=httpx.MockTransport(handler))
    captured = capsys.readouterr()

    assert code == cli.EXIT_USAGE
    assert "токен" in captured.err
    assert TOKEN not in captured.out + captured.err


def test_fr_033_empty_token_does_not_fall_back_to_environment(
    monkeypatch: Any, capsys: Any
) -> None:
    """`--token ""` — ошибка, а не подстановка PATCHES_PLEASE_TOKEN."""
    monkeypatch.setenv(cli.TOKEN_ENV, TOKEN)

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("сеть не должна вызываться с пустым токеном")

    argv = [
        "scan",
        "--server",
        SERVER,
        "--token",
        "",
        "--provider",
        PROVIDER,
        "--commit",
        SHA,
        "--ref",
        REF,
    ]
    assert cli.main(argv, transport=httpx.MockTransport(handler)) == cli.EXIT_USAGE
    captured = capsys.readouterr()

    assert TOKEN not in captured.out + captured.err


def test_fr_033_exit_three_on_unauthorized(monkeypatch: Any, capsys: Any) -> None:
    """401 на старте — код 3, повтор не выполняется."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(401, json={"detail": "Требуется действующий токен проекта"})

    code = _run(monkeypatch, handler)
    captured = capsys.readouterr()

    assert code == cli.EXIT_ACCESS
    assert len(calls) == 1
    assert "401" in captured.err


def test_fr_033_exit_three_on_forbidden_poll(monkeypatch: Any, capsys: Any) -> None:
    """403 при опросе — код 3."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(403, json={"detail": "Нет доступа"})

    code = _run(monkeypatch, handler, "--wait")
    captured = capsys.readouterr()

    assert code == cli.EXIT_ACCESS
    assert "403" in captured.err


def test_fr_033_exit_three_on_not_found_poll(monkeypatch: Any, capsys: Any) -> None:
    """404 при опросе — код 3: чужой прогон неотличим от несуществующего."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(404, json={"detail": "Прогон не найден"})

    code = _run(monkeypatch, handler, "--wait")
    captured = capsys.readouterr()

    assert code == cli.EXIT_ACCESS
    assert "404" in captured.err


def test_fr_033_exit_four_on_scan_error(monkeypatch: Any, capsys: Any) -> None:
    """status=error — код 4: сервис сломан, это не «код плохой»."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(200, json=_payload("error"))

    code = _run(monkeypatch, handler, "--wait")
    captured = capsys.readouterr()

    assert code == cli.EXIT_SCAN_ERROR
    assert "status=error" in captured.err


def test_fr_033_exit_four_on_existing_error_without_wait(monkeypatch: Any) -> None:
    """Повторный коммит вернул завершённый error: код 4 и без --wait."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json=_payload("error"))

    assert _run(monkeypatch, handler) == cli.EXIT_SCAN_ERROR
    assert [request.method for request in calls] == ["POST"]


def test_fr_033_exit_four_on_done_without_verdict(monkeypatch: Any, capsys: Any) -> None:
    """`done` с пустым вердиктом — поломка сервиса: код 4, а не 0."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(200, json=_payload("done"))

    code = _run(monkeypatch, handler, "--wait")
    captured = capsys.readouterr()

    assert code == cli.EXIT_SCAN_ERROR
    assert "без вердикта" in captured.err
    assert "Вердикт: нет" in captured.out
    assert "None" not in captured.out


def test_fr_033_exit_four_on_unknown_verdict(monkeypatch: Any) -> None:
    """Вердикт вне pass|fail не угадывается и не превращается в 0."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(200, json=_payload("done", "degraded"))

    assert _run(monkeypatch, handler, "--wait") == cli.EXIT_SCAN_ERROR


def test_fr_033_exit_four_on_malformed_response(monkeypatch: Any) -> None:
    """202 без идентификатора прогона — неполный ответ сервиса, код 4."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"status": "queued"})

    assert _run(monkeypatch, handler) == cli.EXIT_SCAN_ERROR


def test_fr_033_exit_four_on_response_without_status(monkeypatch: Any) -> None:
    """Неполный ответ без status — код 4, а не падение и не 0."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"id": SCAN_ID})

    assert _run(monkeypatch, handler) == cli.EXIT_SCAN_ERROR


def test_fr_033_exit_four_on_invalid_scan_id(monkeypatch: Any, capsys: Any) -> None:
    """id не из ScanResponse — поломка сервиса, код 4 до запроса статуса."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(202, json={"id": "not-a-uuid", "status": "queued"})

    code = _run(monkeypatch, handler, "--wait")
    captured = capsys.readouterr()

    assert code == cli.EXIT_SCAN_ERROR
    assert "идентификатор" in captured.err
    assert [request.method for request in calls] == ["POST"]


def test_fr_033_exit_two_on_missing_endpoint(monkeypatch: Any, capsys: Any) -> None:
    """404 на старте — неверный адрес, код 2, а не «нет доступа»."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(404, json={"detail": "Not Found"})

    code = _run(monkeypatch, handler)
    captured = capsys.readouterr()

    assert code == cli.EXIT_USAGE
    assert "проверьте адрес" in captured.err
    assert [request.method for request in calls] == ["POST"]


def test_fr_033_exit_two_on_redirect(monkeypatch: Any, capsys: Any) -> None:
    """Редирект не преследуется: клиент просит указать конечный адрес, код 2."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(301, headers={"Location": "https://api.test/api/v1/scans"})

    code = _run(monkeypatch, handler)
    captured = capsys.readouterr()

    assert code == cli.EXIT_USAGE
    assert "301" in captured.err
    assert "--server" in captured.err


def test_fr_033_exit_two_on_invalid_server(monkeypatch: Any, capsys: Any) -> None:
    """Кривой или пустой --server — ошибка аргументов, а не traceback и не код 1."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(202, json=_payload())

    for server in ("http://api.test:80a", "http://[::1", ""):
        argv = [
            "scan",
            "--server",
            server,
            "--token",
            TOKEN,
            "--provider",
            PROVIDER,
            "--commit",
            SHA,
            "--ref",
            REF,
        ]
        assert cli.main(argv, transport=httpx.MockTransport(handler)) == cli.EXIT_USAGE
    captured = capsys.readouterr()

    assert calls == []
    assert "Traceback" not in captured.err


def test_fr_033_exit_two_on_non_finite_numbers(monkeypatch: Any, capsys: Any) -> None:
    """nan и inf не проходят проверку положительности и не доходят до sleep."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("сеть не должна вызываться при неверных числах")

    for flag, value in (("--interval", "nan"), ("--timeout", "inf")):
        argv = _scan_args(flag, value)
        assert cli.main(argv, transport=httpx.MockTransport(handler)) == cli.EXIT_USAGE
    captured = capsys.readouterr()

    assert "Traceback" not in captured.err


def test_fr_033_exit_six_on_unexpected_error(monkeypatch: Any, capsys: Any) -> None:
    """Непредвиденная ошибка — код 6 без трассировки, а не ложный код 1."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise RuntimeError("неожиданный сбой")

    code = _run(monkeypatch, handler)
    captured = capsys.readouterr()

    assert code == cli.EXIT_NETWORK
    assert "RuntimeError" in captured.err
    assert "Traceback" not in captured.err
    assert TOKEN not in captured.out + captured.err


def test_fr_033_exit_six_when_server_unreachable(monkeypatch: Any, capsys: Any) -> None:
    """Соединение не установлено на старте — код 6, токен в сообщении не появляется."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        raise httpx.ConnectError("нет соединения")

    code = _run(monkeypatch, handler)
    captured = capsys.readouterr()

    assert code == cli.EXIT_NETWORK
    assert [request.method for request in calls] == ["POST"]
    assert TOKEN not in captured.out + captured.err
    assert "сетевая ошибка" in captured.err


def test_fr_034_token_not_in_output(monkeypatch: Any, capsys: Any) -> None:
    """Даже с --verbose токен не попадает ни в stdout, ни в stderr."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(200, json=_payload("done", "pass"))

    code = _run(monkeypatch, handler, "--wait", "--verbose")
    captured = capsys.readouterr()

    assert code == cli.EXIT_PASS
    assert TOKEN not in captured.out
    assert TOKEN not in captured.err
    assert "GET" in captured.err


def test_fr_034_error_message_hints_token_without_value(monkeypatch: Any, capsys: Any) -> None:
    """401: в ошибке есть код ответа и подсказка про токен, но не его значение."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(401, json={"detail": "Требуется действующий токен проекта"})

    code = _run(monkeypatch, handler, "--verbose")
    captured = capsys.readouterr()

    assert code == cli.EXIT_ACCESS
    assert "401" in captured.err
    assert cli.TOKEN_ENV in captured.err
    assert TOKEN not in captured.out + captured.err


def test_fr_034_non_ascii_token_is_argument_error(monkeypatch: Any, capsys: Any) -> None:
    """Не-ASCII токен отсекается до сети: иначе httpx упадёт вне кодов выхода."""
    unsafe_token = "pp_тестовый-токен"

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("сеть не должна вызываться с не-ASCII токеном")

    argv = [
        "scan",
        "--server",
        SERVER,
        "--token",
        unsafe_token,
        "--provider",
        PROVIDER,
        "--commit",
        SHA,
        "--ref",
        REF,
    ]
    code = cli.main(argv, transport=httpx.MockTransport(handler))
    captured = capsys.readouterr()

    assert code == cli.EXIT_USAGE
    assert unsafe_token not in captured.out + captured.err
    assert "ASCII" in captured.err


def test_fr_035_json_prints_single_object(monkeypatch: Any, capsys: Any) -> None:
    """--json: stdout содержит ровно один JSON-объект прогона без посторонних строк."""
    payload = _payload("done", "fail")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(200, json=payload)

    code = _run(monkeypatch, handler, "--wait", "--json")
    captured = capsys.readouterr()
    lines = captured.out.strip().splitlines()

    assert code == cli.EXIT_FAIL
    assert len(lines) == 1
    assert json.loads(lines[0]) == payload
    assert TOKEN not in captured.out


def test_fr_035_human_output_has_verdict_findings_and_report(monkeypatch: Any, capsys: Any) -> None:
    """Человекочитаемый режим: вердикт, находки по severity и адрес отчёта.

    Находок и адреса в ScanResponse пока нет — клиент печатает явную пометку
    вместо выдуманных данных (уточнение delta-008 к FR-035).
    """
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(200, json=_payload("done", "pass"))

    code = _run(monkeypatch, handler, "--wait")
    output = capsys.readouterr().out

    assert code == cli.EXIT_PASS
    assert "Вердикт: pass" in output
    assert "Находки по severity" in output
    assert "Отчёт:" in output


def test_fr_036_retries_on_5xx_then_exits_six(monkeypatch: Any, capsys: Any) -> None:
    """503 при опросе: попытки повторяются, затем код 6 с последней ошибкой."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(503, json={"detail": "Сервис недоступен"})

    code = _run(monkeypatch, handler, "--wait", "--timeout", "5")
    captured = capsys.readouterr()
    gets = [request for request in calls if request.method == "GET"]

    assert code == cli.EXIT_NETWORK
    assert len(gets) == cli.RETRY_ATTEMPTS
    assert len(gets) > 1
    assert "503" in captured.err


def test_fr_036_does_not_retry_4xx(monkeypatch: Any, capsys: Any) -> None:
    """4xx не повторяется: тот же неверный токен ничего не изменит."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(403, json={"detail": "Нет доступа"})

    code = _run(monkeypatch, handler, "--wait")
    gets = [request for request in calls if request.method == "GET"]

    assert code == cli.EXIT_ACCESS
    assert len(gets) == 1


def test_fr_036_retries_on_network_error_then_exits_six(monkeypatch: Any, capsys: Any) -> None:
    """Сетевая ошибка при опросе повторяется и завершается кодом 6."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        raise httpx.ConnectError("нет соединения")

    code = _run(monkeypatch, handler, "--wait", "--timeout", "5")
    captured = capsys.readouterr()
    gets = [request for request in calls if request.method == "GET"]

    assert code == cli.EXIT_NETWORK
    assert len(gets) == cli.RETRY_ATTEMPTS
    assert "сетевая ошибка" in captured.err


def test_fr_036_retry_pauses_grow_and_start_is_single(monkeypatch: Any, capsys: Any) -> None:
    """Пауза повторов растёт (1, 2, 4 с), а стартовый POST не повторяется."""
    monkeypatch.setattr(cli, "RETRY_BASE_DELAY", 1.0)
    pauses: list[float] = []
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: pauses.append(seconds))
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(503, json={"detail": "Сервис недоступен"})

    code = cli.main(_scan_args("--wait", "--timeout", "5"), transport=httpx.MockTransport(handler))
    capsys.readouterr()

    assert code == cli.EXIT_NETWORK
    assert [request.method for request in calls].count("POST") == 1
    gets = [request for request in calls if request.method == "GET"]
    assert len(gets) == cli.RETRY_ATTEMPTS
    assert pauses == [1.0, 2.0, 4.0]


def test_fr_036_retry_pauses_are_clipped_by_deadline(monkeypatch: Any, capsys: Any) -> None:
    """Пауза не выходит за дедлайн: 1 с, затем остаток 1.5 с вместо 2 с."""
    clock = [0.0]
    pauses: list[float] = []

    def fake_sleep(seconds: float) -> None:
        pauses.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cli.time, "sleep", fake_sleep)
    monkeypatch.setattr(cli, "RETRY_BASE_DELAY", 1.0)
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(503, json={"detail": "Сервис недоступен"})

    code = cli.main(
        _scan_args("--wait", "--timeout", "2.5"), transport=httpx.MockTransport(handler)
    )
    capsys.readouterr()
    gets = [request for request in calls if request.method == "GET"]

    assert code == cli.EXIT_NETWORK
    assert pauses == [1.0, 1.5]
    assert len(gets) == 2


def test_fr_037_verdict_from_api_despite_critical_findings(monkeypatch: Any, capsys: Any) -> None:
    """Клиент не пересчитывает политику: pass остаётся pass даже с critical в ответе."""
    payload = _payload(
        "done",
        "pass",
        findings=[{"severity": "critical", "title": "SQL-инъекция"}],
        report_url="http://localhost:8000/scans/" + SCAN_ID,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(200, json=payload)

    assert _run(monkeypatch, handler, "--wait") == cli.EXIT_PASS


def test_fr_037_fail_on_degraded_does_not_change_verdict(monkeypatch: Any, capsys: Any) -> None:
    """--fail-on-degraded — предупреждение в stderr; вердикт и stdout не меняются."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(202, json=_payload("queued"))
        return httpx.Response(200, json=_payload("done", "pass"))

    code = _run(monkeypatch, handler, "--wait", "--json", "--fail-on-degraded")
    captured = capsys.readouterr()
    lines = captured.out.strip().splitlines()

    assert code == cli.EXIT_PASS
    assert len(lines) == 1
    assert "предупреждение" not in captured.out
    assert "fail-on-degraded" in captured.err


def test_nfr_007_cli_does_not_import_service_stack() -> None:
    """Клиенту не нужны SQLAlchemy, Redis, RQ и FastAPI: их нет в его процессе."""
    program = (
        "import sys\n"
        "import patches_please.cli\n"
        "forbidden = sorted({'sqlalchemy', 'redis', 'rq', 'psycopg', 'fastapi'}"
        " & set(sys.modules))\n"
        "print(','.join(forbidden))\n"
        "raise SystemExit(1 if forbidden else 0)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        cwd=ROOT,
        env=_clean_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_nfr_007_module_entry_point_runs_without_database_url() -> None:
    """`python -m patches_please.cli` работает без DATABASE_URL и повторяет коды CLI."""
    help_result = subprocess.run(
        [sys.executable, "-m", "patches_please.cli", "scan", "--help"],
        cwd=ROOT,
        env=_clean_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert help_result.returncode == 0, help_result.stderr
    assert "--provider" in help_result.stdout
    assert "--fail-on-degraded" in help_result.stdout

    missing_provider = subprocess.run(
        [
            sys.executable,
            "-m",
            "patches_please.cli",
            "scan",
            "--token",
            "pp_7HGf4kLmN0pQrStUvWxYz",
            "--commit",
            SHA,
            "--ref",
            REF,
        ],
        cwd=ROOT,
        env=_clean_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert missing_provider.returncode == cli.EXIT_USAGE
