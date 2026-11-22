"""CLI-клиент для CI: один протокол запуска и ожидания прогона (T-036, delta-008).

Клиент делает три шага: создаёт прогон через `POST /api/v1/scans`, при `--wait`
опрашивает `GET /api/v1/scans/{id}` до терминального статуса и переводит
вердикт API в код выхода. Вердикт не пересчитывается: единственный источник —
ответ сервиса (FR-037). Клиент не знает про базу, Redis и файлы репозитория
(NFR-007): только `httpx` и стандартная библиотека.

Коды выхода: 0 — `pass`; 1 — `fail`; 2 — ошибка аргументов или адреса;
3 — `401`/`403`/`404`; 4 — `status=error`, `done` без вердикта или неполный
ответ сервиса; 5 — истёк `--timeout` в ожидании; 6 — сеть, `5xx` после
повторов или непредвиденная ошибка клиента.

Токен проекта не попадает в вывод ни в одном режиме (FR-034): он живёт только
в заголовке `Authorization`, а диагностика печатает метод, адрес и код ответа.
Без `--wait` клиент только запускает прогон и выходит с 0 — для гейта в CI
нужен `--wait`, иначе вердикт не проверяется. Исключение — повторный `POST`,
который вернул уже завершённый прогон: код определяется его вердиктом.

`--fail-on-degraded` принимается, но пока ничего не передаёт: поля в
`ScanCreate` нет. Предупреждение уходит в stderr, вердикт не меняется.

`transport` в `main` — шов для тестов (`httpx.MockTransport`), в CI он не нужен.
"""

import argparse
import json
import math
import os
import sys
import time
import uuid
from collections.abc import Sequence
from typing import Any, Final
from urllib.parse import urlsplit

import httpx

EXIT_PASS: Final = 0
EXIT_FAIL: Final = 1
EXIT_USAGE: Final = 2
EXIT_ACCESS: Final = 3
EXIT_SCAN_ERROR: Final = 4
EXIT_TIMEOUT: Final = 5
EXIT_NETWORK: Final = 6

DEFAULT_SERVER: Final = "http://localhost:8000"
DEFAULT_TIMEOUT: Final = 900.0
DEFAULT_INTERVAL: Final = 5.0
SERVER_ENV: Final = "PATCHES_PLEASE_URL"
TOKEN_ENV: Final = "PATCHES_PLEASE_TOKEN"
API_PATH: Final = "/api/v1/scans"
PROVIDERS: Final = ("github", "gitlab")
TERMINAL_STATUSES: Final = frozenset({"done", "error"})
# Отчёты с находками по severity и адресом появятся в T-020; пока клиент честно
# сообщает, что данных нет, вместо выдуманных цифр.
REPORTS_NOTE: Final = "появятся вместе с отчётами (T-020)"

# Повторы: до четырёх попыток опроса с паузой 1, 2 и 4 с; каждая обрезается
# остатком дедлайна. Стартовый POST не повторяется: дельта ограничивает
# повторы опросом статуса.
RETRY_ATTEMPTS: Final = 4
RETRY_BASE_DELAY: Final = 1.0
RETRY_MAX_DELAY: Final = 30.0


class CliError(Exception):
    """Ошибка с кодом выхода: сообщение печатается в stderr, код возвращает `main`."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


class Deadline:
    """Общий дедлайн команды: `--timeout` ограничивает старт, повторы и ожидание."""

    def __init__(self, seconds: float) -> None:
        self._end = time.monotonic() + seconds

    def remaining(self) -> float:
        """Сколько секунд осталось до дедлайна; ноль — дедлайн истёк."""
        return max(0.0, self._end - time.monotonic())

    def expired(self) -> bool:
        return self.remaining() <= 0.0


def _build_parser() -> argparse.ArgumentParser:
    """Аргументы из delta-008: адрес, токен, провайдер, коммит, ref, ожидание и вывод."""
    parser = argparse.ArgumentParser(
        prog="patches-please",
        description="Клиент Patches, Please для CI: запуск прогона и код выхода по вердикту.",
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="команда")
    scan = commands.add_parser(
        "scan",
        help="запустить прогон коммита и при --wait дождаться вердикта",
        description=(
            "Создаёт прогон через POST /api/v1/scans. С --wait опрашивает статус "
            "и завершается кодом 0 при pass и 1 при fail. Без --wait только "
            "запускает прогон и выходит с 0: для гейта в CI нужен --wait. Если "
            "сервер вернул уже завершённый прогон, код определяется вердиктом."
        ),
    )
    scan.add_argument(
        "--server",
        help=f"адрес API; по умолчанию {SERVER_ENV} или {DEFAULT_SERVER}",
    )
    scan.add_argument("--token", help=f"токен проекта; по умолчанию {TOKEN_ENV}")
    scan.add_argument("--provider", metavar="github|gitlab", help="CI-провайдер (обязателен)")
    scan.add_argument("--commit", metavar="SHA", help="полный SHA коммита (обязателен)")
    scan.add_argument(
        "--ref",
        metavar="REF",
        help="git ref: main, refs/heads/main (обязателен)",
    )
    scan.add_argument("--wait", action="store_true", help="ждать завершения и проверять вердикт")
    scan.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar="СЕК",
        help=f"общий дедлайн команды в секундах (по умолчанию {DEFAULT_TIMEOUT:g})",
    )
    scan.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        metavar="СЕК",
        help=f"пауза между опросами статуса (по умолчанию {DEFAULT_INTERVAL:g})",
    )
    scan.add_argument("--json", action="store_true", help="один JSON-объект прогона в stdout")
    scan.add_argument(
        "--fail-on-degraded",
        action="store_true",
        help="намерение для сервера; пока не поддерживается и не меняет вердикт",
    )
    scan.add_argument("--verbose", action="store_true", help="печатать HTTP-диагностику в stderr")
    return parser


def _server_url(value: str | None) -> str:
    """Адрес API: явный флаг важнее переменной окружения, иначе локальный стенд.

    Пустой флаг — ошибка аргументов, а не повод молча взять переменную: в CI
    `--server "$URL"` при незаданной переменной иначе уедет на localhost.
    """
    if value is not None:
        server = value.strip()
        if not server:
            raise CliError(EXIT_USAGE, "--server не может быть пустым")
    else:
        server = os.environ.get(SERVER_ENV, "").strip() or DEFAULT_SERVER
    try:
        parts = urlsplit(server)
        # Порт разбирается отдельно: `http://host:80a` проходит urlsplit,
        # но httpx на таком адресе падает уже внутри запроса.
        _ = parts.port
    except ValueError as error:
        raise CliError(EXIT_USAGE, "--server содержит некорректный URL") from error
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise CliError(EXIT_USAGE, "--server должен быть http(s)-адресом")
    return server.rstrip("/")


def _project_token(value: str | None) -> str:
    """Токен проекта: флаг важнее переменной. Значение не печатается нигде.

    Пустой `--token` — ошибка, а не переход к переменной: иначе опечатка в CI
    незаметно подменит секрет значением из окружения.
    """
    token = value.strip() if value is not None else os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        raise CliError(
            EXIT_USAGE,
            f"не задан токен проекта: укажите --token или переменную {TOKEN_ENV}",
        )
    try:
        token.encode("ascii")
    except UnicodeEncodeError as error:
        # HTTP-заголовки кодируются в ASCII: проверяем до запроса, иначе httpx
        # упадёт уже внутри отправки, а сообщение не должно содержать токен.
        raise CliError(
            EXIT_USAGE,
            "токен содержит символы, которые нельзя отправить в HTTP-заголовке; "
            "ожидается ASCII-токен вида pp_...",
        ) from error
    return token


def _required(value: str | None, flag: str) -> str:
    """Обязательный строковый аргумент без пустых значений."""
    text = (value or "").strip()
    if not text:
        raise CliError(EXIT_USAGE, f"не задан обязательный аргумент {flag}")
    return text


def _request(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    deadline: Deadline,
    verbose: bool,
    retry: bool,
    payload: dict[str, str] | None = None,
) -> httpx.Response:
    """Запрос с повторами на `5xx` и сетевых ошибках; `4xx` возвращается сразу.

    Пауза растёт, но не выходит за остаток дедлайна. Повторы включены только для
    опроса статуса: стартовый POST не повторяется (см. delta-008).
    """
    attempts = RETRY_ATTEMPTS if retry else 1
    last_error = "истёк общий таймаут"
    for attempt in range(attempts):
        remaining = deadline.remaining()
        if remaining <= 0:
            last_error = "истёк общий таймаут"
            break
        if verbose:
            print(f"{method} {url}", file=sys.stderr)
        try:
            response = client.request(
                method,
                url,
                json=payload,
                timeout=httpx.Timeout(remaining),
            )
        except httpx.InvalidURL as error:
            raise CliError(
                EXIT_USAGE,
                f"{method} {url}: некорректный адрес сервера",
            ) from error
        except UnicodeEncodeError as error:
            raise CliError(
                EXIT_USAGE,
                "токен или адрес содержат символы, которые нельзя отправить в HTTP-заголовке",
            ) from error
        except httpx.HTTPError as error:
            last_error = f"сетевая ошибка ({error.__class__.__name__})"
        else:
            if verbose:
                print(f"{response.status_code} {method} {url}", file=sys.stderr)
            if response.status_code < 500:
                return response
            last_error = f"сервер ответил {response.status_code}"
        if attempt + 1 >= attempts:
            break
        remaining = deadline.remaining()
        if remaining <= 0:
            break
        delay = min(RETRY_BASE_DELAY * (2**attempt), RETRY_MAX_DELAY)
        time.sleep(min(delay, remaining))
    raise CliError(EXIT_NETWORK, f"{method} {url}: {last_error}")


def _ensure_success(response: httpx.Response, action: str) -> None:
    """Переводит HTTP-код в код выхода клиента; успех — `200` или `202`."""
    code = response.status_code
    if code in {200, 202}:
        return
    if code in {401, 403}:
        raise CliError(
            EXIT_ACCESS,
            f"{action}: сервер ответил {code}; проверьте токен проекта (--token или {TOKEN_ENV})",
        )
    if code == 404:
        if action == "запуск прогона":
            raise CliError(
                EXIT_USAGE,
                "запуск прогона: сервер ответил 404; проверьте адрес --server",
            )
        raise CliError(EXIT_ACCESS, f"{action}: прогон не найден или недоступен (HTTP 404)")
    if 300 <= code < 400:
        raise CliError(
            EXIT_USAGE,
            f"{action}: сервер перенаправил запрос (HTTP {code}); "
            "клиент не ходит по редиректам — укажите конечный https-адрес в --server",
        )
    if 400 <= code < 500:
        raise CliError(EXIT_USAGE, f"{action}: сервер отклонил запрос (HTTP {code})")
    raise CliError(EXIT_NETWORK, f"{action}: неожиданный ответ сервера (HTTP {code})")


def _scan_object(response: httpx.Response, action: str) -> dict[str, Any]:
    """Тело ответа как объект прогона: без идентификатора продолжать нельзя.

    Нечитаемое тело — поломка сервиса, а не сети: код 4, чтобы CI не искал
    сетевую проблему там, где сервер вернул неполный ответ.
    """
    try:
        payload = response.json()
    except ValueError as error:
        raise CliError(EXIT_SCAN_ERROR, f"{action}: сервер вернул не JSON") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("id"), str):
        raise CliError(EXIT_SCAN_ERROR, f"{action}: в ответе нет идентификатора прогона")
    try:
        scan_id = str(uuid.UUID(payload["id"]))
    except ValueError as error:
        raise CliError(
            EXIT_SCAN_ERROR,
            f"{action}: сервер вернул некорректный идентификатор прогона",
        ) from error
    # Нормализованный UUID: в URL не попадут посторонние символы из ответа.
    payload["id"] = scan_id
    return payload


def _scan_status(scan: dict[str, Any]) -> str:
    status = scan.get("status")
    if not isinstance(status, str):
        raise CliError(EXIT_SCAN_ERROR, "в ответе нет статуса прогона")
    return status


def _wait_for_terminal(
    client: httpx.Client,
    scans_url: str,
    scan: dict[str, Any],
    *,
    deadline: Deadline,
    interval: float,
    verbose: bool,
) -> dict[str, Any]:
    """Опрос до `done` или `error`; истёкший дедлайн — код 5."""
    scan_id = str(scan["id"])
    scan_url = f"{scans_url}/{scan_id}"
    first_poll = True
    while True:
        status = _scan_status(scan)
        if status in TERMINAL_STATUSES:
            return scan
        # Первый опрос — сразу после старта: при --timeout меньше --interval
        # клиент всё равно должен увидеть хотя бы один статус.
        if not first_poll:
            pause = min(interval, deadline.remaining())
            if pause <= 0:
                raise CliError(
                    EXIT_TIMEOUT,
                    f"прогон {scan_id} не завершился за отведённое время",
                )
            time.sleep(pause)
        if deadline.expired():
            raise CliError(
                EXIT_TIMEOUT,
                f"прогон {scan_id} не завершился за отведённое время",
            )
        response = _request(
            client,
            "GET",
            scan_url,
            deadline=deadline,
            verbose=verbose,
            retry=True,
        )
        _ensure_success(response, "опрос прогона")
        scan = _scan_object(response, "опрос прогона")
        first_poll = False


def _print_json(scan: dict[str, Any]) -> None:
    """Ровно один JSON-объект в stdout: диагностика идёт в stderr."""
    print(json.dumps(scan, ensure_ascii=False))


def _print_human(scan: dict[str, Any], scan_id: str) -> None:
    """Человекочитаемый режим: прогон, статус, при завершении — вердикт и отчёт."""
    print(f"Прогон: {scan_id}")
    status = _scan_status(scan)
    print(f"Статус: {status}")
    if status == "done":
        verdict = scan.get("verdict")
        print(f"Вердикт: {verdict if isinstance(verdict, str) else 'нет'}")
        print(f"Находки по severity: {REPORTS_NOTE}")
        print(f"Отчёт: {REPORTS_NOTE}")


def _emit(scan: dict[str, Any], scan_id: str, as_json: bool) -> None:
    if as_json:
        _print_json(scan)
    else:
        _print_human(scan, scan_id)


def _finish(scan: dict[str, Any], scan_id: str, as_json: bool) -> int:
    """Терминальный прогон: вывод и код по вердикту; `error` и пустой вердикт — 4."""
    status = _scan_status(scan)
    if status == "error":
        _emit(scan, scan_id, as_json)
        raise CliError(EXIT_SCAN_ERROR, f"прогон {scan_id} завершился ошибкой (status=error)")

    verdict = scan.get("verdict")
    if verdict == "pass":
        code = EXIT_PASS
    elif verdict == "fail":
        code = EXIT_FAIL
    else:
        _emit(scan, scan_id, as_json)
        raise CliError(EXIT_SCAN_ERROR, f"прогон {scan_id} завершён без вердикта")
    _emit(scan, scan_id, as_json)
    return code


def _scan(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    """Один прогон: старт, при `--wait` ожидание, вывод и код по вердикту."""
    server = _server_url(args.server)
    token = _project_token(args.token)
    provider = _required(args.provider, "--provider")
    if provider not in PROVIDERS:
        raise CliError(EXIT_USAGE, f"--provider должен быть одним из: {', '.join(PROVIDERS)}")
    commit = _required(args.commit, "--commit")
    ref = _required(args.ref, "--ref")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise CliError(EXIT_USAGE, "--timeout должен быть положительным числом")
    if not math.isfinite(args.interval) or args.interval <= 0:
        raise CliError(EXIT_USAGE, "--interval должен быть положительным числом")

    if args.fail_on_degraded:
        print(
            "предупреждение: --fail-on-degraded пока не поддерживается сервером; "
            "вердикт считает политика проекта (FR-013)",
            file=sys.stderr,
        )

    scans_url = server + API_PATH
    deadline = Deadline(float(args.timeout))
    headers = {"Authorization": f"Bearer {token}"}
    with httpx.Client(transport=transport, headers=headers) as client:
        response = _request(
            client,
            "POST",
            scans_url,
            deadline=deadline,
            verbose=args.verbose,
            retry=False,
            payload={"commit_sha": commit, "ref": ref, "provider": provider},
        )
        _ensure_success(response, "запуск прогона")
        scan = _scan_object(response, "запуск прогона")
        scan_id = str(scan["id"])

        # Повторный коммит возвращает существующий прогон; если он уже завершён,
        # ждать нечего даже без --wait, и код определяется его вердиктом.
        if _scan_status(scan) in TERMINAL_STATUSES:
            return _finish(scan, scan_id, bool(args.json))

        if not args.wait:
            _emit(scan, scan_id, bool(args.json))
            if not args.json:
                print("Вердикт не проверялся: добавьте --wait, чтобы получить код выхода.")
            return EXIT_PASS

        scan = _wait_for_terminal(
            client,
            scans_url,
            scan,
            deadline=deadline,
            interval=float(args.interval),
            verbose=args.verbose,
        )

    return _finish(scan, scan_id, bool(args.json))


def main(
    argv: Sequence[str] | None = None,
    transport: httpx.BaseTransport | None = None,
) -> int:
    """Точка входа `patches-please`: разбирает аргументы и возвращает код выхода.

    `argv` и `transport` нужны тестам: без них CLI берёт `sys.argv` и настоящую
    сеть. `--help` и ошибки разбора argparse тоже возвращаются кодом, а не
    прерывают процесс, чтобы `main` оставался вызываемым из тестов.
    """
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
        return _scan(args, transport)
    except CliError as error:
        print(f"ошибка: {error}", file=sys.stderr)
        return error.code
    except KeyboardInterrupt:
        print("прервано", file=sys.stderr)
        return 130
    except SystemExit as exit_code:
        code = exit_code.code
        return code if isinstance(code, int) else EXIT_USAGE
    except Exception as error:
        # Непредвиденная ошибка не должна выходить трассировкой и кодом 1:
        # код 1 в CI означает «вердикт fail», а не сбой клиента.
        print(
            f"внутренняя ошибка клиента ({error.__class__.__name__}); сообщите разработчикам",
            file=sys.stderr,
        )
        return EXIT_NETWORK


if __name__ == "__main__":
    sys.exit(main())
