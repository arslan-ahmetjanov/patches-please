"""Проверка собранного wheel: установка в чистый venv и импорт извне репозитория (T-035).

Запуск из корня репозитория:

    uv run python -m scripts.check_wheel

Скрипт берёт свежий `dist/patches_please-*.whl`, создаёт временное окружение в
системном каталоге вне репозитория, ставит туда wheel и запускает проверку с
рабочим каталогом внутри этого окружения. Корень репозитория в `sys.path` не
попадает, поэтому импортируется именно установленный пакет: подмена исходниками
невозможна.

Проверяется три вещи: модуль импортируется из окружения, а не из репозитория;
каталог шаблонов внутри пакета существует и содержит `login.html`; миграции
попали в wheel вместе с `env.py`.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

PROBE = """\
import sys
from pathlib import Path

import patches_please
from patches_please.auth.router import TEMPLATES_DIR

repo_root = Path(sys.argv[1]).resolve()
package_path = Path(patches_please.__file__).resolve()
environment = Path(sys.prefix).resolve()

if repo_root in package_path.parents:
    raise SystemExit(f"импортирован пакет из репозитория: {package_path}")
if environment not in package_path.parents:
    raise SystemExit(f"пакет установлен не в это окружение: {package_path}")

login = TEMPLATES_DIR / "login.html"
if not TEMPLATES_DIR.is_dir():
    raise SystemExit(f"каталог шаблонов не найден: {TEMPLATES_DIR}")
if not login.is_file():
    raise SystemExit(f"в каталоге шаблонов нет login.html: {TEMPLATES_DIR}")

migrations = package_path.parent / "migrations"
if not (migrations / "env.py").is_file():
    raise SystemExit(f"в wheel нет миграций: {migrations}")

print(f"wheel: {package_path.parent.name}, шаблоны: {TEMPLATES_DIR.name}, "
      f"login.html: {'есть' if login.is_file() else 'нет'}")
print(f"пакет импортирован из {package_path}")
"""


def _run(args: list[str], cwd: Path, env: dict[str, str]) -> str:
    """Выполняет команду и возвращает её stdout; ошибка — исключение с stderr."""
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"команда {' '.join(args)} завершилась с кодом {result.returncode}:\n"
            f"{result.stdout}{result.stderr}"
        )
    return result.stdout


def _find_wheel() -> Path:
    """Свежий wheel из `dist/`: сборка кладёт туда ровно один файл версии проекта."""
    wheels = sorted(DIST.glob("patches_please-*.whl"), key=lambda path: path.stat().st_mtime)
    if not wheels:
        raise RuntimeError("в dist/ нет wheel; сначала выполните `uv build`")
    return wheels[-1]


def _venv_python(venv: Path) -> Path:
    """Путь к интерпретатору окружения: на Windows он лежит в Scripts/."""
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def _clean_environment() -> dict[str, str]:
    """Окружение без PYTHONPATH и VIRTUAL_ENV: репозиторий не должен влиять на импорт.

    `PYTHONIOENCODING` фиксирует UTF-8 у дочерних процессов: иначе на Windows
    их вывод приходит в кодировке консоли и портится при чтении.
    """
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"}
    }
    environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def _use_utf8_console() -> None:
    """Переводит вывод скрипта в UTF-8: иначе консоль Windows печатает русский текст нечитаемо."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    """Собирает окружение, ставит wheel и запускает проверку."""
    _use_utf8_console()
    workdir: Path | None = None
    try:
        wheel = _find_wheel()
        uv = shutil.which("uv")
        if uv is None:
            raise RuntimeError("не найден uv; проверка wheel запускается через `uv run`")

        workdir = Path(tempfile.mkdtemp(prefix="patches-please-wheel-"))
        venv = workdir / "venv"
        environment = _clean_environment()
        _run([uv, "venv", "--python", "3.12", str(venv)], cwd=workdir, env=environment)
        python = _venv_python(venv)
        # Зависимости ставим вместе с пакетом: проверка повторяет пользовательскую установку.
        _run(
            [uv, "pip", "install", "--python", str(python), str(wheel)],
            cwd=workdir,
            env=environment,
        )

        probe = workdir / "probe.py"
        probe.write_text(PROBE, encoding="utf-8")
        output = _run([str(python), str(probe), str(ROOT)], cwd=workdir, env=environment)
    except (OSError, RuntimeError) as error:
        print(f"ошибка: {error}", file=sys.stderr)
        if workdir is not None:
            print(f"рабочий каталог оставлен для разбора: {workdir}", file=sys.stderr)
        return 1

    print(output.strip())
    print(f"wheel {wheel.name} установлен и импортируется вне репозитория")
    shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
