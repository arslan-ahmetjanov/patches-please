"""Фикстурное приложение с намеренными уязвимостями (T-013, FR-030).

Все данные вымышлены. Файл нужен, чтобы офлайн-прогон давал находки всех трёх
типов: Semgrep — небезопасные вызовы, Gitleaks — секрет, Trivy — устаревшие
зависимости из requirements.txt. В демо-репозиторий T-032 файл не входит.
"""

import pickle
import subprocess

# Вымышленный секрет: не настоящий ключ, добавлен только для проверки Gitleaks.
API_TOKEN = "pp_fixture_9f3K2mQ7vR4pX8tZ"


def run_command(command: str) -> str:
    """Запускает команду через оболочку — намеренная уязвимость."""
    return subprocess.check_output(command, shell=True, text=True)


def calculate(expression: str) -> object:
    """Вычисляет выражение — намеренная уязвимость."""
    return eval(expression)


def load_state(payload: bytes) -> object:
    """Загружает состояние — намеренная уязвимость."""
    return pickle.loads(payload)
