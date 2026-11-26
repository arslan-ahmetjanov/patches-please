// Нагрузочный замер API (T-029, NFR-001).
//
// Профиль: 20 запросов в секунду в течение DURATION (по умолчанию 60 с).
// Мерим два эндпоинта, которые CI вызывает без запуска сканеров:
//   * GET /health — служебная проверка живости;
//   * GET /api/v1/scans/{id} — поллинг статуса прогона с токеном проекта.
// POST /api/v1/scans в цикл не входит: он пишет строку в БД, ставит задачу
// в Redis и дедуплицирует прогоны по коммиту, то есть меняет состояние,
// а NFR-001 требует замер без учёта запуска сканеров.
//
// Порог NFR-001 — p95 не выше 300 мс. k6 считает http_req_duration по всем
// запросам профиля, поэтому порог проверяется на смеси двух эндпоинтов.
//
// Окружение (секретов в файле нет):
//   BASE_URL — адрес API, по умолчанию http://localhost:8000
//   TOKEN    — токен проекта (pp_...), обязателен
//   SCAN_ID  — идентификатор существующего прогона, обязателен
//   DURATION — длительность замера, по умолчанию 60s
//
// Запуск: k6 run tests/load/k6.js
// Переменные задаются через `-e ИМЯ=значение` или переменными окружения;
// подготовка TOKEN и SCAN_ID описана в docs/measurements.md.

import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = (__ENV.BASE_URL || 'http://localhost:8000').replace(/\/+$/, '');
const TOKEN = __ENV.TOKEN || '';
const SCAN_ID = __ENV.SCAN_ID || '';
const DURATION = __ENV.DURATION || '60s';

// 20 запросов в секунду — требование NFR-001.
const RATE = 20;

export const options = {
  scenarios: {
    api_20rps: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: DURATION,
      // Запас VU: при 20 RPS и отклике в единицы миллисекунд хватает нескольких,
      // но при просадке стенда k6 не должен сам стать узким местом.
      preAllocatedVUs: 20,
      maxVUs: 100,
      exec: 'api',
    },
  },
  thresholds: {
    // Порог NFR-001.
    http_req_duration: ['p(95)<300'],
    // Ответ 401/404/5xx в замере — ошибка подготовки данных, а не «быстрый ответ».
    http_req_failed: ['rate<0.01'],
  },
  // Тела ответов не нужны: мерим время ответа, а не разбор JSON.
  discardResponseBodies: true,
};

// Проверяем окружение до старта: без TOKEN и SCAN_ID профиль измерит только
// /health и ничего не скажет о поллинге, который и есть путь CI.
export function setup() {
  if (!TOKEN || !SCAN_ID) {
    throw new Error(
      'Задайте TOKEN и SCAN_ID: подготовка данных описана в docs/measurements.md (T-029)',
    );
  }
  const health = http.get(`${BASE_URL}/health`);
  if (health.status !== 200) {
    throw new Error(`GET /health вернул ${health.status}: стенд не готов`);
  }
  const scan = http.get(`${BASE_URL}/api/v1/scans/${SCAN_ID}`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });
  if (scan.status !== 200) {
    throw new Error(
      `GET /api/v1/scans/${SCAN_ID} вернул ${scan.status}: проверьте TOKEN и SCAN_ID`,
    );
  }
  // Адрес один на все VU.
  return { baseUrl: BASE_URL };
}

export function api(data) {
  // Чётные итерации мерим поллинг прогона, нечётные — healthcheck: на длинном
  // профиле смесь близка к 50/50, а не случайная.
  if (__ITER % 2 === 0) {
    const res = http.get(`${data.baseUrl}/api/v1/scans/${SCAN_ID}`, {
      headers: { Authorization: `Bearer ${TOKEN}` },
      tags: { name: 'GET /api/v1/scans/{id}' },
    });
    check(res, { 'статус прогона: 200': (r) => r.status === 200 });
    return;
  }
  const res = http.get(`${data.baseUrl}/health`, {
    tags: { name: 'GET /health' },
  });
  check(res, { 'health: 200': (r) => r.status === 200 });
}
