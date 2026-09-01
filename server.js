// Сервер базы знаний RedSMS
// Хранит данные (категории и карточки) в SQLite-базе на диске
// и отдаёт/принимает их через простое REST API.
//
// Используется встроенный в Node.js модуль node:sqlite (появился в Node 22.5,
// стабилизирован в Node 24/26) — он не требует компиляции нативных модулей
// (в отличие от better-sqlite3), поэтому не нужны Visual Studio / build tools
// ни на Windows, ни где-либо ещё. Требуется Node.js версии 22.5 или новее
// (рекомендуется 24+).

const path = require('path');
const fs = require('fs');
const express = require('express');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;

// Ключ для защиты API. Задайте свой через переменную окружения API_KEY.
// По умолчанию используется тот же пароль, что и в самом приложении ('redsms'),
// но для реальной эксплуатации рекомендуется задать свой секретный ключ.
const API_KEY = process.env.API_KEY || 'redsms';

const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'kb.db');
const SEED_PATH = path.join(__dirname, 'seed-data.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL;');

// Простая схема: одна запись, хранящая весь JSON базы знаний,
// плюс отдельная таблица истории версий на случай, если что-то
// понадобится откатить.
db.exec(`
  CREATE TABLE IF NOT EXISTS kb_store (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    json_data TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS kb_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    json_data TEXT NOT NULL,
    saved_at TEXT NOT NULL
  );
`);

function getCurrent() {
  const row = db.prepare('SELECT json_data, updated_at FROM kb_store WHERE id = 1').get();
  return row || null;
}

function seedIfEmpty() {
  const existing = getCurrent();
  if (existing) return;

  let seed = { categories: [], data: [] };
  if (fs.existsSync(SEED_PATH)) {
    seed = JSON.parse(fs.readFileSync(SEED_PATH, 'utf8'));
  }

  const now = new Date().toISOString();
  db.prepare(
    'INSERT INTO kb_store (id, json_data, updated_at) VALUES (1, ?, ?)'
  ).run(JSON.stringify(seed), now);
  console.log('База данных инициализирована начальными данными:', seed.data.length, 'карточек');
}

seedIfEmpty();

const app = express();
app.use(express.json({ limit: '10mb' }));

// Раздаём фронтенд (папка public/index.html) с того же сервера,
// чтобы не было проблем с CORS.
app.use(express.static(path.join(__dirname, 'public')));

function checkApiKey(req, res, next) {
  const key = req.get('X-API-Key') || req.query.key;
  if (key !== API_KEY) {
    return res.status(401).json({ error: 'Неверный или отсутствующий API-ключ' });
  }
  next();
}

// Получить текущие данные базы знаний
app.get('/api/kb', (req, res) => {
  const row = getCurrent();
  if (!row) return res.json({ categories: [], data: [] });
  res.set('Cache-Control', 'no-store');
  res.json(JSON.parse(row.json_data));
});

// Сохранить (перезаписать) данные целиком
app.put('/api/kb', checkApiKey, (req, res) => {
  const body = req.body;
  if (!body || !Array.isArray(body.categories) || !Array.isArray(body.data)) {
    return res.status(400).json({ error: 'Некорректный формат данных' });
  }

  const now = new Date().toISOString();
  const json = JSON.stringify(body);

  db.exec('BEGIN');
  try {
    db.prepare(
      `INSERT INTO kb_store (id, json_data, updated_at) VALUES (1, ?, ?)
       ON CONFLICT(id) DO UPDATE SET json_data = excluded.json_data, updated_at = excluded.updated_at`
    ).run(json, now);

    db.prepare('INSERT INTO kb_history (json_data, saved_at) VALUES (?, ?)').run(json, now);

    // Храним не более 50 последних версий, чтобы файл базы не разрастался бесконечно
    db.prepare(
      `DELETE FROM kb_history WHERE id NOT IN (
         SELECT id FROM kb_history ORDER BY id DESC LIMIT 50
       )`
    ).run();

    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    console.error('Ошибка сохранения в базу данных:', error);
    return res.status(500).json({ error: 'Не удалось сохранить данные' });
  }

  res.json({ ok: true, updatedAt: now });
});

// Список последних версий (на случай отката)
app.get('/api/kb/history', checkApiKey, (req, res) => {
  const rows = db
    .prepare('SELECT id, saved_at FROM kb_history ORDER BY id DESC LIMIT 50')
    .all();
  res.json(rows);
});

// Восстановить конкретную версию из истории
app.post('/api/kb/history/:id/restore', checkApiKey, (req, res) => {
  const row = db.prepare('SELECT json_data FROM kb_history WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Версия не найдена' });

  const now = new Date().toISOString();
  db.prepare('UPDATE kb_store SET json_data = ?, updated_at = ? WHERE id = 1').run(
    row.json_data,
    now
  );
  res.json({ ok: true, restoredAt: now });
});

app.listen(PORT, () => {
  console.log(`RedSMS KB сервер запущен: http://localhost:${PORT}`);
  console.log(`База данных: ${DB_PATH}`);
});
