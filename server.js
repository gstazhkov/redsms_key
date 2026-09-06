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
const crypto = require('crypto');
const express = require('express');
const multer = require('multer');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const INITIAL_ADMIN_LOGIN = process.env.ADMIN_LOGIN || 'admin';
const INITIAL_ADMIN_PASSWORD = process.env.REDSMS_PASSWORD || 'redsms';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const SESSION_COOKIE = 'redsms_session';

if (!process.env.REDSMS_PASSWORD || !process.env.SESSION_SECRET) {
  console.warn('Внимание: задайте REDSMS_PASSWORD и SESSION_SECRET перед production-запуском.');
}

const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'kb.db');
const SEED_PATH = path.join(__dirname, 'seed-data.json');
const WIKI_SEED_PATH = path.join(__dirname, 'wiki-seed-data.json');
const DOCS_DIR = path.join(DATA_DIR, 'documents');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DOCS_DIR)) fs.mkdirSync(DOCS_DIR, { recursive: true });

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

  CREATE TABLE IF NOT EXISTS wiki_store (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    json_data TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS wiki_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    json_data TEXT NOT NULL,
    saved_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    original_name TEXT NOT NULL,
    file_name TEXT NOT NULL UNIQUE,
    uploaded_at TEXT NOT NULL,
    size INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    login TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('reader', 'editor', 'admin')),
    created_at TEXT NOT NULL
  );
`);

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derivedKey = crypto.scryptSync(password, salt, 64);
  return `${salt.toString('base64url')}.${derivedKey.toString('base64url')}`;
}

function verifyPassword(password, storedHash) {
  const [saltText, hashText] = storedHash.split('.');
  if (!saltText || !hashText) return false;
  try {
    const salt = Buffer.from(saltText, 'base64url');
    const expected = Buffer.from(hashText, 'base64url');
    const actual = crypto.scryptSync(password, salt, expected.length);
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function seedAdminUser() {
  const existing = db.prepare('SELECT id FROM users LIMIT 1').get();
  if (existing) return;
  db.prepare(
    'INSERT INTO users (id, login, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run(crypto.randomUUID(), INITIAL_ADMIN_LOGIN, hashPassword(INITIAL_ADMIN_PASSWORD), 'admin', new Date().toISOString());
  console.log('Создан первоначальный пользователь администратора:', INITIAL_ADMIN_LOGIN);
}

seedAdminUser();

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

function getCurrentWiki() {
  const row = db.prepare('SELECT json_data, updated_at FROM wiki_store WHERE id = 1').get();
  return row || null;
}

function seedWikiIfEmpty() {
  const existing = getCurrentWiki();
  if (existing) return;

  let seed = { pages: [] };
  if (fs.existsSync(WIKI_SEED_PATH)) {
    seed = JSON.parse(fs.readFileSync(WIKI_SEED_PATH, 'utf8'));
  } else {
    // Дефолтная приветственная страница, если отдельного seed-файла нет
    const now = new Date().toISOString();
    seed = {
      pages: [
        {
          id: 'w1',
          parentId: null,
          icon: '👋',
          title: 'Добро пожаловать в Wiki',
          content: '<h1>Добро пожаловать!</h1><p>Это ваша база знаний в стиле Notion. Создавайте страницы, вкладывайте их друг в друга и оформляйте текст через панель инструментов.</p>',
          updatedAt: now
        }
      ]
    };
  }

  const now = new Date().toISOString();
  db.prepare(
    'INSERT INTO wiki_store (id, json_data, updated_at) VALUES (1, ?, ?)'
  ).run(JSON.stringify(seed), now);
  console.log('Wiki инициализирована начальными данными:', seed.pages.length, 'страниц');
}

seedWikiIfEmpty();

const app = express();
app.use(express.json({ limit: '10mb' }));

function createSession(user) {
  const payload = Buffer.from(JSON.stringify({
    exp: Date.now() + SESSION_TTL_MS,
    nonce: crypto.randomBytes(16).toString('hex'),
    userId: user.id,
    login: user.login,
    role: user.role
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function getCookie(req, name) {
  const cookies = (req.get('Cookie') || '').split(';');
  const cookie = cookies.find(value => value.trim().startsWith(`${name}=`));
  return cookie ? decodeURIComponent(cookie.trim().slice(name.length + 1)) : null;
}

function getSession(req) {
  const token = getCookie(req, SESSION_COOKIE);
  if (!token) return null;

  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;

  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  const actualBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (actualBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(actualBuffer, expectedBuffer)) {
    return null;
  }

  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (session.exp <= Date.now() || !session.userId || !session.role) return null;
    const user = db.prepare('SELECT id, login, role FROM users WHERE id = ?').get(session.userId);
    return user && user.login === session.login && user.role === session.role ? user : null;
  } catch {
    return null;
  }
}

function hasValidSession(req) {
  return Boolean(getSession(req));
}

const failedLogins = new Map();
function isLoginBlocked(ip) {
  const record = failedLogins.get(ip);
  if (!record) return false;
  if (record.blockedUntil <= Date.now()) {
    failedLogins.delete(ip);
    return false;
  }
  return record.attempts >= 5;
}

function recordFailedLogin(ip) {
  const record = failedLogins.get(ip) || { attempts: 0, blockedUntil: 0 };
  record.attempts += 1;
  if (record.attempts >= 5) record.blockedUntil = Date.now() + 15 * 60 * 1000;
  failedLogins.set(ip, record);
}

app.post('/api/auth/login', (req, res) => {
  const ip = req.ip;
  if (isLoginBlocked(ip)) {
    return res.status(429).json({ error: 'Слишком много попыток. Повторите позже.' });
  }

  const login = typeof req.body?.login === 'string' ? req.body.login.trim() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const user = db.prepare('SELECT id, login, password_hash AS passwordHash, role FROM users WHERE login = ?').get(login);
  const valid = user && verifyPassword(password, user.passwordHash);

  if (!valid) {
    recordFailedLogin(ip);
    return res.status(401).json({ error: 'Неверный пароль' });
  }

  failedLogins.delete(ip);
  const isHttps = req.secure || req.get('x-forwarded-proto') === 'https';
  const secureFlag = isHttps ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=${encodeURIComponent(createSession(user))}; Max-Age=${SESSION_TTL_MS / 1000}; HttpOnly; SameSite=Lax; Path=/${secureFlag}`
  );
  res.json({ ok: true, user: { id: user.id, login: user.login, role: user.role } });
});

app.get('/api/auth/session', (req, res) => {
  const user = getSession(req);
  res.json({
    authenticated: Boolean(user),
    user: user ? { id: user.id, login: user.login, role: user.role } : null
  });
});

app.post('/api/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/`);
  res.json({ ok: true });
});

app.get(['/', '/index.html'], (req, res) => {
  const page = hasValidSession(req) ? 'index.html' : 'login.html';
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', page));
});

// Остаток статических ресурсов раздаём с того же сервера, чтобы не было CORS.
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  const user = getSession(req);
  if (!user) {
    return res.status(401).json({ error: 'Требуется авторизация' });
  }
  req.user = user;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Недостаточно прав' });
    }
    next();
  };
}

const requireEditor = [requireAuth, requireRole('editor', 'admin')];
const requireAdmin = [requireAuth, requireRole('admin')];

app.get('/api/users', ...requireAdmin, (req, res) => {
  const users = db.prepare(
    'SELECT id, login, role, created_at AS createdAt FROM users ORDER BY login'
  ).all();
  res.json(users);
});

app.post('/api/users', ...requireAdmin, (req, res) => {
  const login = typeof req.body?.login === 'string' ? req.body.login.trim() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const role = req.body?.role;
  if (!/^[a-zA-Z0-9_.-]{3,50}$/.test(login) || password.length < 8 || !['reader', 'editor', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Логин: 3-50 символов; пароль: минимум 8; роль обязательна' });
  }
  try {
    const user = { id: crypto.randomUUID(), login, role };
    db.prepare(
      'INSERT INTO users (id, login, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(user.id, user.login, hashPassword(password), user.role, new Date().toISOString());
    res.status(201).json(user);
  } catch (error) {
    if (String(error.message).includes('UNIQUE')) return res.status(409).json({ error: 'Такой логин уже существует' });
    res.status(500).json({ error: 'Не удалось создать пользователя' });
  }
});

app.delete('/api/users/:id', ...requireAdmin, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Нельзя удалить текущего администратора' });
  const result = db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  if (!result.changes) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json({ ok: true });
});

const upload = multer({
  storage: multer.diskStorage({
    destination: DOCS_DIR,
    filename: (req, file, callback) => {
      callback(null, `${crypto.randomUUID()}.pdf`);
    }
  }),
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (req, file, callback) => {
    const isPdf = file.mimetype === 'application/pdf'
      || path.extname(file.originalname).toLowerCase() === '.pdf';
    callback(null, isPdf);
  }
});

app.get('/api/docs', requireAuth, (req, res) => {
  const rows = db.prepare(
    'SELECT id, title, original_name AS originalName, uploaded_at AS uploadedAt, size FROM documents ORDER BY uploaded_at DESC'
  ).all();
  res.set('Cache-Control', 'no-store');
  res.json(rows);
});

app.post('/api/docs', ...requireEditor, upload.single('document'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Выберите PDF-файл' });
  }

  const id = crypto.randomUUID();
  const title = typeof req.body.title === 'string' && req.body.title.trim()
    ? req.body.title.trim().slice(0, 200)
    : path.basename(req.file.originalname, '.pdf');
  const uploadedAt = new Date().toISOString();

  try {
    db.prepare(
      'INSERT INTO documents (id, title, original_name, file_name, uploaded_at, size) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(id, title, req.file.originalname.slice(0, 255), req.file.filename, uploadedAt, req.file.size);
  } catch (error) {
    fs.rmSync(req.file.path, { force: true });
    console.error('Ошибка сохранения документа:', error);
    return res.status(500).json({ error: 'Не удалось сохранить документ' });
  }

  res.status(201).json({ id, title, uploadedAt, size: req.file.size });
});

app.get('/api/docs/:id/download', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Документ не найден' });
  const filePath = path.join(DOCS_DIR, row.file_name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Файл документа не найден' });
  res.download(filePath, row.original_name);
});

app.delete('/api/docs/:id', ...requireEditor, (req, res) => {
  const row = db.prepare('SELECT file_name FROM documents WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Документ не найден' });
  db.prepare('DELETE FROM documents WHERE id = ?').run(req.params.id);
  fs.rmSync(path.join(DOCS_DIR, row.file_name), { force: true });
  res.json({ ok: true });
});

// Получить текущие данные базы знаний
app.get('/api/kb', requireAuth, (req, res) => {
  const row = getCurrent();
  if (!row) return res.json({ categories: [], data: [] });
  res.set('Cache-Control', 'no-store');
  res.json(JSON.parse(row.json_data));
});

// Сохранить (перезаписать) данные целиком
app.put('/api/kb', ...requireEditor, (req, res) => {
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
app.get('/api/kb/history', requireAuth, (req, res) => {
  const rows = db
    .prepare('SELECT id, saved_at FROM kb_history ORDER BY id DESC LIMIT 50')
    .all();
  res.json(rows);
});

// Восстановить конкретную версию из истории
app.post('/api/kb/history/:id/restore', ...requireEditor, (req, res) => {
  const row = db.prepare('SELECT json_data FROM kb_history WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Версия не найдена' });

  const now = new Date().toISOString();
  db.prepare('UPDATE kb_store SET json_data = ?, updated_at = ? WHERE id = 1').run(
    row.json_data,
    now
  );
  res.json({ ok: true, restoredAt: now });
});

// ===== Wiki: те же принципы, что и у /api/kb выше =====

// Получить текущие данные Wiki
app.get('/api/wiki', requireAuth, (req, res) => {
  const row = getCurrentWiki();
  if (!row) return res.json({ pages: [] });
  res.set('Cache-Control', 'no-store');
  res.json(JSON.parse(row.json_data));
});

// Сохранить (перезаписать) данные Wiki целиком
app.put('/api/wiki', ...requireEditor, (req, res) => {
  const body = req.body;
  if (!body || !Array.isArray(body.pages)) {
    return res.status(400).json({ error: 'Некорректный формат данных Wiki' });
  }

  const now = new Date().toISOString();
  const json = JSON.stringify(body);

  db.exec('BEGIN');
  try {
    db.prepare(
      `INSERT INTO wiki_store (id, json_data, updated_at) VALUES (1, ?, ?)
       ON CONFLICT(id) DO UPDATE SET json_data = excluded.json_data, updated_at = excluded.updated_at`
    ).run(json, now);

    db.prepare('INSERT INTO wiki_history (json_data, saved_at) VALUES (?, ?)').run(json, now);

    // Храним не более 50 последних версий
    db.prepare(
      `DELETE FROM wiki_history WHERE id NOT IN (
         SELECT id FROM wiki_history ORDER BY id DESC LIMIT 50
       )`
    ).run();

    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    console.error('Ошибка сохранения Wiki в базу данных:', error);
    return res.status(500).json({ error: 'Не удалось сохранить данные Wiki' });
  }

  res.json({ ok: true, updatedAt: now });
});

// Список последних версий Wiki (на случай отката)
app.get('/api/wiki/history', requireAuth, (req, res) => {
  const rows = db
    .prepare('SELECT id, saved_at FROM wiki_history ORDER BY id DESC LIMIT 50')
    .all();
  res.json(rows);
});

// Восстановить конкретную версию Wiki из истории
app.post('/api/wiki/history/:id/restore', ...requireEditor, (req, res) => {
  const row = db.prepare('SELECT json_data FROM wiki_history WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Версия не найдена' });

  const now = new Date().toISOString();
  db.prepare('UPDATE wiki_store SET json_data = ?, updated_at = ? WHERE id = 1').run(
    row.json_data,
    now
  );
  res.json({ ok: true, restoredAt: now });
});

app.listen(PORT, () => {
  console.log(`RedSMS KB сервер запущен: http://localhost:${PORT}`);
  console.log(`База данных: ${DB_PATH}`);
});
