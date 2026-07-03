'use strict';

// tools.gimago.cn 工具箱的统一后端
// Express + better-sqlite3，单文件 SQLite，自托管
// 一套账号通行全站：/api/auth/* 管注册登录，各 app 数据走 /api/<app>/*（当前：log）
// 认证：用户名/密码，密码 scrypt 哈希，登录发 HMAC 签名 token（无额外依赖）

require('dotenv').config();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const Database = require('better-sqlite3');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const JWT_SECRET = process.env.JWT_SECRET;
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || 'https://tools.gimago.cn';

if (!JWT_SECRET || JWT_SECRET.length < 16) {
  console.error('FATAL: 未设置足够长的 JWT_SECRET（建议 openssl rand -hex 24）。');
  process.exit(1);
}

// --- 数据库 ---
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'data.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL UNIQUE,
    password   TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS activities (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    emoji         TEXT NOT NULL DEFAULT '',
    interval_days INTEGER,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    activity_id INTEGER NOT NULL REFERENCES activities(id) ON DELETE CASCADE,
    done_at     TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_activities_user ON activities(user_id);
  CREATE INDEX IF NOT EXISTS idx_events_activity ON events(activity_id, done_at);
  CREATE TABLE IF NOT EXISTS todos (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    category   TEXT NOT NULL DEFAULT '',
    priority   INTEGER NOT NULL DEFAULT 1,
    due_at     TEXT,
    done       INTEGER NOT NULL DEFAULT 0,
    done_at    TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_todos_user ON todos(user_id, done);
`);

// 迁移：给已存在的 todos 表补周期字段；新增周期事件的「例外/完成」表
const _todoCols = db.prepare("PRAGMA table_info(todos)").all().map((c) => c.name);
if (!_todoCols.includes('recur_freq')) db.exec("ALTER TABLE todos ADD COLUMN recur_freq TEXT NOT NULL DEFAULT ''");
if (!_todoCols.includes('recur_until')) db.exec("ALTER TABLE todos ADD COLUMN recur_until TEXT");
db.exec(`
  CREATE TABLE IF NOT EXISTS todo_occurrences (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    todo_id  INTEGER NOT NULL REFERENCES todos(id) ON DELETE CASCADE,
    occ_date TEXT NOT NULL,
    done     INTEGER NOT NULL DEFAULT 0,
    done_at  TEXT,
    deleted  INTEGER NOT NULL DEFAULT 0,
    UNIQUE(todo_id, occ_date)
  );
  CREATE INDEX IF NOT EXISTS idx_occ_todo ON todo_occurrences(todo_id);
`);

// --- 密码哈希（scrypt，无原生依赖）---
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const dk = crypto.scryptSync(pw, salt, 64).toString('hex');
  return salt + ':' + dk;
}
function verifyPassword(pw, stored) {
  const [salt, dk] = String(stored).split(':');
  if (!salt || !dk) return false;
  const test = crypto.scryptSync(pw, salt, 64).toString('hex');
  const a = Buffer.from(dk, 'hex');
  const b = Buffer.from(test, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// --- 登录 token（HMAC 签名，类 JWT）---
const TOKEN_TTL = 90 * 24 * 60 * 60 * 1000; // 90 天
function signToken(uid) {
  const body = Buffer.from(JSON.stringify({ uid, exp: Date.now() + TOKEN_TTL })).toString('base64url');
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}
function verifyTokenStr(token) {
  const parts = String(token).split('.');
  if (parts.length !== 2) return null;
  const expect = crypto.createHmac('sha256', JWT_SECRET).update(parts[0]).digest('base64url');
  const a = Buffer.from(parts[1]);
  const b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    if (!p.exp || Date.now() > p.exp) return null;
    return p;
  } catch (e) { return null; }
}

// --- 应用 ---
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));

app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', ALLOW_ORIGIN);
  res.set('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.set('Vary', 'Origin');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const wrap = (fn) => (req, res) => {
  try { fn(req, res); }
  catch (err) { console.error('API 错误:', err); res.status(500).json({ error: '服务器内部错误' }); }
};

// --- 校验工具 ---
function cleanName(v) { if (typeof v !== 'string') return null; const s = v.trim(); return s.length >= 1 && s.length <= 100 ? s : null; }
function cleanEmoji(v) { if (v == null) return ''; return String(v).trim().slice(0, 16); }
function cleanInterval(v) { if (v == null || v === '') return null; const n = Number(v); return Number.isInteger(n) && n > 0 && n <= 3650 ? n : null; }
function cleanDoneAt(v) { if (v == null || v === '') return new Date().toISOString(); const t = Date.parse(v); return Number.isNaN(t) ? null : new Date(t).toISOString(); }
function cleanNote(v) { if (v == null) return ''; return String(v).trim().slice(0, 500); }
function cleanUsername(v) { if (typeof v !== 'string') return null; const s = v.trim(); return /^[\w一-龥.@-]{1,50}$/.test(s) ? s : null; }
function cleanCategory(v) { if (v == null) return ''; return String(v).trim().slice(0, 30); }
function cleanPriority(v) { if (v == null || v === '') return 1; const n = Number(v); return (n === 0 || n === 1 || n === 2) ? n : 1; }
function cleanDue(v) { if (v == null || v === '') return null; const t = Date.parse(v); return Number.isNaN(t) ? null : new Date(t).toISOString(); }
function cleanFreq(v) { const s = (v == null ? '' : String(v)).trim(); return ['weekly', 'monthly', 'yearly'].includes(s) ? s : ''; }
function cleanOccDate(v) {
  if (v == null || v === '') return null;
  const head = String(v).slice(0, 10);
  if (/^\d{4}-\d{2}-\d{2}$/.test(head)) return head;
  const t = Date.parse(v);
  if (Number.isNaN(t)) return null;
  const d = new Date(t);
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}
function dateKeyToISO(k) { const [y, m, d] = k.split('-').map(Number); return new Date(Date.UTC(y, m - 1, d, 12)).toISOString(); }
// 周期事件某一次的状态 upsert（done / deleted）
function upsertOccurrence(todoId, date, fields) {
  const ex = db.prepare('SELECT * FROM todo_occurrences WHERE todo_id = ? AND occ_date = ?').get(todoId, date);
  if (!ex) {
    db.prepare('INSERT INTO todo_occurrences (todo_id, occ_date, done, done_at, deleted) VALUES (?, ?, ?, ?, ?)')
      .run(todoId, date, fields.done ? 1 : 0, fields.done ? new Date().toISOString() : null, fields.deleted ? 1 : 0);
    return;
  }
  const done = fields.done !== undefined ? (fields.done ? 1 : 0) : ex.done;
  const done_at = fields.done !== undefined ? (fields.done ? (ex.done ? ex.done_at : new Date().toISOString()) : null) : ex.done_at;
  const deleted = fields.deleted !== undefined ? (fields.deleted ? 1 : 0) : ex.deleted;
  db.prepare('UPDATE todo_occurrences SET done = ?, done_at = ?, deleted = ? WHERE todo_id = ? AND occ_date = ?')
    .run(done, done_at, deleted, todoId, date);
}

// ============ 统一账号：/api/auth ============
app.post('/api/auth/register', wrap((req, res) => {
  const username = cleanUsername(req.body && req.body.username);
  const password = req.body && req.body.password;
  if (!username) return res.status(400).json({ error: '用户名无效（1-50 位，支持字母数字中文 . @ -）' });
  if (typeof password !== 'string' || password.length < 4) return res.status(400).json({ error: '密码至少 4 位' });
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) {
    return res.status(409).json({ error: '用户名已存在' });
  }
  const info = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hashPassword(password));
  res.status(201).json({ token: signToken(info.lastInsertRowid), username });
}));

app.post('/api/auth/login', wrap((req, res) => {
  const username = cleanUsername(req.body && req.body.username);
  const password = req.body && req.body.password;
  if (!username || typeof password !== 'string') return res.status(400).json({ error: '请填用户名和密码' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !verifyPassword(password, user.password)) return res.status(401).json({ error: '用户名或密码错误' });
  res.json({ token: signToken(user.id), username });
}));

// 当前登录态校验（前端可用来确认 token 是否仍有效）
app.get('/api/auth/me', wrap((req, res) => {
  const p = verifyTokenStr((req.get('Authorization') || '').replace(/^Bearer /, ''));
  if (!p) return res.status(401).json({ error: '未登录' });
  const u = db.prepare('SELECT username FROM users WHERE id = ?').get(p.uid);
  if (!u) return res.status(401).json({ error: '账号不存在' });
  res.json({ username: u.username });
}));

// ============ 认证中间件：保护所有 app 数据接口 ============
function requireAuth(req, res, next) {
  const p = verifyTokenStr((req.get('Authorization') || '').replace(/^Bearer /, ''));
  if (!p) return res.status(401).json({ error: '未登录或登录已过期' });
  req.uid = p.uid;
  next();
}

// ============ 做事记录：/api/log ============
app.get('/api/log/activities', requireAuth, wrap((req, res) => {
  const rows = db.prepare(`
    SELECT a.id, a.name, a.emoji, a.interval_days, a.created_at,
      (SELECT MAX(e.done_at) FROM events e WHERE e.activity_id = a.id) AS last_done,
      (SELECT COUNT(*)       FROM events e WHERE e.activity_id = a.id) AS event_count
    FROM activities a WHERE a.user_id = ? ORDER BY a.created_at DESC
  `).all(req.uid);
  res.json(rows);
}));

app.post('/api/log/activities', requireAuth, wrap((req, res) => {
  const name = cleanName(req.body && req.body.name);
  if (!name) return res.status(400).json({ error: '名称必填（1-100 字）' });
  const info = db.prepare('INSERT INTO activities (user_id, name, emoji, interval_days) VALUES (?, ?, ?, ?)')
    .run(req.uid, name, cleanEmoji(req.body.emoji), cleanInterval(req.body.interval_days));
  res.status(201).json(db.prepare('SELECT * FROM activities WHERE id = ?').get(info.lastInsertRowid));
}));

app.patch('/api/log/activities/:id', requireAuth, wrap((req, res) => {
  const id = Number(req.params.id);
  const ex = db.prepare('SELECT * FROM activities WHERE id = ? AND user_id = ?').get(id, req.uid);
  if (!ex) return res.status(404).json({ error: '活动不存在' });
  const name = req.body.name !== undefined ? cleanName(req.body.name) : ex.name;
  if (!name) return res.status(400).json({ error: '名称无效' });
  const emoji = req.body.emoji !== undefined ? cleanEmoji(req.body.emoji) : ex.emoji;
  const interval = req.body.interval_days !== undefined ? cleanInterval(req.body.interval_days) : ex.interval_days;
  db.prepare('UPDATE activities SET name = ?, emoji = ?, interval_days = ? WHERE id = ? AND user_id = ?')
    .run(name, emoji, interval, id, req.uid);
  res.json(db.prepare('SELECT * FROM activities WHERE id = ?').get(id));
}));

app.delete('/api/log/activities/:id', requireAuth, wrap((req, res) => {
  const info = db.prepare('DELETE FROM activities WHERE id = ? AND user_id = ?').run(Number(req.params.id), req.uid);
  if (info.changes === 0) return res.status(404).json({ error: '活动不存在' });
  res.json({ ok: true });
}));

app.get('/api/log/activities/:id/events', requireAuth, wrap((req, res) => {
  const rows = db.prepare(`
    SELECT e.* FROM events e JOIN activities a ON a.id = e.activity_id
    WHERE e.activity_id = ? AND a.user_id = ? ORDER BY e.done_at DESC
  `).all(Number(req.params.id), req.uid);
  res.json(rows);
}));

// 按日期区间取「全部事项」的事件，喂前端日历（带事项名/emoji，免二次查表）
app.get('/api/log/events', requireAuth, wrap((req, res) => {
  const from = cleanDoneAt(req.query.from);
  const to = cleanDoneAt(req.query.to);
  if (!from || !to) return res.status(400).json({ error: 'from/to 需为有效日期' });
  const rows = db.prepare(`
    SELECT e.id, e.activity_id, e.done_at, e.note, a.name, a.emoji
    FROM events e JOIN activities a ON a.id = e.activity_id
    WHERE a.user_id = ? AND e.done_at >= ? AND e.done_at < ?
    ORDER BY e.done_at
  `).all(req.uid, from, to);
  res.json(rows);
}));

app.post('/api/log/events', requireAuth, wrap((req, res) => {
  const activityId = Number(req.body && req.body.activity_id);
  const own = db.prepare('SELECT id FROM activities WHERE id = ? AND user_id = ?').get(activityId, req.uid);
  if (!own) return res.status(400).json({ error: 'activity_id 无效' });
  const doneAt = cleanDoneAt(req.body.done_at);
  if (!doneAt) return res.status(400).json({ error: 'done_at 不是有效时间' });
  const info = db.prepare('INSERT INTO events (activity_id, done_at, note) VALUES (?, ?, ?)')
    .run(activityId, doneAt, cleanNote(req.body.note));
  res.status(201).json(db.prepare('SELECT * FROM events WHERE id = ?').get(info.lastInsertRowid));
}));

app.delete('/api/log/events/:id', requireAuth, wrap((req, res) => {
  const info = db.prepare(
    'DELETE FROM events WHERE id = ? AND activity_id IN (SELECT id FROM activities WHERE user_id = ?)'
  ).run(Number(req.params.id), req.uid);
  if (info.changes === 0) return res.status(404).json({ error: '记录不存在' });
  res.json({ ok: true });
}));

// ============ 待办清单：/api/todo ============
app.get('/api/todo/items', requireAuth, wrap((req, res) => {
  const rows = db.prepare(`
    SELECT id, title, note, category, priority, due_at, done, done_at, recur_freq, recur_until, created_at
    FROM todos WHERE user_id = ?
    ORDER BY done ASC, priority DESC, (due_at IS NULL) ASC, due_at ASC, created_at DESC
  `).all(req.uid);
  res.json(rows);
}));

app.post('/api/todo/items', requireAuth, wrap((req, res) => {
  const title = cleanName(req.body && req.body.title);
  if (!title) return res.status(400).json({ error: '标题必填（1-100 字）' });
  const info = db.prepare(
    'INSERT INTO todos (user_id, title, note, category, priority, due_at, recur_freq, recur_until) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(req.uid, title, cleanNote(req.body.note), cleanCategory(req.body.category),
    cleanPriority(req.body.priority), cleanDue(req.body.due_at),
    cleanFreq(req.body.recur_freq), cleanDue(req.body.recur_until));
  res.status(201).json(db.prepare('SELECT * FROM todos WHERE id = ?').get(info.lastInsertRowid));
}));

app.patch('/api/todo/items/:id', requireAuth, wrap((req, res) => {
  const id = Number(req.params.id);
  const ex = db.prepare('SELECT * FROM todos WHERE id = ? AND user_id = ?').get(id, req.uid);
  if (!ex) return res.status(404).json({ error: '待办不存在' });
  const b = req.body || {};
  const title = b.title !== undefined ? cleanName(b.title) : ex.title;
  if (!title) return res.status(400).json({ error: '标题无效' });
  const note = b.note !== undefined ? cleanNote(b.note) : ex.note;
  const category = b.category !== undefined ? cleanCategory(b.category) : ex.category;
  const priority = b.priority !== undefined ? cleanPriority(b.priority) : ex.priority;
  const due_at = b.due_at !== undefined ? cleanDue(b.due_at) : ex.due_at;
  const recur_freq = b.recur_freq !== undefined ? cleanFreq(b.recur_freq) : ex.recur_freq;
  const recur_until = b.recur_until !== undefined ? cleanDue(b.recur_until) : ex.recur_until;
  let done = ex.done, done_at = ex.done_at;
  if (b.done !== undefined) {
    done = b.done ? 1 : 0;
    done_at = done ? (ex.done ? ex.done_at : new Date().toISOString()) : null;
  }
  db.prepare(`UPDATE todos SET title = ?, note = ?, category = ?, priority = ?, due_at = ?, recur_freq = ?, recur_until = ?, done = ?, done_at = ?
    WHERE id = ? AND user_id = ?`).run(title, note, category, priority, due_at, recur_freq, recur_until, done, done_at, id, req.uid);
  res.json(db.prepare('SELECT * FROM todos WHERE id = ?').get(id));
}));

// 周期事件全部「例外/完成」记录（前端按 todo_id+occ_date 建映射）
app.get('/api/todo/occurrences', requireAuth, wrap((req, res) => {
  const rows = db.prepare(`
    SELECT o.todo_id, o.occ_date, o.done, o.done_at, o.deleted
    FROM todo_occurrences o JOIN todos t ON t.id = o.todo_id
    WHERE t.user_id = ?
  `).all(req.uid);
  res.json(rows);
}));

// 标记周期事件某一次：完成/取消完成，或仅删这一次（deleted）
app.put('/api/todo/items/:id/occurrence', requireAuth, wrap((req, res) => {
  const id = Number(req.params.id);
  const own = db.prepare('SELECT id FROM todos WHERE id = ? AND user_id = ?').get(id, req.uid);
  if (!own) return res.status(404).json({ error: '待办不存在' });
  const date = cleanOccDate(req.body && req.body.occ_date);
  if (!date) return res.status(400).json({ error: 'occ_date 无效' });
  const fields = {};
  if (req.body.done !== undefined) fields.done = !!req.body.done;
  if (req.body.deleted !== undefined) fields.deleted = !!req.body.deleted;
  upsertOccurrence(id, date, fields);
  res.json({ ok: true });
}));

// 删除：mode=all（默认，删事项及其所有次）/ occurrence（仅删该次，需 date）/ completed（删事项但把已完成的各次转为独立记录保留）
app.delete('/api/todo/items/:id', requireAuth, wrap((req, res) => {
  const id = Number(req.params.id);
  const t = db.prepare('SELECT * FROM todos WHERE id = ? AND user_id = ?').get(id, req.uid);
  if (!t) return res.status(404).json({ error: '待办不存在' });
  const mode = req.query.mode || 'all';

  if (mode === 'occurrence') {
    const date = cleanOccDate(req.query.date);
    if (!date) return res.status(400).json({ error: 'date 无效' });
    upsertOccurrence(id, date, { deleted: true });
    return res.json({ ok: true, mode });
  }

  if (mode === 'completed' && t.recur_freq) {
    const tx = db.transaction(() => {
      const comps = db.prepare('SELECT occ_date, done_at FROM todo_occurrences WHERE todo_id = ? AND done = 1 AND deleted = 0').all(id);
      const ins = db.prepare('INSERT INTO todos (user_id, title, note, category, priority, due_at, done, done_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)');
      for (const c of comps) ins.run(req.uid, t.title, t.note, t.category, t.priority, dateKeyToISO(c.occ_date), c.done_at || dateKeyToISO(c.occ_date));
      db.prepare('DELETE FROM todos WHERE id = ? AND user_id = ?').run(id, req.uid);
    });
    tx();
    return res.json({ ok: true, mode });
  }

  db.prepare('DELETE FROM todos WHERE id = ? AND user_id = ?').run(id, req.uid);
  res.json({ ok: true, mode: 'all' });
}));

// 健康检查（无需登录）
app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, HOST, () => {
  console.log(`gimago 工具箱后端已启动: http://${HOST}:${PORT}  (CORS 允许: ${ALLOW_ORIGIN})`);
});
