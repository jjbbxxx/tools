'use strict';

// 做事记录页面的轻量后端
// Express + better-sqlite3，单文件 SQLite，自托管，替代 Supabase
// 认证：单用户共享密钥（Authorization: Bearer <APP_TOKEN>）

require('dotenv').config();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const Database = require('better-sqlite3');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const APP_TOKEN = process.env.APP_TOKEN;
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || 'https://tools.gimago.cn';

if (!APP_TOKEN || APP_TOKEN.length < 16) {
  console.error('FATAL: 未设置足够长的 APP_TOKEN。请在 .env 里配置（建议 openssl rand -hex 24）。');
  process.exit(1);
}

// --- 数据库 ---
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'events.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS activities (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
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
  CREATE INDEX IF NOT EXISTS idx_events_activity ON events(activity_id, done_at);
`);

// --- 应用 ---
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));

// CORS：只允许配置的来源
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', ALLOW_ORIGIN);
  res.set('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.set('Vary', 'Origin');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// 认证：恒定时间比较，避免泄露 token
function tokenValid(provided) {
  const a = Buffer.from(String(provided));
  const b = Buffer.from(APP_TOKEN);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
app.use('/api', (req, res, next) => {
  const header = req.get('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!tokenValid(token)) return res.status(401).json({ error: '未授权' });
  next();
});

// --- 校验工具 ---
function cleanName(v) {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  return s.length >= 1 && s.length <= 100 ? s : null;
}
function cleanEmoji(v) {
  if (v == null) return '';
  const s = String(v).trim();
  return s.length <= 16 ? s : s.slice(0, 16);
}
function cleanInterval(v) {
  if (v == null || v === '') return null;
  const n = Number(v);
  return Number.isInteger(n) && n > 0 && n <= 3650 ? n : null;
}
function cleanDoneAt(v) {
  if (v == null || v === '') return new Date().toISOString();
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}
function cleanNote(v) {
  if (v == null) return '';
  const s = String(v).trim();
  return s.length <= 500 ? s : s.slice(0, 500);
}

// 包一层 try/catch，统一错误处理
const wrap = (fn) => (req, res) => {
  try { fn(req, res); }
  catch (err) {
    console.error('API 错误:', err);
    res.status(500).json({ error: '服务器内部错误' });
  }
};

// --- 路由：activities ---
app.get('/api/activities', wrap((req, res) => {
  const rows = db.prepare(`
    SELECT a.id, a.name, a.emoji, a.interval_days, a.created_at,
           (SELECT MAX(e.done_at) FROM events e WHERE e.activity_id = a.id) AS last_done,
           (SELECT COUNT(*)       FROM events e WHERE e.activity_id = a.id) AS event_count
    FROM activities a
    ORDER BY a.created_at DESC
  `).all();
  res.json(rows);
}));

app.post('/api/activities', wrap((req, res) => {
  const name = cleanName(req.body && req.body.name);
  if (!name) return res.status(400).json({ error: '名称必填（1-100 字）' });
  const emoji = cleanEmoji(req.body.emoji);
  const interval = cleanInterval(req.body.interval_days);
  const info = db.prepare(
    'INSERT INTO activities (name, emoji, interval_days) VALUES (?, ?, ?)'
  ).run(name, emoji, interval);
  const row = db.prepare('SELECT * FROM activities WHERE id = ?').get(info.lastInsertRowid);
  res.status(201).json(row);
}));

app.patch('/api/activities/:id', wrap((req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare('SELECT * FROM activities WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: '活动不存在' });
  const name = req.body.name !== undefined ? cleanName(req.body.name) : existing.name;
  if (!name) return res.status(400).json({ error: '名称无效' });
  const emoji = req.body.emoji !== undefined ? cleanEmoji(req.body.emoji) : existing.emoji;
  const interval = req.body.interval_days !== undefined
    ? cleanInterval(req.body.interval_days) : existing.interval_days;
  db.prepare('UPDATE activities SET name = ?, emoji = ?, interval_days = ? WHERE id = ?')
    .run(name, emoji, interval, id);
  res.json(db.prepare('SELECT * FROM activities WHERE id = ?').get(id));
}));

app.delete('/api/activities/:id', wrap((req, res) => {
  const id = Number(req.params.id);
  const info = db.prepare('DELETE FROM activities WHERE id = ?').run(id);
  if (info.changes === 0) return res.status(404).json({ error: '活动不存在' });
  res.json({ ok: true });
}));

// --- 路由：events ---
app.get('/api/activities/:id/events', wrap((req, res) => {
  const id = Number(req.params.id);
  const rows = db.prepare(
    'SELECT * FROM events WHERE activity_id = ? ORDER BY done_at DESC'
  ).all(id);
  res.json(rows);
}));

app.post('/api/events', wrap((req, res) => {
  const activityId = Number(req.body && req.body.activity_id);
  const activity = db.prepare('SELECT id FROM activities WHERE id = ?').get(activityId);
  if (!activity) return res.status(400).json({ error: 'activity_id 无效' });
  const doneAt = cleanDoneAt(req.body.done_at);
  if (!doneAt) return res.status(400).json({ error: 'done_at 不是有效时间' });
  const note = cleanNote(req.body.note);
  const info = db.prepare(
    'INSERT INTO events (activity_id, done_at, note) VALUES (?, ?, ?)'
  ).run(activityId, doneAt, note);
  res.status(201).json(db.prepare('SELECT * FROM events WHERE id = ?').get(info.lastInsertRowid));
}));

app.delete('/api/events/:id', wrap((req, res) => {
  const id = Number(req.params.id);
  const info = db.prepare('DELETE FROM events WHERE id = ?').run(id);
  if (info.changes === 0) return res.status(404).json({ error: '记录不存在' });
  res.json({ ok: true });
}));

// 健康检查（无需认证，方便探活）
app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, HOST, () => {
  console.log(`做事记录后端已启动: http://${HOST}:${PORT}  (CORS 允许: ${ALLOW_ORIGIN})`);
});
