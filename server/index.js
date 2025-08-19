import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { fileURLToPath } from 'url';

// ====================
// CONFIG
// ====================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 5174;
const DB_PATH = path.join(__dirname, 'wplace.json');
const JWT_SECRET = process.env.JWT_SECRET || 'wplace-secret';

// Progressão
const BASE_CAPACITY = 30;
const CAPACITY_PER_LEVEL = 5;
const CHUNK_SIZE = 0.01;
const XP_MULT_BASE = 1.5;
const XP_MULT_GROWTH = 0.05;

// Pontos e Loja
const COINS_PER_PIXEL = 1;
const COINS_PER_LEVEL = 10;
const SHOP_REFILL_AMOUNT = 5;
const SHOP_REFILL_COST = 5;
const SHOP_CAPACITY_STEP = 5;
const SHOP_CAPACITY_COST = 25;

// ====================
// DB HELPERS
// ====================
function loadDB() {
  try {
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    const data = JSON.parse(raw);
    data.users ||= [];
    data.progress ||= {};
    data.pixels ||= {};
    migrateDB(data);
    return data;
  } catch {
    const data = { users: [], progress: {}, pixels: {} };
    migrateDB(data);
    return data;
  }
}
function migrateDB(dbObj) {
  for (const uid of Object.keys(dbObj.progress || {})) {
    const p = dbObj.progress[uid] || {};
    dbObj.progress[uid] = {
      level: typeof p.level === 'number' ? p.level : 1,
      xp: typeof p.xp === 'number' ? p.xp : 0,
      points: typeof p.points === 'number' ? p.points : 0,
      extra_capacity: typeof p.extra_capacity === 'number' ? p.extra_capacity : 0,
    };
  }
}
function saveDB() {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
}
let db = loadDB();

function ensureProgress(userId) {
  db.progress[userId] ||= { level: 1, xp: 0, points: 0, extra_capacity: 0 };
  const p = db.progress[userId];
  if (typeof p.points !== 'number') p.points = 0;
  if (typeof p.extra_capacity !== 'number') p.extra_capacity = 0;
  return p;
}

function capacityAtLevel(lvl) { return BASE_CAPACITY + (lvl - 1) * CAPACITY_PER_LEVEL; }
function xpNeededForLevel(lvl) {
  const cap = capacityAtLevel(lvl);
  const mult = XP_MULT_BASE + (lvl - 1) * XP_MULT_GROWTH;
  return Math.ceil(cap * mult);
}
function getChunkKey(lat, lng) {
  const chunkLat = Math.floor(lat / CHUNK_SIZE);
  const chunkLng = Math.floor(lng / CHUNK_SIZE);
  return `${chunkLat},${chunkLng}`;
}
function isValidHexColor(s) { return typeof s === 'string' && /^#[0-9A-Fa-f]{6}$/.test(s); }

// ====================
// AUTH HELPERS
// ====================
function signToken(userId) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '30d' });
}
function auth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const [type, token] = hdr.split(' ');
  if (type !== 'Bearer' || !token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ====================
// APP
// ====================
const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

// Health
app.get('/health', (req, res) => res.json({ ok: true }));

// ========== PRESENÇA (SSE) ==========
const presenceClients = new Set();
function broadcastPresence() {
  const data = `data: ${JSON.stringify({ online: presenceClients.size })}\n\n`;
  for (const res of presenceClients) {
    try { res.write(data); } catch {}
  }
}
app.get('/presence', (req, res) => res.json({ online: presenceClients.size }));
app.get('/presence/stream', (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });
  res.flushHeaders?.();
  presenceClients.add(res);
  res.write(`retry: 2000\n\n`);
  res.write(`data: ${JSON.stringify({ online: presenceClients.size })}\n\n`);

  req.on('close', () => {
    presenceClients.delete(res);
    try { res.end(); } catch {}
    broadcastPresence();
  });
  const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch {} }, 15000);
  res.on('close', () => clearInterval(ping));
  broadcastPresence();
});

// ====== AUTH ======
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'missing_fields' });
  const exists = db.users.find(u => u.email.toLowerCase() === String(email).toLowerCase());
  if (exists) return res.status(409).json({ error: 'email_in_use' });
  const id = String(Date.now());
  const password_hash = await bcrypt.hash(password, 10);
  db.users.push({ id, email, password_hash });
  ensureProgress(id);
  saveDB();
  return res.json({ token: signToken(id) });
});
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'missing_fields' });
  const user = db.users.find(u => u.email.toLowerCase() === String(email).toLowerCase());
  if (!user) return res.status(401).json({ error: 'invalid_credentials' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });
  return res.json({ token: signToken(user.id) });
});
app.get('/auth/me', auth, (req, res) => {
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(401).json({ error: 'invalid_user' });
  const prog = ensureProgress(user.id);
  return res.json({
    email: user.email,
    progress: {
      level: prog.level,
      xp: prog.xp,
      points: prog.points || 0,
      extra_capacity: prog.extra_capacity || 0,
    }
  });
});

// ====== PIXELS ======
app.get('/chunk/:key', (req, res) => {
  const key = String(req.params.key);
  const pixels = db.pixels[key] || {};
  return res.json({ pixels });
});

app.post('/commit', auth, (req, res) => {
  const { pixels } = req.body || {};
  if (!Array.isArray(pixels)) return res.status(400).json({ error: 'invalid_payload' });

  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(401).json({ error: 'invalid_user' });
  const prog = ensureProgress(user.id);

  const unique = new Map(); // key -> color
  for (const p of pixels) {
    if (!p || typeof p.key !== 'string' || !isValidHexColor(p.color)) continue;
    const parts = p.key.split(',');
    if (parts.length !== 2) continue;
    const lat = Number(parts[0]);
    const lng = Number(parts[1]);
    if (!isFinite(lat) || !isFinite(lng)) continue;
    unique.set(p.key, p.color);
  }

  let count = 0;
  for (const [key, color] of unique.entries()) {
    const [lat, lng] = key.split(',').map(Number);
    const ck = getChunkKey(lat, lng);
    db.pixels[ck] ||= {};
    db.pixels[ck][key] = color;
    count++;
  }

  const prevLevel = prog.level;

  // XP e level up
  prog.xp += count;
  while (prog.xp >= xpNeededForLevel(prog.level)) {
    prog.xp -= xpNeededForLevel(prog.level);
    prog.level++;
  }

  // Pontos
  prog.points ||= 0;
  prog.points += count * COINS_PER_PIXEL;
  if (prog.level > prevLevel) {
    prog.points += (prog.level - prevLevel) * COINS_PER_LEVEL;
  }

  saveDB();
  return res.json({
    count,
    level: prog.level,
    xp: prog.xp,
    points: prog.points,
    extra_capacity: prog.extra_capacity || 0
  });
});

// ====== LOJA ======
app.post('/shop/refill', auth, (req, res) => {
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(401).json({ error: 'invalid_user' });
  const prog = ensureProgress(user.id);
  prog.points ||= 0;
  if (prog.points < SHOP_REFILL_COST) return res.status(400).json({ error: 'insufficient_points' });
  prog.points -= SHOP_REFILL_COST;
  saveDB();
  return res.json({ ok: true, points: prog.points, amount: SHOP_REFILL_AMOUNT });
});
app.post('/shop/capacity', auth, (req, res) => {
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(401).json({ error: 'invalid_user' });
  const prog = ensureProgress(user.id);
  prog.points ||= 0;
  if (prog.points < SHOP_CAPACITY_COST) return res.status(400).json({ error: 'insufficient_points' });
  prog.points -= SHOP_CAPACITY_COST;
  prog.extra_capacity = (prog.extra_capacity || 0) + SHOP_CAPACITY_STEP;
  saveDB();
  return res.json({ ok: true, points: prog.points, extra_capacity: prog.extra_capacity });
});

app.listen(PORT, () => {
  console.log(`WPlace API running on http://localhost:${PORT}`);
});