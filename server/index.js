import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';

dotenv.config();

const PORT = process.env.PORT || 5174;
const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo';

// DB JSON no seu PC
const adapter = new JSONFile('wplace.json');
const db = new Low(adapter, { users: [], progress: {}, pixels: {} });
await db.read();
db.data ||= { users: [], progress: {}, pixels: {} };

// Helpers auth
function signToken(user) {
  return jwt.sign({ uid: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
}
function auth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'no_token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.uid, email: payload.email };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

// Curva de XP (igual ao front)
const BASE_CAPACITY = 30;
const CAPACITY_PER_LEVEL = 5;
function getMaxPixelsAt(lvl) { return BASE_CAPACITY + (lvl - 1) * CAPACITY_PER_LEVEL; }
function xpNeededForLevel(lvl) {
  const cap = getMaxPixelsAt(lvl);
  const mult = 1.5 + (lvl - 1) * 0.05; // sempre > capacidade
  return Math.ceil(cap * mult);
}
function snap(lat, lng) {
  const p = 20000;
  const sLat = Math.round(lat * p) / p;
  const sLng = Math.round(lng * p) / p;
  return { sLat, sLng, key: `${sLat},${sLng}` };
}
const CHUNK_SIZE = 0.01;
function chunkKeyFromLatLng(lat, lng) {
  const chunkLat = Math.floor(lat / CHUNK_SIZE);
  const chunkLng = Math.floor(lng / CHUNK_SIZE);
  return `${chunkLat},${chunkLng}`;
}

// App
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// Auth
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password || password.length < 6) return res.status(400).json({ error: 'invalid_input' });
  const emailL = String(email).toLowerCase().trim();
  if (db.data.users.find(u => u.email === emailL)) return res.status(409).json({ error: 'email_exists' });
  const hash = bcrypt.hashSync(password, 10);
  const user = { id: String(Date.now()), email: emailL, password_hash: hash };
  db.data.users.push(user);
  db.data.progress[user.id] = { level: 1, xp: 0 }; // disponível/recharge ficam no cliente
  await db.write();
  return res.json({ token: signToken(user) });
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'invalid_input' });
  const user = db.data.users.find(u => u.email === String(email).toLowerCase().trim());
  if (!user) return res.status(401).json({ error: 'invalid_credentials' });
  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });
  return res.json({ token: signToken(user) });
});

app.get('/auth/me', auth, (req, res) => {
  const prog = db.data.progress[req.user.id] || { level: 1, xp: 0 };
  return res.json({ id: req.user.id, email: req.user.email, progress: prog });
});

// Chunk (leitura)
app.get('/chunk/:key', async (req, res) => {
  const key = String(req.params.key || '');
  const pixelsByChunk = db.data.pixels[key] || {};
  return res.json({ chunkKey: key, pixels: pixelsByChunk });
});

// Commit (grava pixels + XP)
app.post('/commit', auth, async (req, res) => {
  const pixels = Array.isArray(req.body?.pixels) ? req.body.pixels : [];
  if (pixels.length === 0) return res.status(400).json({ error: 'empty' });

  let count = 0;
  for (const p of pixels) {
    let key = p.key;
    let lat, lng;
    if (key) {
      const parts = key.split(',').map(Number);
      lat = parts[0]; lng = parts[1];
    } else {
      if (!Number.isFinite(p.lat) || !Number.isFinite(p.lng)) continue;
      ({ sLat: lat, sLng: lng, key } = snap(p.lat, p.lng));
    }
    if (!/^#[0-9A-Fa-f]{6}$/.test(p.color || '')) continue;

    const ck = chunkKeyFromLatLng(lat, lng);
    db.data.pixels[ck] ||= {};
    db.data.pixels[ck][key] = p.color;
    count++;
  }

  // XP
  const prog = db.data.progress[req.user.id] || { level: 1, xp: 0 };
  let { level, xp } = prog;
  xp += count;
  while (xp >= xpNeededForLevel(level)) {
    xp -= xpNeededForLevel(level);
    level++;
  }
  db.data.progress[req.user.id] = { level, xp };
  await db.write();

  return res.json({ ok: true, count, level, xp });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`API on http://0.0.0.0:${PORT}`);
});