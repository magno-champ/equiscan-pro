/**
 * EquiScan Pro — Railway Backend v53 (sessões persistentes)
 */

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

// ── SESSÕES PERSISTENTES ───────────────────────────────────────────────────────
// Guarda sessões em ficheiro para sobreviver a reinicios do servidor
const SESSIONS_FILE = path.join(__dirname, '../data/sessions.json');

function loadSessions() {
  try {
    if (fs.existsSync(SESSIONS_FILE)) {
      return new Map(Object.entries(JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'))));
    }
  } catch(e) {}
  return new Map();
}

function saveSessions(sessions) {
  try {
    ensureDataDir();
    const obj = {};
    sessions.forEach((v, k) => { obj[k] = v; });
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify(obj));
  } catch(e) {}
}

const sessions = loadSessions();

function createToken(user) {
  const token = crypto.randomBytes(32).toString('hex');
  // 30 dias em vez de 24 horas
  sessions.set(token, { user, expires: Date.now() + 30 * 24 * 60 * 60 * 1000 });
  saveSessions(sessions);
  return token;
}

function validateToken(token) {
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expires) { sessions.delete(token); saveSessions(sessions); return null; }
  return session.user;
}

function getUsers() {
  const raw = process.env.USERS || '';
  const users = {};
  raw.split(',').forEach(pair => {
    const [name, pass] = pair.trim().split(':');
    if (name && pass) users[name.trim()] = pass.trim();
  });
  return users;
}

function requireAuth(req, res, next) {
  const users = getUsers();
  if (Object.keys(users).length === 0) return next();
  const token = req.headers['x-session-token'] || req.query.token;
  const user = validateToken(token);
  if (!user) return res.status(401).json({ error: 'Sessão inválida. Faz login.' });
  req.user = user;
  next();
}

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, '../public')));

const limiter = rateLimit({ windowMs: 60*60*1000, max: 60, validate: false });
app.use('/api/', limiter);

app.post('/api/login', (req, res) => {
  const { user, password } = req.body;
  const users = getUsers();
  if (Object.keys(users).length === 0) return res.json({ ok: true, token: 'dev-mode', user: 'dev' });
  if (!user || !password) return res.status(400).json({ error: 'user e password obrigatórios' });
  if (users[user] !== password) return res.status(401).json({ error: 'Credenciais inválidas' });
  const token = createToken(user);
  console.log(`[EQ] Login: ${user}`);
  res.json({ ok: true, token, user });
});

app.post('/api/logout', (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) { sessions.delete(token); saveSessions(sessions); }
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const users = getUsers();
  if (Object.keys(users).length === 0) return res.json({ user: 'dev', mode: 'open' });
  const token = req.headers['x-session-token'];
  const user = validateToken(token);
  if (!user) return res.status(401).json({ error: 'Não autenticado' });
  res.json({ user });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: 'v53', hasKey: !!ANTHROPIC_API_KEY });
});

// ── PROXY ANTHROPIC ────────────────────────────────────────────────────────────
app.post('/api/claude', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key não configurada' });
  const { model, max_tokens, system, messages, stream } = req.body;
  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({ model, max_tokens, system, messages, stream })
    });
    if (stream) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      upstream.body.pipe(res);
    } else {
      const data = await upstream.json();
      res.status(upstream.status).json(data);
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── FEEDBACK DO VETERINÁRIO ────────────────────────────────────────────────────
function ensureDataDir() {
  const dir = path.join(__dirname, '../data');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

app.post('/api/feedback', requireAuth, (req, res) => {
  try {
    ensureDataDir();
    const fbFile = path.join(__dirname, '../data/vet_feedback.json');
    let data = [];
    if (fs.existsSync(fbFile)) data = JSON.parse(fs.readFileSync(fbFile, 'utf8'));
    const entry = {
      id:         crypto.randomBytes(8).toString('hex'),
      horse:      req.body.horse      || 'Desconhecido',
      date:       req.body.date       || new Date().toLocaleDateString('pt-PT'),
      appGrade:   req.body.appGrade   || '',
      vetGrade:   req.body.vetGrade   || '',
      vetNotes:   req.body.vetNotes   || '',
      structures: req.body.structures || [],
      user:       req.user            || 'unknown',
      ts:         Date.now()
    };
    data.unshift(entry);
    if (data.length > 500) data = data.slice(0, 500);
    fs.writeFileSync(fbFile, JSON.stringify(data, null, 2));
    console.log(`[EQ] Feedback: ${entry.horse} — app="${entry.appGrade}" -> vet="${entry.vetGrade}"`);
    res.json({ ok: true, id: entry.id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/feedback', requireAuth, (req, res) => {
  try {
    const fbFile = path.join(__dirname, '../data/vet_feedback.json');
    if (!fs.existsSync(fbFile)) return res.json([]);
    res.json(JSON.parse(fs.readFileSync(fbFile, 'utf8')));
  } catch (e) {
    res.json([]);
  }
});

// ── SERVE SPA ─────────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => {
  console.log(`[EQ] EquiScan Pro v53 a correr na porta ${PORT}`);
  console.log(`[EQ] API Key: ${ANTHROPIC_API_KEY ? '✓ configurada' : '✗ FALTA'}`);
  console.log(`[EQ] Sessões carregadas: ${sessions.size}`);
});
