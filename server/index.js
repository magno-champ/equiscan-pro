/**
 * EquiScan Pro — Railway Backend
 * Proxy seguro para API Anthropic + persistência de calibrações + autenticação
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
const PORT = process.env.PORT || 3000;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

// ── UTILIZADORES ──────────────────────────────────────────────────────────────
// Define em Railway Variables: USERS=nome1:password1,nome2:password2
// Exemplo: USERS=pedro:cavalo123,dra_ana:equine2024
function getUsers() {
  const raw = process.env.USERS || '';
  const users = {};
  raw.split(',').forEach(pair => {
    const [name, pass] = pair.trim().split(':');
    if (name && pass) users[name.trim()] = pass.trim();
  });
  return users;
}

// Tokens de sessão em memória (reinicia com o servidor — simples e seguro)
const sessions = new Map(); // token → { user, expires }

function createToken(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { user, expires: Date.now() + 24 * 60 * 60 * 1000 }); // 24h
  return token;
}

function validateToken(token) {
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expires) { sessions.delete(token); return null; }
  return session.user;
}

// Middleware de autenticação — protege todas as rotas /api/ excepto /api/login
function requireAuth(req, res, next) {
  // Se não há utilizadores definidos, permite tudo (modo desenvolvimento)
  const users = getUsers();
  if (Object.keys(users).length === 0) return next();

  const token = req.headers['x-session-token'] || req.query.token;
  const user = validateToken(token);
  if (!user) return res.status(401).json({ error: 'Sessão inválida. Faz login.' });
  req.user = user;
  next();
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Serve ficheiros estáticos SEM autenticação (html/css/js)
app.use(express.static(path.join(__dirname, '../public')));

// Rate limiting — 60 pedidos por hora por IP
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 60,
  message: { error: 'Demasiados pedidos. Aguarda 1 hora.' }
});
app.use('/api/', limiter);

// ── LOGIN ─────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { user, password } = req.body;
  const users = getUsers();

  // Sem utilizadores configurados = modo aberto
  if (Object.keys(users).length === 0) {
    return res.json({ ok: true, token: 'dev-mode', user: 'dev' });
  }

  if (!user || !password) return res.status(400).json({ error: 'user e password obrigatórios' });
  if (users[user] !== password) return res.status(401).json({ error: 'Credenciais inválidas' });

  const token = createToken(user);
  console.log(`[EQ] Login: ${user}`);
  res.json({ ok: true, token, user });
});

// Logout
app.post('/api/logout', (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

// Verifica sessão activa
app.get('/api/me', (req, res) => {
  const users = getUsers();
  if (Object.keys(users).length === 0) return res.json({ user: 'dev', mode: 'open' });
  const token = req.headers['x-session-token'];
  const user = validateToken(token);
  if (!user) return res.status(401).json({ error: 'Não autenticado' });
  res.json({ user });
});

// ── HEALTH CHECK ──────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    version: 'v52',
    hasKey: !!ANTHROPIC_API_KEY,
    authEnabled: Object.keys(getUsers()).length > 0,
    ts: new Date().toISOString()
  });
});

// ── PROXY ANTHROPIC — ANÁLISE PRINCIPAL (STREAMING) ──────────────────────────
app.post('/api/claude', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'ANTHROPIC_API_KEY não configurada no servidor.' });
  }

  const { model, max_tokens, system, messages, stream, tools, mcp_servers } = req.body;

  try {
    const body = { model, max_tokens, system, messages };
    if (stream) body.stream = true;
    if (tools) body.tools = tools;
    if (mcp_servers) body.mcp_servers = mcp_servers;

    const headers = {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'anthropic-beta': 'prompt-caching-2024-07-31'
    };

    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers,
      body: JSON.stringify(body)
    });

    if (stream) {
      // Passa o stream directamente ao browser
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      upstream.body.pipe(res);
    } else {
      const data = await upstream.json();
      res.status(upstream.status).json(data);
    }

  } catch (err) {
    console.error('[EQ] Proxy error:', err);
    res.status(500).json({ error: 'Erro interno do servidor: ' + err.message });
  }
});

// ── CALIBRAÇÕES — PERSISTÊNCIA EM FICHEIRO JSON ───────────────────────────────
// (Em produção substituir por base de dados — Supabase, SQLite, etc.)
const CALIB_FILE = path.join(__dirname, '../data/calibrations.json');

function ensureDataDir() {
  const dir = path.dirname(CALIB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(CALIB_FILE)) fs.writeFileSync(CALIB_FILE, '{}');
}

// GET /api/calibrations — carrega todas
app.get('/api/calibrations', requireAuth, (req, res) => {
  try {
    ensureDataDir();
    const data = JSON.parse(fs.readFileSync(CALIB_FILE, 'utf8'));
    res.json(data);
  } catch (e) {
    res.json({});
  }
});

// POST /api/calibrations — guarda/actualiza uma
app.post('/api/calibrations', requireAuth, (req, res) => {
  try {
    ensureDataDir();
    const { key, value } = req.body;
    if (!key || !value) return res.status(400).json({ error: 'key e value obrigatórios' });
    const data = JSON.parse(fs.readFileSync(CALIB_FILE, 'utf8'));
    data[key] = { value, ts: Date.now(), date: new Date().toLocaleDateString('pt-PT') };
    fs.writeFileSync(CALIB_FILE, JSON.stringify(data, null, 2));
    res.json({ ok: true, key, date: data[key].date });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/calibrations/:key — remove uma
app.delete('/api/calibrations/:key', requireAuth, (req, res) => {
  try {
    ensureDataDir();
    const data = JSON.parse(fs.readFileSync(CALIB_FILE, 'utf8'));
    delete data[req.params.key];
    fs.writeFileSync(CALIB_FILE, JSON.stringify(data, null, 2));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── HISTÓRICO — PERSISTÊNCIA ──────────────────────────────────────────────────
const HISTORY_FILE = path.join(__dirname, '../data/history.json');

app.get('/api/history', requireAuth, (req, res) => {
  try {
    ensureDataDir();
    const hfile = HISTORY_FILE;
    if (!fs.existsSync(hfile)) return res.json([]);
    const data = JSON.parse(fs.readFileSync(hfile, 'utf8'));
    // Filtra por cavalo se passado como query
    const horse = req.query.horse;
    const result = horse
      ? data.filter(h => (h.horse||'').toLowerCase().includes(horse.toLowerCase()))
      : data;
    res.json(result.slice(0, 50));
  } catch (e) {
    res.json([]);
  }
});

app.post('/api/history', requireAuth, (req, res) => {
  try {
    ensureDataDir();
    let data = [];
    if (fs.existsSync(HISTORY_FILE)) {
      data = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
    }
    const entry = { ...req.body, ts: Date.now(), date: new Date().toLocaleDateString('pt-PT') };
    data.unshift(entry);
    if (data.length > 200) data = data.slice(0, 200);
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(data, null, 2));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── MODELOS DISPONÍVEIS ────────────────────────────────────────────────────────
app.get('/api/models', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key não configurada' });
  try {
    const upstream = await fetch('https://api.anthropic.com/v1/models?limit=50', {
      headers: {
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      }
    });
    const data = await upstream.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── SERVE SPA ─────────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => {
  console.log(`[EQ] EquiScan Pro v52 a correr na porta ${PORT}`);
  console.log(`[EQ] API Key: ${ANTHROPIC_API_KEY ? '✓ configurada' : '✗ FALTA definir ANTHROPIC_API_KEY'}`);
});
