/**
 * EquiScan Pro — Railway Backend
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

function getUsers() {
  const raw = process.env.USERS || '';
  const users = {};
  raw.split(',').forEach(pair => {
    const [name, pass] = pair.trim().split(':');
    if (name && pass) users[name.trim()] = pass.trim();
  });
  return users;
}

const sessions = new Map();

function createToken(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { user, expires: Date.now() + 24 * 60 * 60 * 1000 });
  return token;
}

function validateToken(token) {
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expires) { sessions.delete(token); return null; }
  return session.user;
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
  if (token) sessions.delete(token);
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
  res.json({ status: 'ok', version: 'v52', hasKey: !!ANTHROPIC_API_KEY });
});

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

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => {
  console.log(`[EQ] EquiScan Pro v52 a correr na porta ${PORT}`);
  console.log(`[EQ] API Key: ${ANTHROPIC_API_KEY ? '✓ configurada' : '✗ FALTA'}`);
});
