/**
 * EquiScan Pro — Railway Backend v55
 * Multi-clínica: CLINICS=id:nome:pass | USERS=user:pass:clinic_id:role
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

function ensureDataDir() {
  const d = path.join(__dirname, '../data');
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

const SESSIONS_FILE = path.join(__dirname, '../data/sessions.json');
function loadSessions() {
  try {
    if (fs.existsSync(SESSIONS_FILE))
      return new Map(Object.entries(JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'))));
  } catch(e) {}
  return new Map();
}
function saveSessions(map) {
  try {
    ensureDataDir();
    const obj = {};
    map.forEach((v, k) => { obj[k] = v; });
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify(obj));
  } catch(e) {}
}
const sessions = loadSessions();

// CLINICS=id:Nome:pass,id2:Nome2:pass2
function getClinics() {
  const raw = process.env.CLINICS || '';
  const clinics = {};
  raw.split(',').forEach(part => {
    const segs = part.trim().split(':');
    const [id, nome, pass] = segs;
    if (id && id.trim()) clinics[id.trim()] = { nome: nome || id, pass: (pass||'').trim() };
  });
  if (!Object.keys(clinics).length) clinics['default'] = { nome: 'Demo', pass: '' };
  return clinics;
}

// USERS=user:pass:clinic_id:role
function getUsers() {
  const raw = process.env.USERS || '';
  const users = {};
  raw.split(',').forEach(part => {
    const segs = part.trim().split(':');
    const [user, pass, clinic_id, role] = segs;
    if (user && pass) users[user.trim()] = {
      pass: pass.trim(),
      clinic_id: (clinic_id||'default').trim(),
      role: (role||'vet').trim()
    };
  });
  return users;
}

function createToken(user, clinic_id, role) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { user, clinic_id: clinic_id||'default', role: role||'vet', expires: Date.now() + 30*24*60*60*1000 });
  saveSessions(sessions);
  return token;
}

function validateToken(token) {
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() > s.expires) { sessions.delete(token); saveSessions(sessions); return null; }
  return s;
}

function requireAuth(req, res, next) {
  const users = getUsers();
  if (!Object.keys(users).length) {
    req.user='dev'; req.clinic_id='default'; req.role='admin'; return next();
  }
  const session = validateToken(req.headers['x-session-token']);
  if (!session) return res.status(401).json({ error: 'Nao autenticado', code: 'AUTH_REQUIRED' });
  req.user=session.user; req.clinic_id=session.clinic_id; req.role=session.role;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.role)) return res.status(403).json({ error: 'Sem permissao' });
    next();
  };
}

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use('/api/claude', rateLimit({ windowMs: 60*60*1000, max: 200 }));

// Passo 1 login: validar clinica
app.post('/api/login/clinic', (req, res) => {
  const { clinic_id, password } = req.body;
  if (!clinic_id) return res.status(400).json({ error: 'clinic_id obrigatorio' });
  const users = getUsers();
  if (!Object.keys(users).length) return res.json({ ok: true, clinic_id: 'default', clinic_nome: 'Demo' });
  const clinics = getClinics();
  const clinic = clinics[clinic_id];
  if (!clinic) return res.status(401).json({ error: 'Clinica nao encontrada' });
  if (clinic.pass && clinic.pass !== (password||'')) return res.status(401).json({ error: 'Password de clinica incorrecta' });
  console.log('[EQ] Clinic step: ' + clinic_id);
  res.json({ ok: true, clinic_id, clinic_nome: clinic.nome });
});

// Passo 2 login: validar utilizador
app.post('/api/login/user', (req, res) => {
  const { clinic_id, user, password } = req.body;
  if (!clinic_id || !user || !password) return res.status(400).json({ error: 'Campos obrigatorios em falta' });
  const users = getUsers();
  if (!Object.keys(users).length) {
    const token = createToken(user, 'default', 'admin');
    return res.json({ ok: true, token, user, clinic_id: 'default', role: 'admin', clinic_nome: 'Demo' });
  }
  const u = users[user];
  if (!u) return res.status(401).json({ error: 'Utilizador nao encontrado' });
  if (u.clinic_id !== clinic_id) return res.status(401).json({ error: 'Utilizador nao pertence a esta clinica' });
  if (u.pass !== password) return res.status(401).json({ error: 'Password incorrecta' });
  const clinics = getClinics();
  const clinic = clinics[clinic_id] || { nome: clinic_id };
  const token = createToken(user, clinic_id, u.role);
  console.log('[EQ] User login: ' + user + ' @ ' + clinic_id + ' (' + u.role + ')');
  res.json({ ok: true, token, user, clinic_id, role: u.role, clinic_nome: clinic.nome });
});

// Retrocompat login
app.post('/api/login', (req, res) => {
  const { user, password } = req.body;
  const users = getUsers();
  if (!Object.keys(users).length) return res.json({ ok: true, token: 'dev-mode', user: 'dev', clinic_id: 'default', role: 'admin', clinic_nome: 'Demo' });
  if (!user || !password) return res.status(400).json({ error: 'user e password obrigatorios' });
  const u = users[user];
  if (!u || u.pass !== password) return res.status(401).json({ error: 'Credenciais invalidas' });
  const clinics = getClinics();
  const clinic = clinics[u.clinic_id] || { nome: u.clinic_id };
  const token = createToken(user, u.clinic_id, u.role);
  console.log('[EQ] Login: ' + user + ' @ ' + u.clinic_id);
  res.json({ ok: true, token, user, clinic_id: u.clinic_id, role: u.role, clinic_nome: clinic.nome });
});

app.post('/api/logout', (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) { sessions.delete(token); saveSessions(sessions); }
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const users = getUsers();
  if (!Object.keys(users).length) return res.json({ user: 'dev', clinic_id: 'default', role: 'admin', clinic_nome: 'Demo', mode: 'open' });
  const session = validateToken(req.headers['x-session-token']);
  if (!session) return res.status(401).json({ error: 'Nao autenticado' });
  const clinic = getClinics()[session.clinic_id] || { nome: session.clinic_id };
  res.json({ user: session.user, clinic_id: session.clinic_id, clinic_nome: clinic.nome, role: session.role });
});

app.get('/api/clinic/users', requireAuth, requireRole('admin'), (req, res) => {
  const users = getUsers();
  const list = Object.entries(users)
    .filter(([, u]) => u.clinic_id === req.clinic_id)
    .map(([name, u]) => ({ name, role: u.role }));
  res.json({ ok: true, users: list, clinic_id: req.clinic_id });
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, version: 55, ts: Date.now() });
});

app.post('/api/claude', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key nao configurada' });
  const { model, max_tokens, system, messages, stream } = req.body;
  console.log('[EQ] /api/claude: ' + req.user + '@' + req.clinic_id + ' stream=' + stream + ' tokens=' + max_tokens);
  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model, max_tokens, system, messages, stream })
    });
    if (stream) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('X-Accel-Buffering', 'no');
      res.setHeader('Connection', 'keep-alive');
      if (!upstream.ok) {
        const errBody = await upstream.text();
        console.error('[EQ] Anthropic error ' + upstream.status + ':', errBody.slice(0,200));
        res.write('data: ' + JSON.stringify({ type: 'error', status: upstream.status, message: errBody.slice(0,500) }) + '\n\n');
        res.end(); return;
      }
      upstream.body.pipe(res);
      upstream.body.on('end', () => res.end());
      upstream.body.on('error', (err) => { console.error('[EQ] Stream error:', err.message); res.end(); });
    } else {
      const data = await upstream.json();
      res.status(upstream.status).json(data);
    }
  } catch (err) {
    console.error('[EQ] /api/claude error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/feedback', requireAuth, (req, res) => {
  try {
    ensureDataDir();
    const fbFile = path.join(__dirname, '../data/vet_feedback.json');
    let data = [];
    if (fs.existsSync(fbFile)) data = JSON.parse(fs.readFileSync(fbFile, 'utf8'));
    const entry = {
      id: crypto.randomBytes(8).toString('hex'),
      clinic_id: req.clinic_id,
      horse: req.body.horse || 'Desconhecido',
      date: req.body.date || new Date().toLocaleDateString('pt-PT'),
      appGrade: req.body.appGrade || '',
      vetGrade: req.body.vetGrade || '',
      vetNotes: req.body.vetNotes || '',
      structures: req.body.structures || [],
      user: req.user,
      ts: Date.now()
    };
    data.unshift(entry);
    if (data.length > 500) data = data.slice(0, 500);
    fs.writeFileSync(fbFile, JSON.stringify(data, null, 2));
    res.json({ ok: true, id: entry.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/feedback', requireAuth, (req, res) => {
  try {
    const fbFile = path.join(__dirname, '../data/vet_feedback.json');
    if (!fs.existsSync(fbFile)) return res.json([]);
    const all = JSON.parse(fs.readFileSync(fbFile, 'utf8'));
    const filtered = all.filter(e => !e.clinic_id || e.clinic_id === req.clinic_id);
    res.json(filtered);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Job de agregação de conhecimento global
function runKnowledgeAggregation() {
  try {
    const fbFile = path.join(__dirname, '../data/vet_feedback.json');
    if (!fs.existsSync(fbFile)) return;
    const all = JSON.parse(fs.readFileSync(fbFile, 'utf8'));
    const patterns = {};
    all.forEach(fb => {
      if (!fb.vetGrade || fb.vetGrade === fb.appGrade) return;
      const key = ((fb.structures||[])[0]||'?') + '|' + fb.appGrade + '|' + fb.vetGrade;
      if (!patterns[key]) patterns[key] = { clinics: new Set(), count: 0 };
      patterns[key].clinics.add(fb.clinic_id || 'unknown');
      patterns[key].count++;
    });
    const global = [];
    Object.entries(patterns).forEach(([key, p]) => {
      if (p.clinics.size >= 2 && p.count >= 5) {
        const parts = key.split('|');
        global.push({ estrutura: parts[0], appGrade: parts[1], vetGrade: parts[2], n_clinicas: p.clinics.size, n_casos: p.count, ts: Date.now() });
      }
    });
    if (global.length) {
      ensureDataDir();
      fs.writeFileSync(path.join(__dirname, '../data/calib_global.json'), JSON.stringify(global, null, 2));
      console.log('[EQ] Knowledge aggregation: ' + global.length + ' padroes globais');
    }
  } catch(e) { console.error('[EQ] Aggregation error:', e.message); }
}

app.get('/api/calib/global', requireAuth, (req, res) => {
  try {
    const f = path.join(__dirname, '../data/calib_global.json');
    if (!fs.existsSync(f)) return res.json([]);
    res.json(JSON.parse(fs.readFileSync(f, 'utf8')));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

runKnowledgeAggregation();
setInterval(runKnowledgeAggregation, 24*60*60*1000);

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => {
  const clinics = getClinics();
  const users = getUsers();
  console.log('[EQ] EquiScan Pro v55 porta ' + PORT);
  console.log('[EQ] Clinicas: ' + Object.keys(clinics).length + ' | Users: ' + Object.keys(users).length);
  if (!ANTHROPIC_API_KEY) console.warn('[EQ] AVISO: ANTHROPIC_API_KEY nao configurada');
});
