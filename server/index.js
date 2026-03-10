/**
 * EquiScan Pro — Railway Backend v57
 * Novidades v57:
 *   - Registo de utilizadores via Supabase Auth
 *   - Endpoints /api/sync/* para dados user (cavalos, exames, calibs, intel)
 *   - Stripe: planos free/pro/clinic, webhooks, portal
 *   - Rate limiting por plano (free: 10 análises/dia, pro: 100, clinic: ilimitado)
 *   - PWA: serve manifest.json, sw.js, icons
 */

const express    = require('express');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const fetch      = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);

const PORT               = process.env.PORT || 3000;
const ANTHROPIC_API_KEY  = process.env.ANTHROPIC_API_KEY;
const SUPABASE_URL        = process.env.SUPABASE_URL        || 'https://egwvssdakicnfsukgmsz.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY; // service role key (só no servidor)
const STRIPE_SECRET_KEY  = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const APP_URL            = process.env.APP_URL || 'https://equiscan-pro-production.up.railway.app';

const UPSTREAM_TIMEOUT_MS = 240_000;

// ── PLANOS ────────────────────────────────────────────────────────────────────
const PLANS = {
  free:   { name: 'Free',       analyses_per_day: 5,   price_id: null },
  pro:    { name: 'Pro',        analyses_per_day: 100,  price_id: process.env.STRIPE_PRICE_PRO },
  clinic: { name: 'Clínica',   analyses_per_day: 9999, price_id: process.env.STRIPE_PRICE_CLINIC }
};

// ── ENV PARSE CACHE (sistema legado — mantido para compatibilidade) ────────────
let _clinicsCache = null;
let _usersCache   = null;

function getClinics() {
  if (_clinicsCache) return _clinicsCache;
  const raw = process.env.CLINICS || '';
  const clinics = {};
  raw.split(',').forEach(part => {
    const [id, nome, pass] = part.trim().split(':');
    if (id && id.trim()) clinics[id.trim()] = { nome: nome || id, pass: (pass || '').trim() };
  });
  if (!Object.keys(clinics).length) clinics['default'] = { nome: 'Demo', pass: '' };
  _clinicsCache = clinics;
  return clinics;
}

function getUsers() {
  if (_usersCache) return _usersCache;
  const raw = process.env.USERS || '';
  const users = {};
  raw.split(',').forEach(part => {
    const [user, pass, clinic_id, role] = part.trim().split(':');
    if (user && pass) users[user.trim()] = {
      pass:      pass.trim(),
      clinic_id: (clinic_id || 'default').trim(),
      role:      (role || 'vet').trim()
    };
  });
  _usersCache = users;
  return users;
}

// ── SESSION STORE ─────────────────────────────────────────────────────────────
const SESSIONS_FILE  = path.join(__dirname, '../data/sessions.json');
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
let   _sessionsDirty = false;

function ensureDataDir() {
  const d = path.join(__dirname, '../data');
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

function loadSessions() {
  try {
    if (fs.existsSync(SESSIONS_FILE))
      return new Map(Object.entries(JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'))));
  } catch (e) {}
  return new Map();
}

function markSessionsDirty() { _sessionsDirty = true; }

setInterval(() => {
  if (!_sessionsDirty) return;
  _sessionsDirty = false;
  try {
    ensureDataDir();
    const obj = {};
    sessions.forEach((v, k) => { obj[k] = v; });
    fs.writeFile(SESSIONS_FILE, JSON.stringify(obj), err => {
      if (err) console.error('[EQ] sessions save error:', err.message);
    });
  } catch (e) { console.error('[EQ] sessions save error:', e.message); }
}, 10_000);

const sessions = loadSessions();

function createToken(user, clinic_id, role, plan, user_id) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, {
    user,
    clinic_id: clinic_id || 'default',
    role:      role || 'vet',
    plan:      plan || 'free',
    user_id:   user_id || null,
    expires:   Date.now() + SESSION_TTL_MS
  });
  markSessionsDirty();
  return token;
}

function validateToken(token) {
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() > s.expires) {
    sessions.delete(token);
    markSessionsDirty();
    return null;
  }
  return s;
}

function requireAuth(req, res, next) {
  const users = getUsers();
  if (!Object.keys(users).length && !SUPABASE_SERVICE_KEY) {
    req.user = 'dev'; req.clinic_id = 'default'; req.role = 'admin'; req.plan = 'clinic'; req.user_id = 'dev';
    return next();
  }
  const session = validateToken(req.headers['x-session-token']);
  if (!session) return res.status(401).json({ error: 'Não autenticado', code: 'AUTH_REQUIRED' });
  req.user      = session.user;
  req.clinic_id = session.clinic_id;
  req.role      = session.role;
  req.plan      = session.plan || 'free';
  req.user_id   = session.user_id;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.role)) return res.status(403).json({ error: 'Sem permissão' });
    next();
  };
}

// ── ANÁLISES POR DIA — rate limit por plano ───────────────────────────────────
const _dailyUsage = new Map(); // userId → { date, count }

function checkDailyLimit(userId, plan) {
  const limit = (PLANS[plan] || PLANS.free).analyses_per_day;
  if (limit >= 9999) return { ok: true, remaining: 9999, limit };
  const today = new Date().toISOString().slice(0, 10);
  const entry = _dailyUsage.get(userId) || { date: today, count: 0 };
  if (entry.date !== today) { entry.date = today; entry.count = 0; }
  if (entry.count >= limit) return { ok: false, remaining: 0, limit };
  return { ok: true, remaining: limit - entry.count, limit };
}

function incrementUsage(userId) {
  const today = new Date().toISOString().slice(0, 10);
  const entry = _dailyUsage.get(userId) || { date: today, count: 0 };
  if (entry.date !== today) { entry.date = today; entry.count = 0; }
  entry.count++;
  _dailyUsage.set(userId, entry);
}

// ── SUPABASE ADMIN HELPERS ────────────────────────────────────────────────────
async function sbAdmin(method, path, body) {
  if (!SUPABASE_SERVICE_KEY) throw new Error('SUPABASE_SERVICE_KEY não configurada');
  const res = await fetch(`${SUPABASE_URL}${path}`, {
    method,
    headers: {
      'Content-Type':  'application/json',
      'apikey':        SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Prefer':        method === 'POST' ? 'return=representation' : ''
    },
    body: body ? JSON.stringify(body) : undefined
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Supabase ${method} ${path} ${res.status}: ${err.slice(0, 200)}`);
  }
  const text = await res.text();
  try { return text ? JSON.parse(text) : null; } catch(e) { return null; }
}

// ── STRIPE ────────────────────────────────────────────────────────────────────
let stripe = null;
if (STRIPE_SECRET_KEY) {
  try { stripe = require('stripe')(STRIPE_SECRET_KEY); }
  catch(e) { console.warn('[EQ] Stripe não disponível:', e.message); }
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors({ origin: '*' }));

// Stripe webhooks precisam de body raw
app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '50mb' }));

// Rate limit global
app.use('/api/claude', rateLimit({ windowMs: 60 * 60 * 1000, max: 200 }));

// ── AUTH LEGADO (compatibilidade) ─────────────────────────────────────────────
app.post('/api/login/clinic', (req, res) => {
  const { clinic_id, password } = req.body;
  if (!clinic_id) return res.status(400).json({ error: 'clinic_id obrigatório' });
  const users = getUsers();
  if (!Object.keys(users).length) return res.json({ ok: true, clinic_id: 'default', clinic_nome: 'Demo' });
  const clinics = getClinics();
  const clinic  = clinics[clinic_id];
  if (!clinic) return res.status(401).json({ error: 'Clínica não encontrada' });
  if (clinic.pass && clinic.pass !== (password || '')) return res.status(401).json({ error: 'Password de clínica incorrecta' });
  res.json({ ok: true, clinic_id, clinic_nome: clinic.nome });
});

app.post('/api/login/user', (req, res) => {
  const { clinic_id, user, password } = req.body;
  if (!clinic_id || !user || !password) return res.status(400).json({ error: 'Campos obrigatórios em falta' });
  const users = getUsers();
  if (!Object.keys(users).length) {
    const token = createToken(user, 'default', 'admin', 'clinic', user);
    return res.json({ ok: true, token, user, clinic_id: 'default', role: 'admin', clinic_nome: 'Demo', plan: 'clinic' });
  }
  const u = users[user];
  if (!u) return res.status(401).json({ error: 'Utilizador não encontrado' });
  if (u.clinic_id !== clinic_id) return res.status(401).json({ error: 'Utilizador não pertence a esta clínica' });
  if (u.pass !== password) return res.status(401).json({ error: 'Password incorrecta' });
  const clinics = getClinics();
  const clinic  = clinics[clinic_id] || { nome: clinic_id };
  const token   = createToken(user, clinic_id, u.role, u.plan || 'pro', user);
  console.log('[EQ] Login:', user, '@', clinic_id, u.role);
  res.json({ ok: true, token, user, clinic_id, role: u.role, clinic_nome: clinic.nome, plan: u.plan || 'pro' });
});

app.post('/api/login', (req, res) => {
  const { user, password } = req.body;
  const users = getUsers();
  if (!Object.keys(users).length)
    return res.json({ ok: true, token: 'dev-mode', user: 'dev', clinic_id: 'default', role: 'admin', clinic_nome: 'Demo', plan: 'clinic' });
  if (!user || !password) return res.status(400).json({ error: 'user e password obrigatórios' });
  const u = users[user];
  if (!u || u.pass !== password) return res.status(401).json({ error: 'Credenciais inválidas' });
  const clinics = getClinics();
  const clinic  = clinics[u.clinic_id] || { nome: u.clinic_id };
  const token   = createToken(user, u.clinic_id, u.role, u.plan || 'pro', user);
  res.json({ ok: true, token, user, clinic_id: u.clinic_id, role: u.role, clinic_nome: clinic.nome, plan: u.plan || 'pro' });
});

// ── AUTH NOVO — Supabase Auth ─────────────────────────────────────────────────

// Registo por email
app.post('/api/register', async (req, res) => {
  const { email, password, nome, clinica } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email e password obrigatórios' });
  if (!SUPABASE_SERVICE_KEY) return res.status(503).json({ error: 'Registo não disponível neste modo' });

  try {
    // 1. Criar utilizador no Supabase Auth
    const authRes = await sbAdmin('POST', '/auth/v1/admin/users', {
      email,
      password,
      email_confirm: true, // confirmar automaticamente para simplificar onboarding
      user_metadata: { nome: nome || email.split('@')[0], clinica: clinica || '' }
    });

    if (!authRes || !authRes.id) throw new Error('Falha ao criar utilizador');

    // 2. Criar perfil na tabela profiles
    try {
      await sbAdmin('POST', '/rest/v1/profiles', {
        id:        authRes.id,
        email,
        nome:      nome || email.split('@')[0],
        clinica:   clinica || '',
        plan:      'free',
        analyses_used: 0,
        created_at: new Date().toISOString()
      });
    } catch(e) { console.warn('[EQ] Profile create warning:', e.message); }

    // 3. Criar token de sessão
    const token = createToken(email, clinica || 'default', 'vet', 'free', authRes.id);
    console.log('[EQ] Register:', email);
    res.json({ ok: true, token, user: email, clinic_id: clinica || 'default', role: 'vet', plan: 'free', clinic_nome: clinica || 'EquiScan' });
  } catch(e) {
    console.error('[EQ] Register error:', e.message);
    if (e.message.includes('already')) return res.status(409).json({ error: 'Email já registado' });
    res.status(500).json({ error: e.message });
  }
});

// Login por email (Supabase Auth)
app.post('/api/login/email', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email e password obrigatórios' });
  if (!SUPABASE_SERVICE_KEY) return res.status(503).json({ error: 'Login por email não disponível' });

  try {
    // Verificar credenciais via Supabase Auth
    const authRes = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey':       SUPABASE_SERVICE_KEY
      },
      body: JSON.stringify({ email, password })
    });

    if (!authRes.ok) {
      const err = await authRes.json();
      return res.status(401).json({ error: err.error_description || 'Credenciais inválidas' });
    }

    const authData = await authRes.json();
    const userId   = authData.user?.id;

    // Buscar perfil
    let profile = null;
    try {
      const profiles = await sbAdmin('GET', `/rest/v1/profiles?id=eq.${userId}&select=*`);
      profile = Array.isArray(profiles) ? profiles[0] : null;
    } catch(e) {}

    const plan     = profile?.plan || 'free';
    const clinica  = profile?.clinica || 'default';
    const nome     = profile?.nome || email.split('@')[0];
    const token    = createToken(email, clinica, 'vet', plan, userId);

    console.log('[EQ] Email login:', email, 'plan:', plan);
    res.json({
      ok: true, token, user: email, user_id: userId,
      clinic_id: clinica, clinic_nome: clinica, role: 'vet', plan, nome
    });
  } catch(e) {
    console.error('[EQ] Email login error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Reset password
app.post('/api/reset-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'email obrigatório' });
  if (!SUPABASE_SERVICE_KEY) return res.status(503).json({ error: 'Reset não disponível' });

  try {
    await fetch(`${SUPABASE_URL}/auth/v1/recover`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'apikey': SUPABASE_SERVICE_KEY },
      body:    JSON.stringify({ email, redirect_to: `${APP_URL}/reset` })
    });
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/logout', (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) { sessions.delete(token); markSessionsDirty(); }
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const users = getUsers();
  if (!Object.keys(users).length && !SUPABASE_SERVICE_KEY)
    return res.json({ user: 'dev', clinic_id: 'default', role: 'admin', clinic_nome: 'Demo', plan: 'clinic', mode: 'open' });
  const session = validateToken(req.headers['x-session-token']);
  if (!session) return res.status(401).json({ error: 'Não autenticado' });
  const clinic = getClinics()[session.clinic_id] || { nome: session.clinic_id };
  res.json({
    user:       session.user,
    clinic_id:  session.clinic_id,
    clinic_nome: clinic.nome,
    role:       session.role,
    plan:       session.plan || 'free',
    user_id:    session.user_id
  });
});

app.get('/api/clinic/users', requireAuth, requireRole('admin'), (req, res) => {
  const users = getUsers();
  const list  = Object.entries(users)
    .filter(([, u]) => u.clinic_id === req.clinic_id)
    .map(([name, u]) => ({ name, role: u.role }));
  res.json({ ok: true, users: list, clinic_id: req.clinic_id });
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, version: 57, ts: Date.now(), sessions: sessions.size, stripe: !!stripe, supabase: !!SUPABASE_SERVICE_KEY });
});

// ── CLAUDE PROXY ──────────────────────────────────────────────────────────────
app.post('/api/claude', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key não configurada' });

  // Rate limit por plano
  const userId = req.user_id || req.user;
  const usage  = checkDailyLimit(userId, req.plan);
  if (!usage.ok) {
    return res.status(429).json({
      error: `Limite diário atingido (${usage.limit} análises/dia no plano ${req.plan}). Faz upgrade para continuar.`,
      code:  'DAILY_LIMIT',
      plan:  req.plan,
      limit: usage.limit,
      upgrade_url: `${APP_URL}?upgrade=1`
    });
  }

  const { model, max_tokens, system, messages, stream } = req.body;
  console.log('[EQ] /api/claude:', req.user, 'plan:', req.plan, 'remaining:', usage.remaining, 'stream:', stream);

  const controller = new AbortController();
  const timeoutId  = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method:  'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'Connection':        'keep-alive'
      },
      body:    JSON.stringify({ model, max_tokens, system, messages, stream }),
      signal:  controller.signal
    });

    clearTimeout(timeoutId);

    if (stream) {
      res.setHeader('Content-Type',      'text/event-stream');
      res.setHeader('Cache-Control',     'no-cache');
      res.setHeader('X-Accel-Buffering', 'no');
      res.setHeader('Connection',        'keep-alive');
      // Incluir info de uso nos headers
      res.setHeader('X-Plan',            req.plan);
      res.setHeader('X-Remaining',       String(usage.remaining - 1));
      if (!upstream.ok) {
        const errBody = await upstream.text();
        res.write('data: ' + JSON.stringify({ type: 'error', status: upstream.status, message: errBody.slice(0, 500) }) + '\n\n');
        res.end();
        return;
      }
      incrementUsage(userId);
      upstream.body.pipe(res);
      upstream.body.on('end',   ()    => res.end());
      upstream.body.on('error', (err) => { console.error('[EQ] Stream error:', err.message); res.end(); });
      req.on('close', () => upstream.body.destroy());
    } else {
      const data = await upstream.json();
      if (upstream.ok) incrementUsage(userId);
      res.status(upstream.status).json({ ...data, _plan: req.plan, _remaining: usage.remaining - 1 });
    }
  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === 'AbortError') return res.status(504).json({ error: 'Timeout — tenta com menos imagens' });
    console.error('[EQ] /api/claude error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── SYNC ENDPOINTS — dados do utilizador ─────────────────────────────────────
// O cliente chama estes endpoints para sincronizar dados locais com a cloud
// Todos usam Supabase como backend através do service key (seguro)

// Cavalos
app.get('/api/sync/horses', requireAuth, async (req, res) => {
  if (!SUPABASE_SERVICE_KEY) return res.json({ data: [], source: 'unavailable' });
  try {
    const rows = await sbAdmin('GET', `/rest/v1/cavalos?clinic_id=eq.${encodeURIComponent(req.clinic_id)}&order=nome.asc&select=*`);
    res.json({ data: rows || [], source: 'supabase' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sync/horses', requireAuth, async (req, res) => {
  if (!SUPABASE_SERVICE_KEY) return res.json({ ok: true, source: 'unavailable' });
  const { horses } = req.body;
  if (!Array.isArray(horses)) return res.status(400).json({ error: 'horses deve ser array' });
  try {
    // Upsert em batch
    const rows = horses.map(h => ({
      client_id:  h.id,
      clinic_id:  req.clinic_id,
      nome:       h.nome || '',
      raca:       h.raca || '',
      idade:      parseInt(h.idade) || null,
      sexo:       h.sexo || '',
      disciplina: h.disciplina || '',
      owner:      h.owner || '',
      notas:      h.notas || '',
      updated_at: new Date().toISOString()
    }));
    if (rows.length) {
      await sbAdmin('POST', '/rest/v1/cavalos?on_conflict=client_id', rows);
    }
    res.json({ ok: true, synced: rows.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Exames
app.get('/api/sync/exams', requireAuth, async (req, res) => {
  if (!SUPABASE_SERVICE_KEY) return res.json({ data: [], source: 'unavailable' });
  const { horse_id } = req.query;
  try {
    const filter = horse_id
      ? `/rest/v1/exames?clinic_id=eq.${encodeURIComponent(req.clinic_id)}&horse_id=eq.${encodeURIComponent(horse_id)}&order=date.desc&select=*`
      : `/rest/v1/exames?clinic_id=eq.${encodeURIComponent(req.clinic_id)}&order=date.desc&limit=100&select=*`;
    const rows = await sbAdmin('GET', filter);
    res.json({ data: rows || [], source: 'supabase' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sync/exams', requireAuth, async (req, res) => {
  if (!SUPABASE_SERVICE_KEY) return res.json({ ok: true, source: 'unavailable' });
  const { exam } = req.body;
  if (!exam) return res.status(400).json({ error: 'exam obrigatório' });
  try {
    const row = {
      client_id:    exam.id,
      clinic_id:    req.clinic_id,
      horse_id:     exam.horse_id || '',
      date:         exam.date || new Date().toISOString().slice(0, 10),
      score:        exam.score || 0,
      classe:       exam.classe || '',
      n_achados:    exam.achados || 0,
      achados_json: JSON.stringify(exam.achados_detalhe || []),
      result_json:  exam.result_json ? JSON.stringify(exam.result_json) : null,
      notas_vet:    exam.notas_vet || '',
      ref:          exam.ref || '',
      user_id:      req.user_id || req.user,
      updated_at:   new Date().toISOString()
    };
    await sbAdmin('POST', '/rest/v1/exames?on_conflict=client_id', row);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Calibrações
app.get('/api/sync/calibs', requireAuth, async (req, res) => {
  if (!SUPABASE_SERVICE_KEY) return res.json({ data: [], source: 'unavailable' });
  try {
    const rows = await sbAdmin('GET', `/rest/v1/calib_rules?status=eq.active&clinic_id=eq.${encodeURIComponent(req.clinic_id)}&order=created_at.asc&select=*`);
    res.json({ data: rows || [] });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sync/calibs', requireAuth, async (req, res) => {
  if (!SUPABASE_SERVICE_KEY) return res.json({ ok: true, source: 'unavailable' });
  const { rule } = req.body;
  if (!rule) return res.status(400).json({ error: 'rule obrigatório' });
  try {
    await sbAdmin('POST', '/rest/v1/calib_rules', {
      ...rule,
      clinic_id:  req.clinic_id,
      user_id:    req.user_id || req.user,
      created_at: rule.created_at || new Date().toISOString()
    });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Intel memory
app.get('/api/sync/intel', requireAuth, async (req, res) => {
  if (!SUPABASE_SERVICE_KEY) return res.json({ data: null });
  try {
    const rows = await sbAdmin('GET', `/rest/v1/intel_memory?clinic_id=eq.${encodeURIComponent(req.clinic_id)}&select=*`);
    res.json({ data: rows?.[0] || null });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sync/intel', requireAuth, async (req, res) => {
  if (!SUPABASE_SERVICE_KEY) return res.json({ ok: true });
  const { memory } = req.body;
  try {
    await sbAdmin('POST', '/rest/v1/intel_memory?on_conflict=clinic_id', {
      clinic_id:  req.clinic_id,
      user_id:    req.user_id || req.user,
      memory_json: JSON.stringify(memory),
      updated_at: new Date().toISOString()
    });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Uso diário (para mostrar no client)
app.get('/api/usage', requireAuth, (req, res) => {
  const userId = req.user_id || req.user;
  const usage  = checkDailyLimit(userId, req.plan);
  const plan   = PLANS[req.plan] || PLANS.free;
  res.json({
    plan:      req.plan,
    plan_name: plan.name,
    used:      plan.analyses_per_day - usage.remaining,
    limit:     plan.analyses_per_day,
    remaining: usage.remaining
  });
});

// ── FEEDBACK ──────────────────────────────────────────────────────────────────
const fbFile = path.join(__dirname, '../data/vet_feedback.json');
let _fbCache = null;

function loadFeedback() {
  if (_fbCache) return _fbCache;
  try {
    if (fs.existsSync(fbFile)) _fbCache = JSON.parse(fs.readFileSync(fbFile, 'utf8'));
    else _fbCache = [];
  } catch (e) { _fbCache = []; }
  return _fbCache;
}

function saveFeedbackAsync(data) {
  _fbCache = data;
  ensureDataDir();
  fs.writeFile(fbFile, JSON.stringify(data, null, 2), err => {
    if (err) console.error('[EQ] feedback save error:', err.message);
  });
}

app.post('/api/feedback', requireAuth, (req, res) => {
  try {
    const entry = {
      id:         crypto.randomBytes(8).toString('hex'),
      clinic_id:  req.clinic_id,
      horse:      req.body.horse      || 'Desconhecido',
      date:       req.body.date       || new Date().toLocaleDateString('pt-PT'),
      appGrade:   req.body.appGrade   || '',
      vetGrade:   req.body.vetGrade   || '',
      vetNotes:   req.body.vetNotes   || '',
      structures: req.body.structures || [],
      user:       req.user,
      ts:         Date.now()
    };
    const data = loadFeedback();
    data.unshift(entry);
    if (data.length > 500) data.length = 500;
    saveFeedbackAsync(data);
    res.json({ ok: true, id: entry.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/feedback', requireAuth, (req, res) => {
  try {
    const all      = loadFeedback();
    const filtered = all.filter(e => !e.clinic_id || e.clinic_id === req.clinic_id);
    res.json(filtered);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── STRIPE ────────────────────────────────────────────────────────────────────
app.get('/api/stripe/plans', (req, res) => {
  res.json({
    plans: [
      {
        id:    'free',
        name:  'Free',
        price: 0,
        currency: 'EUR',
        analyses_per_day: PLANS.free.analyses_per_day,
        features: ['5 análises/dia', 'Cavalos ilimitados', 'Exportar PDF', 'Histórico básico']
      },
      {
        id:    'pro',
        name:  'Pro',
        price: 49,
        currency: 'EUR',
        price_id: PLANS.pro.price_id,
        analyses_per_day: PLANS.pro.analyses_per_day,
        features: ['100 análises/dia', 'Cavalos ilimitados', 'Calibrações avançadas', 'Suporte prioritário', 'Multi-dispositivo', 'Exportar PDF+DICOM']
      },
      {
        id:    'clinic',
        name:  'Clínica',
        price: 149,
        currency: 'EUR',
        price_id: PLANS.clinic.price_id,
        analyses_per_day: 9999,
        features: ['Análises ilimitadas', 'Múltiplos veterinários', 'Admin dashboard', 'Calibrações partilhadas', 'API access', 'Integração PACS']
      }
    ]
  });
});

app.post('/api/stripe/checkout', requireAuth, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Stripe não configurado' });
  const { plan } = req.body;
  const planData = PLANS[plan];
  if (!planData || !planData.price_id) return res.status(400).json({ error: 'Plano inválido ou sem price_id configurado' });

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode:                 'subscription',
      line_items:           [{ price: planData.price_id, quantity: 1 }],
      success_url:          `${APP_URL}?upgrade_success=1&plan=${plan}`,
      cancel_url:           `${APP_URL}?upgrade_cancel=1`,
      metadata:             { user: req.user, clinic_id: req.clinic_id, plan },
      client_reference_id:  req.user_id || req.user,
      ...(req.body.email ? { customer_email: req.body.email } : {})
    });
    res.json({ url: session.url, session_id: session.id });
  } catch(e) {
    console.error('[EQ] Stripe checkout error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/stripe/portal', requireAuth, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Stripe não configurado' });
  try {
    // Procurar customer pelo email
    const customers = await stripe.customers.list({ email: req.user, limit: 1 });
    if (!customers.data.length) return res.status(404).json({ error: 'Cliente Stripe não encontrado' });
    const session = await stripe.billingPortal.sessions.create({
      customer:   customers.data[0].id,
      return_url: APP_URL
    });
    res.json({ url: session.url });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Webhook Stripe
app.post('/api/stripe/webhook', async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(400).send('Webhook não configurado');
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch(e) {
    console.error('[EQ] Webhook signature error:', e.message);
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }

  console.log('[EQ] Stripe event:', event.type);

  switch(event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const { user, clinic_id, plan } = session.metadata || {};
      if (user && plan) {
        // Actualizar plano no Supabase
        if (SUPABASE_SERVICE_KEY && user.includes('@')) {
          try {
            await sbAdmin('PATCH', `/rest/v1/profiles?email=eq.${encodeURIComponent(user)}`, { plan, updated_at: new Date().toISOString() });
          } catch(e) { console.error('[EQ] Profile update error:', e.message); }
        }
        // Actualizar sessões activas deste utilizador
        sessions.forEach((s, token) => {
          if (s.user === user) { s.plan = plan; markSessionsDirty(); }
        });
        console.log('[EQ] Upgrade:', user, '->', plan);
      }
      break;
    }
    case 'customer.subscription.deleted': {
      // Downgrade para free
      const sub = event.data.object;
      const customers = await stripe.customers.retrieve(sub.customer);
      if (customers.email) {
        sessions.forEach((s, token) => {
          if (s.user === customers.email) { s.plan = 'free'; markSessionsDirty(); }
        });
        if (SUPABASE_SERVICE_KEY) {
          try {
            await sbAdmin('PATCH', `/rest/v1/profiles?email=eq.${encodeURIComponent(customers.email)}`, { plan: 'free', updated_at: new Date().toISOString() });
          } catch(e) {}
        }
        console.log('[EQ] Downgrade to free:', customers.email);
      }
      break;
    }
  }

  res.json({ received: true });
});

// ── KNOWLEDGE AGGREGATION ─────────────────────────────────────────────────────
function runKnowledgeAggregation() {
  try {
    const all      = loadFeedback();
    const patterns = {};
    all.forEach(fb => {
      if (!fb.vetGrade || fb.vetGrade === fb.appGrade) return;
      const key = ((fb.structures || [])[0] || '?') + '|' + fb.appGrade + '|' + fb.vetGrade;
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
      fs.writeFile(path.join(__dirname, '../data/calib_global.json'), JSON.stringify(global, null, 2), () => {});
      console.log('[EQ] Knowledge aggregation:', global.length, 'padrões globais');
    }
  } catch (e) { console.error('[EQ] Aggregation error:', e.message); }
}

app.get('/api/calib/global', requireAuth, (req, res) => {
  try {
    const f = path.join(__dirname, '../data/calib_global.json');
    if (!fs.existsSync(f)) return res.json([]);
    res.json(JSON.parse(fs.readFileSync(f, 'utf8')));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

runKnowledgeAggregation();
setInterval(runKnowledgeAggregation, 24 * 60 * 60 * 1000);

// ── STATIC — PWA assets ───────────────────────────────────────────────────────
const publicDir = path.join(__dirname, '../public');
app.use(express.static(publicDir));

// Serve SVG icons como PNG (fallback se não houver PNGs)
app.get('/icons/:icon', (req, res) => {
  const iconPath = path.join(publicDir, 'icons', req.params.icon);
  if (fs.existsSync(iconPath)) return res.sendFile(iconPath);
  // Fallback: gerar SVG inline
  const size = parseInt(req.params.icon.match(/\d+/)?.[0] || '192');
  res.setHeader('Content-Type', 'image/svg+xml');
  res.send(`<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">
    <rect width="${size}" height="${size}" rx="${Math.round(size*0.2)}" fill="#0a0c11"/>
    <rect x="4" y="4" width="${size-8}" height="${size-8}" rx="${Math.round(size*0.16)}" fill="none" stroke="#c9a84c" stroke-width="2" opacity="0.6"/>
    <text x="${Math.round(size/2)}" y="${Math.round(size*0.48)}" font-family="Georgia,serif" font-size="${Math.round(size*0.32)}" font-weight="700" fill="#c9a84c" text-anchor="middle" dominant-baseline="middle">RX</text>
    <text x="${Math.round(size/2)}" y="${Math.round(size*0.78)}" font-family="Arial,sans-serif" font-size="${Math.round(size*0.1)}" fill="#c9a84c" text-anchor="middle" opacity="0.8">EQUI</text>
  </svg>`);
});

app.get('*', (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  const clinics = getClinics();
  const users   = getUsers();
  console.log('[EQ] EquiScan Pro v57 porta', PORT);
  console.log('[EQ] Clínicas:', Object.keys(clinics).length, '| Users:', Object.keys(users).length);
  console.log('[EQ] Stripe:', stripe ? '✓' : '✗ (configurar STRIPE_SECRET_KEY)');
  console.log('[EQ] Supabase admin:', SUPABASE_SERVICE_KEY ? '✓' : '✗ (configurar SUPABASE_SERVICE_KEY)');
  if (!ANTHROPIC_API_KEY) console.warn('[EQ] AVISO: ANTHROPIC_API_KEY não configurada');
});
