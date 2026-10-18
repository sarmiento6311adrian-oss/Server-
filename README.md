#!/usr/bin/env node
/* ================================================================
   Grow a Garden 3D — account + cloud save server
   ----------------------------------------------------------------
   • ONE FILE: the game is built into this file. Nothing else to copy,
     no folder to set up.
   • No installs needed: only Node.js 16+ (built-in modules only).
   • Run it:     node server.js
   • Then open the address it prints (e.g. http://localhost:3000) on any device.

   Settings (all optional, set as environment variables):
     PORT=3000            port to listen on
     HOST=0.0.0.0         0.0.0.0 = reachable from other devices
     DATA_DIR=./gag-data  where accounts and saves are stored
     MAX_STORAGE_GB=50    stop accepting new data after this much (any size you like)
     MAX_SAVE_KB=2048     biggest single save one player can upload
     ALLOW_ORIGIN=*       which websites may call the API
     TRUST_PROXY=1        set when running behind nginx/Cloudflare/Render etc.
     GAME_FILE=           serve this HTML file instead of the built-in game (optional)

   Storage is plain files, so the real limit is the disk it runs on.
   A save is roughly 20–100 KB, so 50 GB holds hundreds of thousands of players.
   Passwords are never stored: only a salted scrypt hash.
   Use HTTPS (Render, Railway, Cloudflare Tunnel, Caddy…) if the server is on the internet.
   ================================================================ */
'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), os = require('os');

const PORT = +process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const DATA = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'gag-data'));
const MAX_BYTES = Math.floor((parseFloat(process.env.MAX_STORAGE_GB) || 50) * 1024 * 1024 * 1024);
const MAX_SAVE = Math.floor((parseFloat(process.env.MAX_SAVE_KB) || 2048) * 1024);
const ORIGIN = process.env.ALLOW_ORIGIN || '*';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const GAME_FILE = process.env.GAME_FILE || '';
const THREE = path.join(__dirname, 'three.min.js');
const TOKEN_DAYS = 90, MAX_TOKENS = 10;
const KEYS = new Set(['gag3d-farm', 'gag3d-epoch', 'gag3d-tut', 'gag3d-plot', 'gag3d-name', 'gag3d-world', 'gag3d-codes']);
const NAME_RE = /^[A-Za-z0-9_]{3,20}$/;

fs.mkdirSync(path.join(DATA, 'users'), { recursive: true });
fs.mkdirSync(path.join(DATA, 'saves'), { recursive: true });

/* ---------- storage accounting ---------- */
let used = 0, userCount = 0;
for (const d of ['users', 'saves']) {
  for (const f of fs.readdirSync(path.join(DATA, d))) {
    if (f.endsWith('.tmp')) { try { fs.unlinkSync(path.join(DATA, d, f)); } catch (_) {} continue; }
    try { used += fs.statSync(path.join(DATA, d, f)).size; if (d === 'users') userCount++; } catch (_) {}
  }
}

const fileOf = (kind, lower) => path.join(DATA, kind, lower + '.json');
function readJSON(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) { return null; } }
function sizeOf(file) { try { return fs.statSync(file).size; } catch (_) { return 0; } }
function writeAtomic(file, text) {            /* write to a temp file, then rename: a crash never leaves a half-written save */
  const old = sizeOf(file), tmp = file + '.' + crypto.randomBytes(4).toString('hex') + '.tmp';
  fs.writeFileSync(tmp, text);
  fs.renameSync(tmp, file);
  used += Buffer.byteLength(text) - old;
}

/* ---------- helpers ---------- */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
function hashPw(pw, salt) {
  return new Promise((ok, no) => crypto.scrypt(pw, salt, 64, (e, k) => e ? no(e) : ok(k)));
}
function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': ORIGIN, 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '86400'
  });
  res.end(body);
}
function body(req, limit) {
  return new Promise((ok, no) => {
    let n = 0; const parts = [];
    req.on('data', c => { n += c.length; if (n > limit) { no(Object.assign(new Error('big'), { code: 413 })); req.destroy(); } else parts.push(c); });
    req.on('end', () => { try { ok(JSON.parse(Buffer.concat(parts).toString('utf8') || '{}')); } catch (_) { no(Object.assign(new Error('json'), { code: 400 })); } });
    req.on('error', no);
  });
}
const ipOf = req => (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '?';

/* ---------- rate limits (in memory) ---------- */
const hits = new Map();
function count(key, windowMs) { const now = Date.now(); const a = (hits.get(key) || []).filter(t => now - t < windowMs); hits.set(key, a); return a.length; }
function hit(key) { const a = hits.get(key) || []; a.push(Date.now()); hits.set(key, a); }
setInterval(() => { const now = Date.now(); for (const [k, a] of hits) { if (!a.length || now - a[a.length - 1] > 3600e3) hits.delete(k); } }, 600e3).unref();

/* ---------- accounts ---------- */
function newToken(user) {
  const raw = crypto.randomBytes(32).toString('hex');
  user.tokens = (user.tokens || []).filter(t => t.exp > Date.now());
  user.tokens.push({ h: sha(raw), exp: Date.now() + TOKEN_DAYS * 864e5 });
  if (user.tokens.length > MAX_TOKENS) user.tokens = user.tokens.slice(-MAX_TOKENS);
  return user.lower + '.' + raw;
}
function authed(token) {                       /* returns the user record for a valid token, else null */
  if (typeof token !== 'string') return null;
  const i = token.indexOf('.'); if (i < 3) return null;
  const lower = token.slice(0, i); if (!NAME_RE.test(lower)) return null;
  const user = readJSON(fileOf('users', lower)); if (!user) return null;
  const h = sha(token.slice(i + 1)), now = Date.now();
  return (user.tokens || []).some(t => t.h === h && t.exp > now) ? user : null;
}
function payload(user, token) {
  const sv = readJSON(fileOf('saves', user.lower)) || { rev: 0, updated: 0, dev: '', data: null };
  const out = { ok: true, user: user.name, rev: sv.rev, updated: sv.updated, dev: sv.dev, data: sv.data };
  if (token) out.token = token;
  return out;
}

/* ---------- routes ---------- */
async function api(req, res, url) {
  const ip = ipOf(req);
  if (count('G:' + ip, 60e3) >= 300) return send(res, 429, { error: 'Slow down.' });
  hit('G:' + ip);

  if (req.method === 'GET' && url === '/api/health')
    return send(res, 200, { ok: true, game: 'grow-a-garden-3d', players: userCount, usedMB: Math.round(used / 1048576), maxGB: +(MAX_BYTES / 1073741824).toFixed(2) });
  if (req.method !== 'POST') return send(res, 405, { error: 'Not allowed.' });

  let b; try { b = await body(req, MAX_SAVE + 4096); } catch (e) { return send(res, e.code === 413 ? 413 : 400, { error: e.code === 413 ? 'That save is too big.' : 'Bad request.' }); }

  if (url === '/api/register') {
    if (count('R:' + ip, 3600e3) >= 10) return send(res, 429, { error: 'Too many new accounts from this network. Try later.' });
    const name = String(b.username || '').trim(), pw = String(b.password || '');
    if (!NAME_RE.test(name)) return send(res, 400, { error: 'Username must be 3–20 letters, numbers or underscores.' });
    if (pw.length < 6 || pw.length > 100) return send(res, 400, { error: 'Password must be 6–100 characters.' });
    if (used + 8192 > MAX_BYTES) return send(res, 507, { error: 'The server is full right now.' });
    const lower = name.toLowerCase();
    if (fs.existsSync(fileOf('users', lower))) return send(res, 409, { error: 'That username is already used.' });
    hit('R:' + ip);
    const salt = crypto.randomBytes(16), key = await hashPw(pw, salt);
    const user = { name, lower, salt: salt.toString('hex'), hash: key.toString('hex'), created: Date.now(), tokens: [] };
    const token = newToken(user), text = JSON.stringify(user), file = fileOf('users', lower);
    try { fs.writeFileSync(file, text, { flag: 'wx' }); } catch (e) { return send(res, 409, { error: 'That username is already used.' }); }
    used += Buffer.byteLength(text); userCount++;
    return send(res, 200, payload(user, token));
  }

  if (url === '/api/login') {
    const name = String(b.username || '').trim(), pw = String(b.password || ''), lower = name.toLowerCase();
    if (!NAME_RE.test(name) || !pw || pw.length > 100) return send(res, 401, { error: 'Wrong username or password.' });
    if (count('F:' + ip, 600e3) >= 20 || count('F:' + lower, 600e3) >= 10) return send(res, 429, { error: 'Too many tries. Wait a few minutes.' });
    const user = readJSON(fileOf('users', lower));
    const salt = Buffer.from(user ? user.salt : '00'.repeat(16), 'hex'), key = await hashPw(pw, salt);
    const ok = user && key.length === Buffer.from(user.hash, 'hex').length && crypto.timingSafeEqual(key, Buffer.from(user.hash, 'hex'));
    if (!ok) { hit('F:' + ip); hit('F:' + lower); return send(res, 401, { error: 'Wrong username or password.' }); }
    const token = newToken(user); writeAtomic(fileOf('users', lower), JSON.stringify(user));
    return send(res, 200, payload(user, token));
  }

  const user = authed(b.token);
  if (!user) return send(res, 401, { error: 'Please log in again.' });

  if (url === '/api/load') return send(res, 200, payload(user));

  if (url === '/api/logout') {
    const h = sha(String(b.token).slice(String(b.token).indexOf('.') + 1));
    user.tokens = (user.tokens || []).filter(t => t.h !== h);
    writeAtomic(fileOf('users', user.lower), JSON.stringify(user));
    return send(res, 200, { ok: true });
  }

  if (url === '/api/save') {
    const data = b.data;
    if (!data || typeof data !== 'object' || Array.isArray(data)) return send(res, 400, { error: 'Bad save.' });
    const clean = {}; let size = 0;
    for (const k of Object.keys(data)) {
      if (!KEYS.has(k) || typeof data[k] !== 'string') continue;
      clean[k] = data[k]; size += data[k].length;
    }
    if (size > MAX_SAVE) return send(res, 413, { error: 'That save is too big.' });
    const file = fileOf('saves', user.lower), cur = readJSON(file) || { rev: 0, updated: 0, dev: '', data: null };
    const dev = String(b.dev || '').slice(0, 40), base = +b.base || 0;
    /* Someone else saved since this device last synced → don't overwrite; let the player choose. */
    if (!b.force && cur.rev !== base && cur.dev !== dev && cur.rev > 0)
      return send(res, 409, { error: 'Newer progress exists.', conflict: true, user: user.name, rev: cur.rev, updated: cur.updated, dev: cur.dev, data: cur.data });
    const next = { rev: cur.rev + 1, updated: Date.now(), dev, data: clean }, text = JSON.stringify(next);
    if (used - sizeOf(file) + Buffer.byteLength(text) > MAX_BYTES) return send(res, 507, { error: 'The server is full right now.' });
    writeAtomic(file, text);
    return send(res, 200, { ok: true, rev: next.rev, updated: next.updated });
  }

  return send(res, 404, { error: 'Not found.' });
}

/* ---------- static: the game itself ---------- */
function serve(res, file, type) {
  fs.readFile(file, (e, buf) => {
    if (e) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-cache' }); res.end(buf);
  });
}

/* The game is stored inside this file (see GAME_B64 at the bottom): gzip + base64. */
let _gz = null, _raw = null;
const gameGz = () => _gz || (_gz = Buffer.from(GAME_B64.join(''), 'base64'));
const gameRaw = () => _raw || (_raw = require('zlib').gunzipSync(gameGz()));
function sendGame(req, res) {
  if (GAME_FILE && fs.existsSync(GAME_FILE)) return serve(res, GAME_FILE, 'text/html; charset=utf-8');
  const h = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'Vary': 'Accept-Encoding' };
  if (/\bgzip\b/.test(String(req.headers['accept-encoding'] || ''))) {   /* phones get the small compressed copy */
    const gz = gameGz(); h['Content-Encoding'] = 'gzip'; h['Content-Length'] = gz.length;
    res.writeHead(200, h); return res.end(gz);
  }
  const raw = gameRaw(); h['Content-Length'] = raw.length;
  res.writeHead(200, h); res.end(raw);
}

http.createServer((req, res) => {
  const url = (req.url || '/').split('?')[0];
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': ORIGIN, 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '86400' });
    return res.end();
  }
  if (url.startsWith('/api/')) return api(req, res, url).catch(e => { console.error(e); try { send(res, 500, { error: 'Server error.' }); } catch (_) {} });
  if (req.method === 'GET' && (url === '/' || url === '/index.html' || url === '/grow-a-garden-3d.html')) return sendGame(req, res);
  if (req.method === 'GET' && url === '/three.min.js') return serve(res, THREE, 'application/javascript; charset=utf-8');
  res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not found');
}).listen(PORT, HOST, () => {
  console.log('\nGrow a Garden server is running.\n');
  console.log('  This computer:  http://localhost:' + PORT);
  for (const list of Object.values(os.networkInterfaces()))
    for (const a of list || []) if (a.family === 'IPv4' && !a.internal) console.log('  Other devices:  http://' + a.address + ':' + PORT + '   (same Wi-Fi / hotspot)');
  console.log('\n  Saves go to:    ' + DATA);
  console.log('  Storage limit:  ' + (MAX_BYTES / 1073741824) + ' GB   (used so far: ' + (used / 1048576).toFixed(1) + ' MB, ' + userCount + ' players)');
  if (GAME_FILE && !fs.existsSync(GAME_FILE)) console.log('\n  ⚠ GAME_FILE was not found, so the built-in game is being served instead.');
  console.log('');
});

/* ================================================================
   Built-in copy of the game (grow-a-garden-3d.html), gzip + base64.
   Generated: do not edit by hand. sha256 of the HTML: b62ecc20a23a7792
   ================================================================ */
const GAME_B64 = [
'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
