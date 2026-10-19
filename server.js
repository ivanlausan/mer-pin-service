'use strict';
const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const PIN_SECRET = process.env.MER_PIN_SECRET || '';
if (Buffer.byteLength(PIN_SECRET, 'utf8') < 32) {
  throw new Error('Configura MER_PIN_SECRET con al menos 32 caracteres aleatorios antes de iniciar el servicio.');
}
const DATA_DIR = path.resolve(process.env.MER_DATA_DIR || path.join(__dirname, 'data'));
const STORE_FILE = path.join(DATA_DIR, 'accounts.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 8;
const DESKTOP_ORIGINS = new Set((process.env.MER_DESKTOP_ORIGINS || 'merapp://app').split(',').map(value => value.trim()).filter(Boolean));
const sessions = new Map();
const attempts = new Map();
const storageKey = crypto.createHash('sha256').update(PIN_SECRET, 'utf8').digest();
let store = { accounts: {} };
let writeQueue = Promise.resolve();

function accountId(pin) {
  return crypto.createHmac('sha256', PIN_SECRET).update(pin, 'utf8').digest('hex');
}
function verifier(pin, salt) {
  return crypto.scryptSync(pin, salt, 32).toString('hex');
}
function constantTimeEqual(a, b) {
  const left = Buffer.from(String(a || ''), 'hex');
  const right = Buffer.from(String(b || ''), 'hex');
  return left.length === right.length && left.length > 0 && crypto.timingSafeEqual(left, right);
}
function encryptionKey(id) {
  return crypto.createHmac('sha256', storageKey).update(id).digest();
}
function encryptModels(id, models) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(id), nonce);
  const data = Buffer.concat([cipher.update(JSON.stringify(models), 'utf8'), cipher.final()]);
  return { nonce: nonce.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') };
}
function decryptModels(id, record) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(id), Buffer.from(record.nonce, 'base64'));
  decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
  const clear = Buffer.concat([decipher.update(Buffer.from(record.data, 'base64')), decipher.final()]).toString('utf8');
  const value = JSON.parse(clear);
  return Array.isArray(value) ? value : [];
}
async function saveStore() {
  const temp = STORE_FILE + '.' + process.pid + '.tmp';
  await fs.writeFile(temp, JSON.stringify(store), { encoding: 'utf8', mode: 0o600 });
  await fs.rename(temp, STORE_FILE);
}
function mutate(fn) {
  const result = writeQueue.then(fn);
  writeQueue = result.catch(() => {});
  return result;
}
function sendJson(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer'
  });
  res.end(JSON.stringify(data));
}
function fail(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(fail(413, 'El archivo del modelo supera el límite de 2 MB.'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch { reject(fail(400, 'El contenido enviado no es un JSON válido.')); }
    });
    req.on('error', reject);
  });
}
function getClientIp(req) {
  return req.socket.remoteAddress || 'unknown';
}
function checkRateLimit(req, pin) {
  const now = Date.now();
  const keys = [getClientIp(req), 'pin:' + accountId(pin)];
  const activeByKey = keys.map(key => [key, (attempts.get(key) || []).filter(t => now - t < ATTEMPT_WINDOW_MS)]);
  if (activeByKey.some(([, active]) => active.length >= MAX_ATTEMPTS)) throw fail(429, 'Demasiados intentos. Vuelve a intentarlo dentro de 15 minutos.');
  for (const [key, active] of activeByKey) { active.push(now); attempts.set(key, active); }
}
function clearAttempts(req, pin) {
  attempts.delete(getClientIp(req));
  attempts.delete('pin:' + accountId(pin));
}
function getPin(body) {
  const pin = String(body.pin || '');
  if (!/^\d{8,16}$/.test(pin)) throw fail(400, 'El PIN debe tener entre 8 y 16 dígitos.');
  return pin;
}
function createSession(id) {
  const token = crypto.randomBytes(32).toString('base64url');
  sessions.set(token, { id, expires: Date.now() + TOKEN_TTL_MS });
  return token;
}
function requireAccount(req) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const session = sessions.get(token);
  if (!session || session.expires <= Date.now()) {
    if (token) sessions.delete(token);
    throw fail(401, 'La sesión terminó. Accede de nuevo con tu PIN.');
  }
  const account = store.accounts[session.id];
  if (!account) throw fail(401, 'No se encontró la cuenta. Accede de nuevo con tu PIN.');
  return { id: session.id, account, token };
}
async function api(req, res, url) {
  if (req.method === 'POST' && (url.pathname === '/api/register' || url.pathname === '/api/login')) {
    const body = await readJson(req);
    const pin = getPin(body);
    checkRateLimit(req, pin);
    const id = accountId(pin);
    if (url.pathname === '/api/register') {
      await mutate(async () => {
        if (store.accounts[id]) throw fail(409, 'Ese PIN ya tiene una cuenta. Usa “Acceder” con ese PIN o crea otro.');
        const salt = crypto.randomBytes(16).toString('hex');
        store.accounts[id] = { salt, verifier: verifier(pin, salt), models: encryptModels(id, []) };
        await saveStore();
      });
    } else {
      const account = store.accounts[id];
      if (!account || !constantTimeEqual(verifier(pin, account.salt), account.verifier)) {
        throw fail(401, 'PIN incorrecto o cuenta inexistente.');
      }
    }
    clearAttempts(req, pin);
    return sendJson(res, 200, { token: createSession(id) });
  }
  if (req.method === 'POST' && url.pathname === '/api/logout') {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    sessions.delete(token);
    return sendJson(res, 200, { ok: true });
  }
  const current = requireAccount(req);
  if (req.method === 'GET' && url.pathname === '/api/models') {
    return sendJson(res, 200, { models: decryptModels(current.id, current.account.models) });
  }
  if (req.method === 'POST' && url.pathname === '/api/models') {
    const body = await readJson(req);
    if (!body.state || !Array.isArray(body.state.entities) || !Array.isArray(body.state.relations)) {
      throw fail(400, 'El modelo no contiene entidades y relaciones válidas.');
    }
    const name = String(body.name || body.projectName || 'Modelo sin nombre').trim().slice(0, 120) || 'Modelo sin nombre';
    const model = await mutate(async () => {
      const models = decryptModels(current.id, store.accounts[current.id].models);
      let existing = models.find(m => (body.id && m.id === body.id) || m.name === name);
      if (existing) {
        existing.name = name;
        existing.projectName = String(body.projectName || name).slice(0, 120);
        existing.state = body.state;
        existing.updatedAt = new Date().toISOString();
      } else {
        existing = { id: crypto.randomUUID(), name, projectName: String(body.projectName || name).slice(0, 120), state: body.state, updatedAt: new Date().toISOString() };
        models.push(existing);
      }
      store.accounts[current.id].models = encryptModels(current.id, models);
      await saveStore();
      return existing;
    });
    return sendJson(res, 200, { model });
  }
  if (req.method === 'DELETE' && url.pathname.startsWith('/api/models/')) {
    const id = decodeURIComponent(url.pathname.slice('/api/models/'.length));
    await mutate(async () => {
      const models = decryptModels(current.id, store.accounts[current.id].models);
      store.accounts[current.id].models = encryptModels(current.id, models.filter(m => m.id !== id));
      await saveStore();
    });
    return sendJson(res, 200, { ok: true });
  }
  return sendJson(res, 404, { error: 'Ruta API no encontrada.' });
}
async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (url.pathname.startsWith('/api/')) {
      const origin = req.headers.origin || '';
      const allowed = DESKTOP_ORIGINS.has(origin);
      if (allowed) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
        res.setHeader('Vary', 'Origin');
      }
      if (req.method === 'OPTIONS') {
        if (!allowed) return sendJson(res, 403, { error: 'Origen de aplicación no autorizado.' });
        res.writeHead(204);
        return res.end();
      }
      return await api(req, res, url);
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') return sendJson(res, 405, { error: 'Método no permitido.' });
    if (url.pathname !== '/' && url.pathname !== '/index.html') return sendJson(res, 404, { error: 'Página no encontrada.' });
    const html = await fs.readFile(path.join(PUBLIC_DIR, 'index.html'));
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer'
    });
    return req.method === 'HEAD' ? res.end() : res.end(html);
  } catch (error) {
    if (!res.headersSent) sendJson(res, error.status || 500, { error: error.status ? error.message : 'Error interno del servicio.' });
    else res.destroy();
  }
}
async function start() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try { store = JSON.parse(await fs.readFile(STORE_FILE, 'utf8')); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    store = { accounts: {} };
    await saveStore();
  }
  if (!store.accounts || typeof store.accounts !== 'object') store = { accounts: {} };
  http.createServer(handle).listen(PORT, HOST, () => {
    console.log('Diseñador MER disponible en http://' + HOST + ':' + PORT);
  });
}
start().catch(error => { console.error(error); process.exit(1); });
