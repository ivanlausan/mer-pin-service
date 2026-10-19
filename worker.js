const TTL = 12 * 60 * 60 * 1000;
const MAX_BODY = 2 * 1024 * 1024;
const te = new TextEncoder();
const td = new TextDecoder();

function b64(bytes) {
  const data = new Uint8Array(bytes);
  let binary = '';
  for (let i = 0; i < data.length; i += 0x8000) binary += String.fromCharCode(...data.subarray(i, i + 0x8000));
  return btoa(binary);
}
function unb64(value) { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', ...headers } });
}
function error(status, message) { return Object.assign(new Error(message), { status }); }
async function digest(data) { return b64(await crypto.subtle.digest('SHA-256', data)); }
async function hmac(secret, value) {
  const key = await crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64(await crypto.subtle.sign('HMAC', key, te.encode(value)));
}
function hex(bytes) { return [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, '0')).join(''); }
async function accountId(secret, pin) { return hex(await crypto.subtle.sign('HMAC', await crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']), te.encode(pin))); }
async function verifier(pin, salt) {
  const key = await crypto.subtle.importKey('raw', te.encode(pin), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: unb64(salt), iterations: 100000, hash: 'SHA-256' }, key, 256));
}
async function cryptKey(secret, id) {
  const raw = await crypto.subtle.sign('HMAC', await crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']), te.encode('models:' + id));
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function encrypt(secret, id, models) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, await cryptKey(secret, id), te.encode(JSON.stringify(models)));
  return { nonce: b64(nonce), models: b64(encrypted) };
}
async function decrypt(secret, id, row) {
  const clear = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(row.nonce) }, await cryptKey(secret, id), unb64(row.models));
  const result = JSON.parse(td.decode(clear));
  return Array.isArray(result) ? result : [];
}
function getPin(body) {
  const pin = String(body.pin || '');
  if (!/^\d{8,16}$/.test(pin)) throw error(400, 'El PIN debe tener entre 8 y 16 dígitos.');
  return pin;
}
async function bodyJson(request) {
  const text = await request.text();
  if (te.encode(text).length > MAX_BODY) throw error(413, 'El archivo del modelo supera el límite de 2 MB.');
  try { return JSON.parse(text || '{}'); } catch { throw error(400, 'El contenido enviado no es un JSON válido.'); }
}
async function rateLimit(db, key) {
  const now = Date.now();
  const row = await db.prepare('SELECT timestamps FROM attempts WHERE attempt_key=?').bind(key).first();
  const active = row ? JSON.parse(row.timestamps).filter(t => now - t < 900000) : [];
  if (active.length >= 8) throw error(429, 'Demasiados intentos. Vuelve a intentarlo dentro de 15 minutos.');
  active.push(now);
  await db.prepare('INSERT INTO attempts(attempt_key,timestamps) VALUES(?,?) ON CONFLICT(attempt_key) DO UPDATE SET timestamps=excluded.timestamps').bind(key, JSON.stringify(active)).run();
}
async function getAccount(request, env) {
  const token = (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!token) throw error(401, 'La sesión terminó. Accede de nuevo con tu PIN.');
  const row = await env.DB.prepare('SELECT s.account_id,s.expires_at,a.nonce,a.models FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE s.token=?').bind(token).first();
  if (!row || row.expires_at <= Date.now()) {
    await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(token).run();
    throw error(401, 'La sesión terminó. Accede de nuevo con tu PIN.');
  }
  return { id: row.account_id, row, token };
}
async function api(request, env, url) {
  const db = env.DB;
  if (request.method === 'POST' && ['/api/register', '/api/login'].includes(url.pathname)) {
    const pin = getPin(await bodyJson(request));
    const id = await accountId(env.MER_PIN_SECRET, pin);
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    await rateLimit(db, 'ip:' + ip);
    await rateLimit(db, 'pin:' + id);
    let account = await db.prepare('SELECT * FROM accounts WHERE id=?').bind(id).first();
    if (url.pathname === '/api/register') {
      if (account) throw error(409, 'Ese PIN ya tiene una cuenta. Usa “Acceder” con ese PIN o crea otro.');
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const salt64 = b64(salt);
      const check = await verifier(pin, salt64);
      const encrypted = await encrypt(env.MER_PIN_SECRET, id, []);
      await db.prepare('INSERT INTO accounts(id,salt,verifier,nonce,models,created_at) VALUES(?,?,?,?,?,?)').bind(id, salt64, check, encrypted.nonce, encrypted.models, Date.now()).run();
      account = { id, salt: salt64, verifier: check };
    } else {
      const check = account ? await verifier(pin, account.salt) : '';
      if (!account || check !== account.verifier) throw error(401, 'PIN incorrecto o cuenta inexistente.');
    }
    const token = b64(crypto.getRandomValues(new Uint8Array(32))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    await db.prepare('INSERT INTO sessions(token,account_id,expires_at) VALUES(?,?,?)').bind(token, id, Date.now() + TTL).run();
    await db.prepare('DELETE FROM attempts WHERE attempt_key IN (?,?)').bind('ip:' + ip, 'pin:' + id).run();
    return json({ token });
  }
  if (request.method === 'POST' && url.pathname === '/api/logout') {
    const token = (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
    await db.prepare('DELETE FROM sessions WHERE token=?').bind(token).run();
    return json({ ok: true });
  }
  const current = await getAccount(request, env);
  if (request.method === 'GET' && url.pathname === '/api/models') return json({ models: await decrypt(env.MER_PIN_SECRET, current.id, current.row) });
  if (request.method === 'POST' && url.pathname === '/api/models') {
    const body = await bodyJson(request);
    if (!body.state || !Array.isArray(body.state.entities) || !Array.isArray(body.state.relations)) throw error(400, 'El modelo no contiene entidades y relaciones válidas.');
    const account = await db.prepare('SELECT * FROM accounts WHERE id=?').bind(current.id).first();
    const models = await decrypt(env.MER_PIN_SECRET, current.id, account);
    const name = String(body.name || body.projectName || 'Modelo sin nombre').trim().slice(0, 120) || 'Modelo sin nombre';
    let model = models.find(m => (body.id && m.id === body.id) || m.name === name);
    if (model) Object.assign(model, { name, projectName: String(body.projectName || name).slice(0, 120), state: body.state, updatedAt: new Date().toISOString() });
    else { model = { id: crypto.randomUUID(), name, projectName: String(body.projectName || name).slice(0, 120), state: body.state, updatedAt: new Date().toISOString() }; models.push(model); }
    const encrypted = await encrypt(env.MER_PIN_SECRET, current.id, models);
    await db.prepare('UPDATE accounts SET nonce=?,models=? WHERE id=?').bind(encrypted.nonce, encrypted.models, current.id).run();
    return json({ model });
  }
  if (request.method === 'DELETE' && url.pathname.startsWith('/api/models/')) {
    const id = decodeURIComponent(url.pathname.slice('/api/models/'.length));
    const account = await db.prepare('SELECT * FROM accounts WHERE id=?').bind(current.id).first();
    const models = (await decrypt(env.MER_PIN_SECRET, current.id, account)).filter(m => m.id !== id);
    const encrypted = await encrypt(env.MER_PIN_SECRET, current.id, models);
    await db.prepare('UPDATE accounts SET nonce=?,models=? WHERE id=?').bind(encrypted.nonce, encrypted.models, current.id).run();
    return json({ ok: true });
  }
  return json({ error: 'Ruta API no encontrada.' }, 404);
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('origin') || '';
    const allowed = origin === 'merapp://app';
    const cors = allowed ? { 'access-control-allow-origin': origin, 'access-control-allow-methods': 'GET, POST, DELETE, OPTIONS', 'access-control-allow-headers': 'Authorization, Content-Type', 'vary': 'Origin' } : {};
    if (!env.MER_PIN_SECRET || te.encode(env.MER_PIN_SECRET).length < 32) return json({ error: 'El servicio no está configurado.' }, 500, cors);
    if (url.pathname.startsWith('/api/')) {
      if (request.method === 'OPTIONS') return allowed ? new Response(null, { status: 204, headers: cors }) : json({ error: 'Origen de aplicación no autorizado.' }, 403);
      try { const response = await api(request, env, url); const headers = new Headers(response.headers); for (const [k,v] of Object.entries(cors)) headers.set(k,v); return new Response(response.body, { status: response.status, headers }); }
      catch (e) {
        if (!e.status) console.error('Error interno en la API MER:', e?.stack || e);
        return json({ error: e.status ? e.message : 'Error interno del servicio.' }, e.status || 500, cors);
      }
    }
    return env.ASSETS.fetch(request);
  }
};
