// Hofplaner: Anmeldung, Rollen und gemeinsame Daten (Cloudflare Worker + D1)
const SECS = ['tasks','events','products','customers','orders','ext','kvs','prices','recipes','pf','pm','mix','meta'];
const ADMIN_ONLY = ['ext','kvs','prices'];
const MAX_DATA = 900000;
const enc = new TextEncoder();

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, pw TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL, created INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS sessions(th TEXT PRIMARY KEY, uid INTEGER NOT NULL, exp INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS items(sec TEXT NOT NULL, id TEXT NOT NULL, data TEXT, upd INTEGER NOT NULL, del INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(sec,id))`,
  `CREATE INDEX IF NOT EXISTS items_upd ON items(upd)`,
  `CREATE TABLE IF NOT EXISTS counters(k TEXT PRIMARY KEY, v INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS fails(k TEXT NOT NULL, ts INTEGER NOT NULL)`,
];
let ready = null;
function init(env) {
  if (!ready) ready = env.DB.batch(SCHEMA.map(q => env.DB.prepare(q))).catch(e => { ready = null; throw e; });
  return ready;
}

const b64 = u8 => btoa(String.fromCharCode(...u8));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
function same(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function hashPw(pw, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return b64(new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, k, 256)));
}
async function sha(s) {
  return b64(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s))));
}
function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
}
const err = (m, s = 400) => json({ error: m }, s);
function cookie(req, name) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? m[1] : null;
}
function sessionCookie(token, maxAge) {
  return `hp_s=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}
async function newSession(env, uid) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const token = [...raw].map(x => x.toString(16).padStart(2, '0')).join('');
  const exp = Date.now() + 30 * 864e5;
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE exp<?').bind(Date.now()),
    env.DB.prepare('INSERT INTO sessions(th,uid,exp) VALUES(?,?,?)').bind(await sha(token), uid, exp),
  ]);
  return token;
}
async function currentUser(req, env) {
  const t = cookie(req, 'hp_s');
  if (!t) return null;
  return await env.DB.prepare('SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.uid WHERE s.th=? AND s.exp>?').bind(await sha(t), Date.now()).first();
}
const validName = n => typeof n === 'string' && /^[A-Za-z0-9._-]{3,32}$/.test(n);
const validPw = p => typeof p === 'string' && p.length >= 8 && p.length <= 200;
async function createUser(env, username, password, role) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  await env.DB.prepare('INSERT INTO users(username,pw,salt,role,created) VALUES(?,?,?,?,?)').bind(username, await hashPw(password, salt), b64(salt), role, Date.now()).run();
  return await env.DB.prepare('SELECT id,username,role FROM users WHERE username=?').bind(username).first();
}

async function handle(req, env, url) {
  const path = url.pathname, method = req.method;
  if (method !== 'GET' && method !== 'HEAD') {
    const o = req.headers.get('origin');
    if (o && o !== url.origin) return err('Anfrage abgelehnt.', 403);
  }
  let body = {};
  if (method === 'POST' || method === 'PATCH') {
    const text = await req.text();
    if (text.length > 4e6) return err('Zu viele Daten.', 413);
    try { body = text ? JSON.parse(text) : {}; } catch { return err('Ungültige Anfrage.'); }
  }

  if (path === '/api/status' && method === 'GET') {
    const n = (await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first()).n;
    return json({ needsSetup: n === 0, setupConfigured: !!env.SETUP_CODE });
  }
  if (path === '/api/setup' && method === 'POST') {
    const n = (await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first()).n;
    if (n > 0) return err('Die Einrichtung ist schon abgeschlossen.', 409);
    if (!env.SETUP_CODE) return err('In Cloudflare fehlt das Secret SETUP_CODE.', 409);
    if (typeof body.code !== 'string' || !same(await sha(body.code), await sha(String(env.SETUP_CODE)))) return err('Der Einrichtungscode stimmt nicht.', 403);
    if (!validName(body.username)) return err('Benutzername: 3 bis 32 Zeichen (Buchstaben, Zahlen, . _ -).');
    if (!validPw(body.password)) return err('Passwort: mindestens 8 Zeichen.');
    const u = await createUser(env, body.username, body.password, 'admin');
    return json({ user: u }, 200, { 'set-cookie': sessionCookie(await newSession(env, u.id), 30 * 86400) });
  }
  if (path === '/api/login' && method === 'POST') {
    const name = String(body.username || '').trim().toLowerCase().slice(0, 40);
    const key = name + '|' + (req.headers.get('cf-connecting-ip') || '');
    const since = Date.now() - 15 * 60e3;
    const f = await env.DB.prepare('SELECT COUNT(*) AS n FROM fails WHERE k=? AND ts>?').bind(key, since).first();
    if (f.n >= 8) return err('Zu viele Versuche. Bitte in 15 Minuten noch einmal probieren.', 429);
    const u = await env.DB.prepare('SELECT id,username,role,pw,salt FROM users WHERE username=?').bind(name).first();
    const salt = u ? unb64(u.salt) : new Uint8Array(16);
    const h = await hashPw(String(body.password || ''), salt);
    if (!u || !same(h, u.pw)) {
      await env.DB.batch([env.DB.prepare('DELETE FROM fails WHERE ts<?').bind(since), env.DB.prepare('INSERT INTO fails(k,ts) VALUES(?,?)').bind(key, Date.now())]);
      return err('Benutzername oder Passwort stimmt nicht.', 401);
    }
    await env.DB.prepare('DELETE FROM fails WHERE k=?').bind(key).run();
    return json({ user: { id: u.id, username: u.username, role: u.role } }, 200, { 'set-cookie': sessionCookie(await newSession(env, u.id), 30 * 86400) });
  }

  const me = await currentUser(req, env);
  if (!me) return err('Nicht angemeldet.', 401);
  const admin = me.role === 'admin';

  if (path === '/api/logout' && method === 'POST') {
    await env.DB.prepare('DELETE FROM sessions WHERE th=?').bind(await sha(cookie(req, 'hp_s'))).run();
    return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) });
  }
  if (path === '/api/me' && method === 'GET') return json({ user: me });

  if (path === '/api/data' && method === 'GET') {
    const since = Math.max(0, parseInt(url.searchParams.get('since')) || 0);
    const allowed = SECS.filter(s => admin || !ADMIN_ONLY.includes(s));
    const rows = (await env.DB.prepare(`SELECT sec,id,data,upd,del FROM items WHERE upd>? AND sec IN (${allowed.map(() => '?').join(',')})`).bind(since, ...allowed).all()).results;
    return json({ now: Date.now(), items: rows.filter(r => since > 0 || !r.del) });
  }

  if (path === '/api/sync' && method === 'POST') {
    const ops = Array.isArray(body.ops) ? body.ops : null;
    if (!ops || ops.length > 300) return err('Ungültige Änderungen.');
    const now = Date.now(), st = [];
    for (const o of ops) {
      if (!o || !SECS.includes(o.sec) || typeof o.id !== 'string' || !o.id || o.id.length > 80) return err('Ungültige Änderung.');
      if (ADMIN_ONLY.includes(o.sec) && !admin) return err('Dafür fehlt die Berechtigung.', 403);
      if (o.op === 'del') {
        if (o.sec === 'products' && !admin) return err('Dafür fehlt die Berechtigung.', 403);
        st.push(env.DB.prepare('INSERT INTO items(sec,id,data,upd,del) VALUES(?,?,NULL,?,1) ON CONFLICT(sec,id) DO UPDATE SET data=NULL,upd=excluded.upd,del=1').bind(o.sec, o.id, now));
      } else if (o.op === 'put' && o.data && typeof o.data === 'object') {
        const d = { ...o.data };
        if (o.sec === 'products' && !admin) {
          const old = await env.DB.prepare('SELECT data FROM items WHERE sec=? AND id=? AND del=0').bind('products', o.id).first();
          if (old && old.data) { const p = JSON.parse(old.data); d.price = p.price; d.changed = p.changed; d.unit = p.unit; }
        }
        const text = JSON.stringify(d);
        if (text.length > MAX_DATA) return err('Ein Eintrag ist zu groß (Foto verkleinern).', 413);
        st.push(env.DB.prepare('INSERT INTO items(sec,id,data,upd,del) VALUES(?,?,?,?,0) ON CONFLICT(sec,id) DO UPDATE SET data=excluded.data,upd=excluded.upd,del=0').bind(o.sec, o.id, text, now));
      } else return err('Ungültige Änderung.');
    }
    if (st.length) await env.DB.batch(st);
    return json({ ok: true, now });
  }

  if (path === '/api/next' && method === 'POST') {
    const k = body.k;
    if (k !== 'rn' && k !== 'qn') return err('Ungültig.');
    if (k === 'qn' && !admin) return err('Dafür fehlt die Berechtigung.', 403);
    const r = await env.DB.prepare('INSERT INTO counters(k,v) VALUES(?,1) ON CONFLICT(k) DO UPDATE SET v=v+1 RETURNING v').bind(k).first();
    return json({ n: r.v });
  }

  if (path === '/api/password' && method === 'POST') {
    const u = await env.DB.prepare('SELECT pw,salt FROM users WHERE id=?').bind(me.id).first();
    if (!same(await hashPw(String(body.old || ''), unb64(u.salt)), u.pw)) return err('Das alte Passwort stimmt nicht.', 403);
    if (!validPw(body.password)) return err('Neues Passwort: mindestens 8 Zeichen.');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    await env.DB.batch([
      env.DB.prepare('UPDATE users SET pw=?,salt=? WHERE id=?').bind(await hashPw(body.password, salt), b64(salt), me.id),
      env.DB.prepare('DELETE FROM sessions WHERE uid=? AND th<>?').bind(me.id, await sha(cookie(req, 'hp_s'))),
    ]);
    return json({ ok: true });
  }

  if (path.startsWith('/api/users')) {
    if (!admin) return err('Dafür fehlt die Berechtigung.', 403);
    const m = path.match(/^\/api\/users(?:\/(\d+))?$/);
    if (!m) return err('Nicht gefunden.', 404);
    const id = m[1] ? parseInt(m[1]) : null;
    if (!id && method === 'GET') return json({ users: (await env.DB.prepare('SELECT id,username,role,created FROM users ORDER BY username').all()).results });
    if (!id && method === 'POST') {
      if (!validName(body.username)) return err('Benutzername: 3 bis 32 Zeichen (Buchstaben, Zahlen, . _ -).');
      if (!validPw(body.password)) return err('Passwort: mindestens 8 Zeichen.');
      if (body.role !== 'admin' && body.role !== 'user') return err('Ungültige Rolle.');
      try { return json({ user: await createUser(env, body.username, body.password, body.role) }); }
      catch { return err('Diesen Benutzernamen gibt es schon.', 409); }
    }
    if (id && method === 'PATCH') {
      const t = await env.DB.prepare('SELECT id,role FROM users WHERE id=?').bind(id).first();
      if (!t) return err('Benutzer nicht gefunden.', 404);
      const st = [];
      if (body.role !== undefined) {
        if (body.role !== 'admin' && body.role !== 'user') return err('Ungültige Rolle.');
        if (t.role === 'admin' && body.role !== 'admin') {
          const n = (await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE role='admin'").first()).n;
          if (n <= 1) return err('Es muss mindestens einen Admin geben.', 409);
        }
        st.push(env.DB.prepare('UPDATE users SET role=? WHERE id=?').bind(body.role, id));
      }
      if (body.password !== undefined) {
        if (!validPw(body.password)) return err('Passwort: mindestens 8 Zeichen.');
        const salt = crypto.getRandomValues(new Uint8Array(16));
        st.push(env.DB.prepare('UPDATE users SET pw=?,salt=? WHERE id=?').bind(await hashPw(body.password, salt), b64(salt), id));
        st.push(env.DB.prepare('DELETE FROM sessions WHERE uid=?').bind(id));
      }
      if (st.length) await env.DB.batch(st);
      return json({ ok: true });
    }
    if (id && method === 'DELETE') {
      if (id === me.id) return err('Du kannst dich nicht selbst löschen.', 409);
      await env.DB.batch([env.DB.prepare('DELETE FROM sessions WHERE uid=?').bind(id), env.DB.prepare('DELETE FROM users WHERE id=?').bind(id)]);
      return json({ ok: true });
    }
  }
  return err('Nicht gefunden.', 404);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    try {
      await init(env);
      return await handle(req, env, url);
    } catch (e) {
      console.error(e);
      return err('Serverfehler. Bitte noch einmal versuchen.', 500);
    }
  },
};
