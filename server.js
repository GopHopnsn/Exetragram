/**
 * Exetragram Server — full control messenger backend
 * REST + WebSocket, file storage (data.json)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = Number(process.env.EX_PORT || process.env.PORT || 3456);
const DB_FILE = path.join(__dirname, 'data.json');
const SECRET = process.env.JWT_SECRET || 'exetragram-secret-change-me-in-production';

function load() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { users: {}, chats: {}, messages: {}, seq: 1 }; }
}
function save() {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(db)); } catch (e) { console.error('save', e.message); }
}
let db = load();

const id = () => crypto.randomBytes(8).toString('hex');
const hash = (pw) => crypto.createHash('sha256').update(pw + SECRET).digest('hex');
function token(userId) {
  const payload = Buffer.from(JSON.stringify({ userId, exp: Date.now() + 30 * 864e5 })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function verify(tok) {
  if (!tok) return null;
  const [payload, sig] = String(tok).split('.');
  if (!payload || !sig) return null;
  const expect = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  if (sig !== expect) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (data.exp < Date.now()) return null;
    return data.userId;
  } catch { return null; }
}

function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    username: u.username,
    name: u.name,
    bio: u.bio || '',
    phone: u.phone || '',
    avatarUrl: u.avatarUrl || '',
    color: u.color || '#c0605a',
    color2: u.color2 || '',
    pattern: u.pattern || '★',
    accent: u.accent || '#2aabee',
    isVerified: !!u.isVerified,
    isMajor: !!u.isMajor,
    isOfficial: !!u.isOfficial,
    isPremium: !!u.isPremium,
    isOwner: !!u.isOwner,
    isAdmin: !!u.isAdmin,
    stars: u.stars || 0,
    status: online.has(u.id) ? 'online' : (u.lastSeenAt || null),
    lastSeenAt: u.lastSeenAt || null,
  };
}

function ensureSeed() {
  if (Object.keys(db.users).length) return;
  const ownerId = id(), alinaId = id(), demoId = id();
  db.users[ownerId] = {
    id: ownerId, username: 'owner', name: 'Owner', bio: 'Владелец Exetragram',
    passwordHash: hash('password123'), color: '#5b4b8a', color2: '#2a1f4a', pattern: '★',
    isOwner: true, isAdmin: true, isPremium: true, isVerified: true, stars: 10000,
    phone: '+7 900 000-00-01',
  };
  db.users[alinaId] = {
    id: alinaId, username: 'alina', name: 'Алина', bio: 'Тестовый собеседник',
    passwordHash: hash('password123'), color: '#4a6cf0', pattern: '❄',
    isVerified: true, stars: 500, phone: '+7 900 555-01-02',
  };
  db.users[demoId] = {
    id: demoId, username: 'demo', name: 'Demo User', bio: 'Демо-аккаунт',
    passwordHash: hash('password123'), color: '#2aabee', pattern: '✈',
    stars: 100,
  };
  const c1 = id(), c2 = id();
  db.chats[c1] = { id: c1, type: 'PRIVATE', members: [ownerId, alinaId], createdAt: new Date().toISOString() };
  db.chats[c2] = { id: c2, type: 'PRIVATE', members: [ownerId, demoId], createdAt: new Date().toISOString() };
  const now = Date.now();
  [
    { chatId: c1, authorId: alinaId, text: 'Привет! Это Exetragram на своём сервере 🚀', t: now - 120000 },
    { chatId: c1, authorId: ownerId, text: 'Отлично, всё под нашим контролем', t: now - 60000 },
    { chatId: c2, authorId: demoId, text: 'Напиши что-нибудь — проверим WebSocket', t: now - 30000 },
  ].forEach((m) => {
    const mid = id();
    db.messages[mid] = {
      id: mid, chatId: m.chatId, authorId: m.authorId, text: m.text, type: 'TEXT',
      createdAt: new Date(m.t).toISOString(),
    };
  });
  save();
  console.log('Seed: owner / alina / demo  — password: password123');
}
ensureSeed();

const online = new Map();

function broadcast(userId, payload) {
  const set = online.get(userId);
  if (!set) return;
  const data = JSON.stringify(payload);
  for (const ws of set) if (ws.readyState === 1) ws.send(data);
}
function broadcastChat(chatId, payload) {
  const chat = db.chats[chatId];
  if (!chat) return;
  for (const uid of chat.members) broadcast(uid, payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let buf = '';
    req.on('data', (c) => { buf += c; if (buf.length > 2e6) reject(new Error('too large')); });
    req.on('end', () => { try { resolve(buf ? JSON.parse(buf) : {}); } catch { reject(new Error('Invalid JSON')); } });
  });
}
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
  });
  res.end(body);
}
function getAuth(req) {
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ')) return verify(h.slice(7));
  return null;
}
function requireUser(req, res) {
  const uid = getAuth(req);
  if (!uid || !db.users[uid]) { send(res, 401, { error: 'Unauthorized' }); return null; }
  return uid;
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
    });
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;

  try {
    if (p === '/' || p === '/index.html' || p === '/app' || p === '/test') {
      const file = path.join(__dirname, 'client.html');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      return res.end(fs.readFileSync(file, 'utf8'));
    }
    if (p === '/manifest.json') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        name: 'Exetragram', short_name: 'Exetragram', start_url: '/', display: 'standalone',
        background_color: '#000000', theme_color: '#000000',
        icons: [{ src: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect fill="%232aabee" width="100" height="100" rx="22"/><text y="68" x="50" text-anchor="middle" font-size="52">✈</text></svg>', sizes: '512x512', type: 'image/svg+xml' }],
      }));
    }
    if (p === '/download.zip' || p === '/exetragram-github.zip') {
      const z = path.join(__dirname, 'exetragram-github.zip');
      if (!fs.existsSync(z)) return send(res, 404, { error: 'zip not found' });
      res.writeHead(200, {
        'Content-Type': 'application/zip',
        'Content-Disposition': 'attachment; filename="exetragram-github.zip"',
        'Access-Control-Allow-Origin': '*',
      });
      return res.end(fs.readFileSync(z));
    }
    if (p === '/health') return send(res, 200, { ok: true, name: 'Exetragram', users: Object.keys(db.users).length });

    // ---- AUTH ----
    if (p === '/auth/register' && req.method === 'POST') {
      const body = await readBody(req);
      const username = String(body.username || '').toLowerCase().replace(/[^a-z0-9_]/g, '');
      const name = String(body.name || '').trim().slice(0, 64);
      const password = String(body.password || '');
      if (username.length < 3 || name.length < 1 || password.length < 6)
        return send(res, 400, { error: 'Проверьте поля (логин ≥3, пароль ≥6)' });
      if (Object.values(db.users).some((u) => u.username === username))
        return send(res, 409, { error: 'Юзернейм занят' });
      const uid = id();
      const colors = ['#c0605a', '#4a6cf0', '#2aabee', '#4fae4e', '#e8a33d', '#7b6cf0', '#ee6fa0'];
      db.users[uid] = {
        id: uid, username, name, bio: '', passwordHash: hash(password),
        color: colors[Math.floor(Math.random() * colors.length)], pattern: '★', stars: 100,
        createdAt: new Date().toISOString(),
      };
      save();
      const tok = token(uid);
      return send(res, 201, { user: publicUser(db.users[uid]), accessToken: tok, refreshToken: tok });
    }

    if (p === '/auth/login' && req.method === 'POST') {
      const body = await readBody(req);
      const login = String(body.login || '').toLowerCase().trim();
      const password = String(body.password || '');
      const user = Object.values(db.users).find(
        (u) => u.username === login || u.phone === body.login || u.email === login
      );
      if (!user || user.passwordHash !== hash(password))
        return send(res, 401, { error: 'Неверный логин или пароль' });
      user.lastSeenAt = new Date().toISOString();
      save();
      const tok = token(user.id);
      return send(res, 200, { user: publicUser(user), accessToken: tok, refreshToken: tok });
    }

    if (p === '/auth/me' && req.method === 'GET') {
      const uid = requireUser(req, res); if (!uid) return;
      return send(res, 200, { user: publicUser(db.users[uid]) });
    }

    // ---- USERS ----
    if (p === '/users/search' && req.method === 'GET') {
      const uid = requireUser(req, res); if (!uid) return;
      const q = String(url.searchParams.get('q') || '').toLowerCase().replace(/^@/, '');
      if (q.length < 1) return send(res, 200, { users: [] });
      const users = Object.values(db.users)
        .filter((u) => u.id !== uid && (u.username.includes(q) || u.name.toLowerCase().includes(q)))
        .slice(0, 30)
        .map(publicUser);
      return send(res, 200, { users });
    }

    if (p === '/users/me' && req.method === 'PATCH') {
      const uid = requireUser(req, res); if (!uid) return;
      const body = await readBody(req);
      const u = db.users[uid];
      if (body.name != null) u.name = String(body.name).slice(0, 64);
      if (body.bio != null) u.bio = String(body.bio).slice(0, 500);
      if (body.color != null) u.color = String(body.color);
      if (body.pattern != null) u.pattern = String(body.pattern).slice(0, 4);
      if (body.accent != null) u.accent = String(body.accent);
      if (body.username != null) {
        const un = String(body.username).toLowerCase().replace(/[^a-z0-9_]/g, '');
        if (un.length >= 3 && !Object.values(db.users).some((x) => x.username === un && x.id !== uid))
          u.username = un;
        else if (un.length >= 3) return send(res, 409, { error: 'Юзернейм занят' });
      }
      save();
      return send(res, 200, { user: publicUser(u) });
    }

    if (p.startsWith('/users/') && req.method === 'GET') {
      const uid = requireUser(req, res); if (!uid) return;
      const key = decodeURIComponent(p.slice(7)).replace(/^@/, '');
      const user = Object.values(db.users).find((u) => u.id === key || u.username === key.toLowerCase());
      if (!user) return send(res, 404, { error: 'Не найден' });
      return send(res, 200, { user: publicUser(user) });
    }

    // ---- CHATS ----
    if (p === '/chats' && req.method === 'GET') {
      const uid = requireUser(req, res); if (!uid) return;
      const list = Object.values(db.chats)
        .filter((c) => c.members.includes(uid))
        .map((c) => {
          let title = c.title, peer = null, color = '#2aabee', pattern = '★';
          if (c.type === 'PRIVATE') {
            const otherId = c.members.find((m) => m !== uid);
            const other = db.users[otherId];
            peer = publicUser(other);
            title = other?.name || 'Чат';
            color = other?.color || color;
            pattern = other?.pattern || pattern;
          }
          const msgs = Object.values(db.messages)
            .filter((m) => m.chatId === c.id && !m.deletedAt)
            .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
          const last = msgs[0];
          return {
            id: c.id, type: c.type, title, peer, color, pattern,
            lastMessage: last ? {
              id: last.id, text: last.text, type: last.type,
              createdAt: last.createdAt, authorId: last.authorId,
              authorName: db.users[last.authorId]?.name,
            } : null,
          };
        })
        .sort((a, b) => {
          const ta = a.lastMessage ? new Date(a.lastMessage.createdAt).getTime() : 0;
          const tb = b.lastMessage ? new Date(b.lastMessage.createdAt).getTime() : 0;
          return tb - ta;
        });
      return send(res, 200, { chats: list });
    }

    if (p === '/chats/private' && req.method === 'POST') {
      const uid = requireUser(req, res); if (!uid) return;
      const body = await readBody(req);
      const otherId = body.userId;
      if (!db.users[otherId]) return send(res, 404, { error: 'Пользователь не найден' });
      if (otherId === uid) return send(res, 400, { error: 'Нельзя писать себе' });
      let chat = Object.values(db.chats).find(
        (c) => c.type === 'PRIVATE' && c.members.includes(uid) && c.members.includes(otherId)
      );
      if (!chat) {
        chat = { id: id(), type: 'PRIVATE', members: [uid, otherId], createdAt: new Date().toISOString() };
        db.chats[chat.id] = chat;
        save();
      }
      return send(res, 200, { chatId: chat.id });
    }

    if (p.match(/^\/chats\/[^/]+\/messages$/) && req.method === 'GET') {
      const uid = requireUser(req, res); if (!uid) return;
      const chatId = p.split('/')[2];
      const chat = db.chats[chatId];
      if (!chat || !chat.members.includes(uid)) return send(res, 403, { error: 'Нет доступа' });
      const limit = Math.min(Number(url.searchParams.get('limit')) || 80, 200);
      const messages = Object.values(db.messages)
        .filter((m) => m.chatId === chatId && !m.deletedAt)
        .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
        .slice(-limit)
        .map((m) => ({
          id: m.id, chatId: m.chatId, type: m.type || 'TEXT', text: m.text,
          author: publicUser(db.users[m.authorId]),
          replyTo: m.replyToId ? (() => {
            const r = db.messages[m.replyToId];
            return r ? { id: r.id, text: r.text, authorName: db.users[r.authorId]?.name } : null;
          })() : null,
          isEdited: !!m.isEdited,
          createdAt: m.createdAt,
        }));
      return send(res, 200, { messages });
    }

    send(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error(e);
    send(res, 500, { error: 'Server error' });
  }
});

const wss = new WebSocketServer({ server, path: '/ws' });
wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const userId = verify(url.searchParams.get('token'));
  if (!userId || !db.users[userId]) { ws.close(4001, 'Unauthorized'); return; }

  if (!online.has(userId)) online.set(userId, new Set());
  online.get(userId).add(ws);
  db.users[userId].lastSeenAt = new Date().toISOString();
  ws.send(JSON.stringify({ event: 'connected', userId, user: publicUser(db.users[userId]) }));

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }
    const { event, data } = msg;

    if (event === 'ping') {
      ws.send(JSON.stringify({ event: 'pong', ts: Date.now() }));
      return;
    }

    if (event === 'message.send') {
      const chatId = data?.chatId;
      const text = String(data?.text || '').trim().slice(0, 4096);
      const chat = db.chats[chatId];
      if (!chat || !chat.members.includes(userId) || !text) {
        ws.send(JSON.stringify({ event: 'error', message: 'Не удалось отправить' }));
        return;
      }
      const message = {
        id: id(), chatId, authorId: userId, text, type: 'TEXT',
        replyToId: data.replyToId || null,
        createdAt: new Date().toISOString(),
      };
      db.messages[message.id] = message;
      save();
      const payload = {
        event: 'message.new',
        data: {
          id: message.id, chatId, type: 'TEXT', text: message.text,
          author: publicUser(db.users[userId]),
          replyTo: null,
          createdAt: message.createdAt,
        },
      };
      broadcastChat(chatId, payload);
      return;
    }

    if (event === 'typing') {
      const chat = db.chats[data?.chatId];
      if (!chat) return;
      for (const uid of chat.members) {
        if (uid !== userId)
          broadcast(uid, { event: 'typing', data: { chatId: data.chatId, userId, name: db.users[userId]?.name } });
      }
    }
  });

  ws.on('close', () => {
    const set = online.get(userId);
    if (set) {
      set.delete(ws);
      if (!set.size) {
        online.delete(userId);
        if (db.users[userId]) {
          db.users[userId].lastSeenAt = new Date().toISOString();
          save();
        }
      }
    }
  });
});

server.listen(PORT, () => {
  console.log('');
  console.log('🚀 Exetragram: http://localhost:' + PORT + '/');
  console.log('   owner / alina / demo  —  password123');
  console.log('');
});
