const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const JWT_SECRET = process.env.JWT_SECRET || 'steroid_jwt_secret_change_in_production';
const PORT = process.env.PORT || 3000;

// DATA_DIR is where the DB and uploads live.
// On Railway set DATA_DIR=/data and mount a volume there for persistence.
const DATA_DIR = process.env.DATA_DIR || __dirname;
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ─── Database ────────────────────────────────────────────────────────────────

const db = new Database(path.join(DATA_DIR, 'steroid.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    email         TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    is_admin      INTEGER DEFAULT 0,
    is_banned     INTEGER DEFAULT 0,
    ban_reason    TEXT,
    offense_count INTEGER DEFAULT 0,
    ban_expires_at DATETIME,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS rooms (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    code       TEXT    UNIQUE NOT NULL,
    name       TEXT    NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS room_members (
    room_id   INTEGER NOT NULL REFERENCES rooms(id),
    user_id   INTEGER NOT NULL REFERENCES users(id),
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (room_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id    INTEGER NOT NULL REFERENCES rooms(id),
    user_id    INTEGER NOT NULL REFERENCES users(id),
    content    TEXT,
    type       TEXT DEFAULT 'text',
    file_url   TEXT,
    file_name  TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Migrate existing databases that lack the new columns
try { db.exec('ALTER TABLE users ADD COLUMN offense_count INTEGER DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE users ADD COLUMN ban_expires_at DATETIME'); } catch {}

// ─── Offensive word filter ────────────────────────────────────────────────────

const OFFENSIVE_WORDS = [
  'nigger','nigga','faggot','fag','retard','spic','chink','kike','gook','wetback',
  'cunt','whore','slut','bitch','bastard','asshole','motherfucker','fuck you',
  'kill yourself','kys','die bitch','go die','piece of shit',
];

// Returns true if the text contains an offensive word/phrase
function isOffensive(text) {
  if (!text) return false;
  const lower = text.toLowerCase();
  return OFFENSIVE_WORDS.some(w => lower.includes(w));
}

const BAN_MESSAGE = 'You have been banned for saying offensive words.';
const ONE_DAY_MS  = 24 * 60 * 60 * 1000;

// Apply a 1-day ban (first offence) or permanent ban (repeat offence).
// Returns the updated user row.
function applyOffensiveBan(userId) {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  const offenses = (user.offense_count || 0) + 1;

  if (offenses === 1) {
    // First offence — 1-day temporary ban
    const expiresAt = new Date(Date.now() + ONE_DAY_MS).toISOString();
    db.prepare(`
      UPDATE users
      SET is_banned = 1, ban_reason = ?, offense_count = ?, ban_expires_at = ?
      WHERE id = ?
    `).run(BAN_MESSAGE, offenses, expiresAt, userId);
  } else {
    // Repeat offence — permanent ban
    db.prepare(`
      UPDATE users
      SET is_banned = 1, ban_reason = ?, offense_count = ?, ban_expires_at = NULL
      WHERE id = ?
    `).run(BAN_MESSAGE, offenses, userId);
  }

  return db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
}

// ─── File uploads ─────────────────────────────────────────────────────────────

const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: UPLOADS_DIR,
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
});

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use(cors());
app.use(express.json());
// Serve uploaded files from DATA_DIR/uploads/
app.use('/uploads', express.static(UPLOADS_DIR));
// Serve the frontend from public/
app.use(express.static(path.join(__dirname, 'public')));

function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized', message: 'No token provided' });
  }
  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.userId);
    if (!user) return res.status(401).json({ error: 'Unauthorized', message: 'User not found' });

    // Auto-lift expired temporary bans
    if (user.is_banned && user.ban_expires_at && new Date(user.ban_expires_at) <= new Date()) {
      db.prepare('UPDATE users SET is_banned = 0, ban_reason = NULL, ban_expires_at = NULL WHERE id = ?').run(user.id);
      user.is_banned = 0;
    }

    if (user.is_banned) {
      const expiry = user.ban_expires_at
        ? ` Expires: ${new Date(user.ban_expires_at).toLocaleString()}.`
        : ' This ban is permanent.';
      return res.status(403).json({ error: 'Banned', message: `${user.ban_reason}${expiry}` });
    }
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized', message: 'Invalid token' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user.is_admin) {
    return res.status(403).json({ error: 'Forbidden', message: 'Admin access required' });
  }
  next();
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sanitizeUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    is_admin: !!user.is_admin,
    is_banned: !!user.is_banned,
    ban_reason: user.ban_reason || null,
    created_at: user.created_at,
  };
}

function formatRoom(room) {
  const { c } = db.prepare('SELECT COUNT(*) as c FROM room_members WHERE room_id = ?').get(room.id);
  return { ...room, member_count: c };
}

function generateCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

function uniqueCode() {
  let code;
  do { code = generateCode(); } while (db.prepare('SELECT id FROM rooms WHERE code = ?').get(code));
  return code;
}

// ─── Auth routes ──────────────────────────────────────────────────────────────

app.post('/api/auth/register', (req, res) => {
  const { username, email, password } = req.body ?? {};

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'BadRequest', message: 'username, email, and password are required' });
  }
  if (username.length < 3 || username.length > 30) {
    return res.status(400).json({ error: 'BadRequest', message: 'Username must be 3–30 characters' });
  }
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return res.status(400).json({ error: 'BadRequest', message: 'Username may only contain letters, numbers, underscores' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'BadRequest', message: 'Password must be at least 6 characters' });
  }

  const exists = db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(email, username);
  if (exists) {
    return res.status(409).json({ error: 'Conflict', message: 'Email or username already taken' });
  }

  const hash = bcrypt.hashSync(password, 10);
  const { lastInsertRowid } = db.prepare(
    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
  ).run(username, email, hash);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(lastInsertRowid);
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.status(201).json({ token, user: sanitizeUser(user) });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password) {
    return res.status(400).json({ error: 'BadRequest', message: 'email and password are required' });
  }

  let user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Unauthorized', message: 'Invalid email or password' });
  }
  // Auto-lift expired temporary bans on login
  if (user.is_banned && user.ban_expires_at && new Date(user.ban_expires_at) <= new Date()) {
    db.prepare('UPDATE users SET is_banned = 0, ban_reason = NULL, ban_expires_at = NULL WHERE id = ?').run(user.id);
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
  }

  if (user.is_banned) {
    const expiry = user.ban_expires_at
      ? ` Expires: ${new Date(user.ban_expires_at).toLocaleString()}.`
      : ' This ban is permanent.';
    return res.status(403).json({ error: 'Banned', message: `${user.ban_reason}${expiry}` });
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: sanitizeUser(user) });
});

app.post('/api/auth/logout', authenticate, (_req, res) => {
  res.json({ message: 'Logged out' });
});

// ─── User routes ──────────────────────────────────────────────────────────────

app.get('/api/users/me', authenticate, (req, res) => {
  res.json(sanitizeUser(req.user));
});

// ─── Room routes ──────────────────────────────────────────────────────────────

app.get('/api/rooms', authenticate, (req, res) => {
  const rows = db.prepare(`
    SELECT r.* FROM rooms r
    JOIN room_members rm ON r.id = rm.room_id
    WHERE rm.user_id = ?
    ORDER BY r.created_at DESC
  `).all(req.user.id);
  res.json(rows.map(formatRoom));
});

app.post('/api/rooms', authenticate, (req, res) => {
  const { name } = req.body ?? {};
  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'BadRequest', message: 'name is required' });
  }

  const code = uniqueCode();
  const { lastInsertRowid } = db.prepare(
    'INSERT INTO rooms (code, name, created_by) VALUES (?, ?, ?)'
  ).run(code, name.trim(), req.user.id);

  db.prepare('INSERT INTO room_members (room_id, user_id) VALUES (?, ?)').run(lastInsertRowid, req.user.id);
  const room = db.prepare('SELECT * FROM rooms WHERE id = ?').get(lastInsertRowid);
  res.status(201).json(formatRoom(room));
});

app.get('/api/rooms/:code', authenticate, (req, res) => {
  const room = db.prepare('SELECT * FROM rooms WHERE code = ?').get(req.params.code.toUpperCase());
  if (!room) return res.status(404).json({ error: 'NotFound', message: 'Room not found' });
  res.json(formatRoom(room));
});

app.post('/api/rooms/:code/join', authenticate, (req, res) => {
  const room = db.prepare('SELECT * FROM rooms WHERE code = ?').get(req.params.code.toUpperCase());
  if (!room) return res.status(404).json({ error: 'NotFound', message: 'Room not found' });

  const already = db.prepare('SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?').get(room.id, req.user.id);
  if (!already) {
    db.prepare('INSERT INTO room_members (room_id, user_id) VALUES (?, ?)').run(room.id, req.user.id);
  }

  res.json(formatRoom(room));
});

// ─── Message routes ───────────────────────────────────────────────────────────

app.get('/api/rooms/:code/messages', authenticate, (req, res) => {
  const room = db.prepare('SELECT * FROM rooms WHERE code = ?').get(req.params.code.toUpperCase());
  if (!room) return res.status(404).json({ error: 'NotFound', message: 'Room not found' });

  const member = db.prepare('SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?').get(room.id, req.user.id);
  if (!member) return res.status(403).json({ error: 'Forbidden', message: 'Not a member of this room' });

  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const before = req.query.before ? parseInt(req.query.before) : null;

  const messages = db.prepare(`
    SELECT m.*, u.username FROM messages m
    JOIN users u ON m.user_id = u.id
    WHERE m.room_id = ? ${before ? 'AND m.id < ?' : ''}
    ORDER BY m.created_at DESC
    LIMIT ?
  `).all(...(before ? [room.id, before, limit] : [room.id, limit])).reverse();

  res.json(messages);
});

app.post('/api/rooms/:code/messages', authenticate, upload.single('file'), (req, res) => {
  const room = db.prepare('SELECT * FROM rooms WHERE code = ?').get(req.params.code.toUpperCase());
  if (!room) return res.status(404).json({ error: 'NotFound', message: 'Room not found' });

  const member = db.prepare('SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?').get(room.id, req.user.id);
  if (!member) return res.status(403).json({ error: 'Forbidden', message: 'Not a member of this room' });

  let { content, type = 'text', link_url } = req.body ?? {};
  let fileUrl = null;
  let fileName = null;

  if (req.file) {
    fileUrl = `/uploads/${req.file.filename}`;
    fileName = req.file.originalname;
    type = req.file.mimetype.startsWith('image/') ? 'image' : 'file';
  } else if (type === 'link' && link_url) {
    fileUrl = link_url;
  }

  if (!content && !fileUrl) {
    return res.status(400).json({ error: 'BadRequest', message: 'Provide content or a file/link' });
  }

  // ── Offensive content check ──────────────────────────────────────────────────
  if (isOffensive(content)) {
    const updated = applyOffensiveBan(req.user.id);
    const isPermanent = !updated.ban_expires_at;
    const extra = isPermanent
      ? ' This is a permanent ban.'
      : ` You are banned for 1 day. Expires: ${new Date(updated.ban_expires_at).toLocaleString()}.`;
    return res.status(403).json({
      error: 'Banned',
      message: BAN_MESSAGE + extra,
    });
  }

  const { lastInsertRowid } = db.prepare(`
    INSERT INTO messages (room_id, user_id, content, type, file_url, file_name)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(room.id, req.user.id, content || null, type, fileUrl, fileName);

  const message = db.prepare(`
    SELECT m.*, u.username FROM messages m
    JOIN users u ON m.user_id = u.id
    WHERE m.id = ?
  `).get(lastInsertRowid);

  io.to(`room:${room.code}`).emit('message', message);
  res.status(201).json(message);
});

// ─── Admin routes ─────────────────────────────────────────────────────────────

app.post('/api/admin/users/:userId/ban', authenticate, requireAdmin, (req, res) => {
  const { reason } = req.body ?? {};
  if (!reason) return res.status(400).json({ error: 'BadRequest', message: 'reason is required' });

  const user = db.prepare('SELECT id FROM users WHERE id = ?').get(req.params.userId);
  if (!user) return res.status(404).json({ error: 'NotFound', message: 'User not found' });

  db.prepare('UPDATE users SET is_banned = 1, ban_reason = ? WHERE id = ?').run(reason, req.params.userId);
  res.json({ message: 'User banned' });
});

app.delete('/api/admin/users/:userId/ban', authenticate, requireAdmin, (req, res) => {
  db.prepare('UPDATE users SET is_banned = 0, ban_reason = NULL WHERE id = ?').run(req.params.userId);
  res.json({ message: 'User unbanned' });
});

// ─── Online presence & WebRTC signaling ──────────────────────────────────────

// userId -> socketId  (one active socket per user)
const onlineUsers = new Map();
// roomCode -> Set<userId>
const roomOnline = new Map();

function emitRoomOnline(code) {
  const ids = Array.from(roomOnline.get(code) || []);
  const users = ids
    .map(id => db.prepare('SELECT id, username FROM users WHERE id = ?').get(id))
    .filter(Boolean);
  io.to(`room:${code}`).emit('room-online-users', users);
}

// ─── Socket.IO ────────────────────────────────────────────────────────────────

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.userId);
    if (!user || user.is_banned) return next(new Error('Unauthorized'));
    socket.user = user;
    next();
  } catch {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  onlineUsers.set(socket.user.id, socket.id);

  // ── Room presence ──────────────────────────────
  socket.on('join-room', (code) => {
    const room = db.prepare('SELECT * FROM rooms WHERE code = ?').get(code);
    if (!room) return;
    const member = db.prepare('SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?').get(room.id, socket.user.id);
    if (!member) return;

    socket.join(`room:${code}`);

    if (!roomOnline.has(code)) roomOnline.set(code, new Set());
    roomOnline.get(code).add(socket.user.id);
    emitRoomOnline(code);
  });

  socket.on('leave-room', (code) => {
    socket.leave(`room:${code}`);
    if (roomOnline.has(code)) {
      roomOnline.get(code).delete(socket.user.id);
      emitRoomOnline(code);
    }
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(socket.user.id);
    roomOnline.forEach((set, code) => {
      if (set.has(socket.user.id)) {
        set.delete(socket.user.id);
        emitRoomOnline(code);
      }
    });
  });

  // ── WebRTC signaling ───────────────────────────

  // Caller → target: request a call
  socket.on('call-request', ({ targetUserId, offer }) => {
    const targetSocket = onlineUsers.get(targetUserId);
    if (!targetSocket) return socket.emit('call-unavailable');
    io.to(targetSocket).emit('incoming-call', {
      from: { id: socket.user.id, username: socket.user.username },
      offer,
    });
  });

  // Callee → caller: accepted, here is the answer
  socket.on('call-accepted', ({ targetUserId, answer }) => {
    const targetSocket = onlineUsers.get(targetUserId);
    if (targetSocket) io.to(targetSocket).emit('call-accepted', { answer });
  });

  // Callee → caller: declined
  socket.on('call-declined', ({ targetUserId }) => {
    const targetSocket = onlineUsers.get(targetUserId);
    if (targetSocket) io.to(targetSocket).emit('call-declined', { username: socket.user.username });
  });

  // Either side → other: ICE candidate
  socket.on('ice-candidate', ({ targetUserId, candidate }) => {
    const targetSocket = onlineUsers.get(targetUserId);
    if (targetSocket) io.to(targetSocket).emit('ice-candidate', { candidate });
  });

  // Either side: end the call
  socket.on('call-ended', ({ targetUserId }) => {
    const targetSocket = onlineUsers.get(targetUserId);
    if (targetSocket) io.to(targetSocket).emit('call-ended', { username: socket.user.username });
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  Steroid Chat is running → http://0.0.0.0:${PORT}\n`);
});
