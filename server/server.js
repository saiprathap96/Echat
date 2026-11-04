import 'dotenv/config';
import express from 'express'; import http from 'http'; import mongoose from 'mongoose';
import { Server } from 'socket.io'; import jwt from 'jsonwebtoken'; import bcrypt from 'bcrypt';
import helmet from 'helmet'; import cors from 'cors'; import rateLimit from 'express-rate-limit'; import { z } from 'zod';

const { PORT = 4000, MONGODB_URI, JWT_SECRET, CLIENT_URL = 'http://localhost:5173', NODE_ENV } = process.env;
if (!JWT_SECRET || !MONGODB_URI) throw new Error('Set JWT_SECRET and MONGODB_URI in .env');

// ---- Models: only PUBLIC keys and ciphertext are ever stored ----
const User = mongoose.model('User', new mongoose.Schema({
  name: String, username: { type: String, unique: true, lowercase: true }, email: { type: String, unique: true, lowercase: true },
  passwordHash: String, identityPublicKey: Object, lastSeen: Date,
}, { timestamps: true }));
const msgSchema = new mongoose.Schema({
  conversationId: String, senderId: mongoose.Types.ObjectId, recipientId: mongoose.Types.ObjectId,
  encryptedPayload: String, nonce: String, clientId: String, deliveryStatus: { type: String, default: 'sent' },
}, { timestamps: true });
msgSchema.index({ conversationId: 1, createdAt: -1 });
msgSchema.index({ senderId: 1, clientId: 1 }, { unique: true }); // duplicate prevention
const Message = mongoose.model('Message', msgSchema);
const convId = (a, b) => [String(a), String(b)].sort().join(':');

const app = express();
app.use(helmet(), cors({ origin: CLIENT_URL }), express.json({ limit: '100kb' }));
app.get('/api/health', (req, res) => res.json({ ok: true }));
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);
const sign = (u) => jwt.sign({ sub: String(u._id) }, JWT_SECRET, { expiresIn: '7d' });
const auth = (req, res, next) => {
  try { req.uid = jwt.verify((req.headers.authorization || '').slice(7), JWT_SECRET).sub; next(); }
  catch { res.status(401).json({ error: 'Unauthorized' }); }
};
const pub = (u) => ({ id: u._id, name: u.name, username: u.username, identityPublicKey: u.identityPublicKey });

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20 });
const reg = z.object({ name: z.string().min(1).max(60), username: z.string().regex(/^[a-z0-9_]{3,20}$/i),
  email: z.string().email(), password: z.string().min(8).max(100), identityPublicKey: z.object({}).passthrough() });

app.post('/api/auth/register', limiter, wrap(async (req, res) => {
  const { password, ...d } = reg.parse(req.body);
  const u = await User.create({ ...d, passwordHash: await bcrypt.hash(password, 12) });
  res.json({ token: sign(u), user: pub(u) });
}));
app.post('/api/auth/login', limiter, wrap(async (req, res) => {
  const { login, password } = z.object({ login: z.string(), password: z.string() }).parse(req.body);
  const u = await User.findOne({ $or: [{ email: login.toLowerCase() }, { username: login.toLowerCase() }] });
  if (!u || !(await bcrypt.compare(password, u.passwordHash))) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ token: sign(u), user: pub(u) });
}));
app.get('/api/users/me', auth, wrap(async (req, res) => res.json(pub(await User.findById(req.uid)))));
app.get('/api/users/search', auth, wrap(async (req, res) => {
  const q = String(req.query.q || '').toLowerCase().replace(/[^a-z0-9_]/g, '');
  const filter = { _id: { $ne: req.uid } };
  if (q.length > 0) filter.username = new RegExp('^' + q);
  const us = await User.find(filter).limit(20);
  res.json(us.map(pub));
}));
app.get('/api/keys/:userId', auth, wrap(async (req, res) => {
  const u = await User.findById(req.params.userId); if (!u) return res.sendStatus(404);
  res.json({ identityPublicKey: u.identityPublicKey });
}));
app.get('/api/messages/:peerId', auth, wrap(async (req, res) => {
  const q = { conversationId: convId(req.uid, req.params.peerId) };
  if (req.query.before) q.createdAt = { $lt: new Date(req.query.before) };
  res.json((await Message.find(q).sort({ createdAt: -1 }).limit(30)).reverse());
}));
app.use((err, req, res, next) => {
  if (err.name === 'ZodError') return res.status(400).json({ error: 'Invalid input' });
  if (err.code === 11000) return res.status(409).json({ error: 'Already exists' });
  if (NODE_ENV !== 'production') console.error(err.message);
  res.status(500).json({ error: 'Server error' });
});

// ---- Socket.IO: server relays ciphertext only ----
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: CLIENT_URL } });
const online = new Map();
io.use((s, next) => { try { s.uid = jwt.verify(s.handshake.auth.token, JWT_SECRET).sub; next(); } catch { next(new Error('unauthorized')); } });
io.on('connection', (s) => {
  const me = s.uid; s.join('u:' + me);
  online.set(me, (online.get(me) || 0) + 1);
  io.emit('user_status_changed', { userId: me, online: true });
  s.emit('online_list', [...online.keys()]);
  s.on('send_message', async ({ to, encryptedPayload, nonce, clientId }, ack) => {
    try {
      const v = z.object({ to: z.string().length(24), encryptedPayload: z.string().max(20000), nonce: z.string().max(64), clientId: z.string().max(64) })
        .parse({ to, encryptedPayload, nonce, clientId });
      if (!(await User.exists({ _id: v.to }))) throw new Error('no user');
      const m = await Message.create({ conversationId: convId(me, v.to), senderId: me, recipientId: v.to, ...v });
      io.to('u:' + v.to).emit('receive_message', m);
      ack?.({ ok: true, message: m });
    } catch (e) { ack?.({ ok: false, error: e.code === 11000 ? 'duplicate' : 'failed' }); }
  });
  s.on('mark_read', async ({ peerId }) => {
    await Message.updateMany({ senderId: peerId, recipientId: me, deliveryStatus: { $ne: 'read' } }, { deliveryStatus: 'read' });
    io.to('u:' + peerId).emit('message_read', { by: me });
  });
  s.on('mark_delivered', async ({ id }) => {
    const m = await Message.findOneAndUpdate({ _id: id, recipientId: me, deliveryStatus: 'sent' }, { deliveryStatus: 'delivered' });
    if (m) io.to('u:' + m.senderId).emit('message_delivered', { id });
  });
  s.on('typing', ({ to }) => io.to('u:' + to).emit('user_typing', { userId: me }));
  s.on('stop_typing', ({ to }) => io.to('u:' + to).emit('user_stopped_typing', { userId: me }));
  s.on('disconnect', async () => {
    const n = (online.get(me) || 1) - 1;
    if (n) return online.set(me, n);
    online.delete(me); await User.updateOne({ _id: me }, { lastSeen: new Date() });
    io.emit('user_status_changed', { userId: me, online: false });
  });
});
let dbUri = MONGODB_URI;
try {
  await mongoose.connect(dbUri, { serverSelectionTimeoutMS: 2500 });
} catch (err) {
  console.log(`Could not connect to ${MONGODB_URI}, starting embedded in-memory MongoDB...`);
  const { MongoMemoryServer } = await import('mongodb-memory-server');
  const mongod = await MongoMemoryServer.create();
  dbUri = mongod.getUri();
  await mongoose.connect(dbUri);
  console.log(`Connected to in-memory MongoDB at ${dbUri}`);
}
server.listen(PORT, () => console.log('SecureChat server on http://localhost:' + PORT));
