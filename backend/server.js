require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const { MongoClient } = require('mongodb');
const { OAuth2Client } = require('google-auth-library');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const FRONTEND_DIR = path.resolve(__dirname, '..', 'public');
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.MONGODB_DB || 'team_secret_store';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const ADMIN_MAX_LOGIN_ATTEMPTS = clampInt(process.env.ADMIN_MAX_LOGIN_ATTEMPTS, 5, 3, 20);
const ADMIN_LOCK_MINUTES = clampInt(process.env.ADMIN_LOCK_MINUTES, 15, 1, 1440);
const API_RATE_LIMIT_PER_MINUTE = clampInt(process.env.API_RATE_LIMIT_PER_MINUTE, 180, 30, 5000);
const AUTH_RATE_LIMIT_PER_15_MIN = clampInt(process.env.AUTH_RATE_LIMIT_PER_15_MIN, 20, 5, 500);
const ORDER_RATE_LIMIT_PER_10_MIN = clampInt(process.env.ORDER_RATE_LIMIT_PER_10_MIN, 10, 2, 200);
const ADMIN_READ_PAGE_SIZE = clampInt(process.env.ADMIN_READ_PAGE_SIZE, 50, 10, 100);
const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || '')
  .split(',')
  .map(v => v.trim().replace(/\/$/, ''))
  .filter(Boolean);

if (!MONGODB_URI) throw new Error('MONGODB_URI is required');
if (!ADMIN_PASSWORD) throw new Error('ADMIN_PASSWORD is required');
if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 characters');
if (FRONTEND_ORIGINS.length === 0) throw new Error('FRONTEND_ORIGINS is required and must contain your exact storefront origin');

const app = express();
const mongo = new MongoClient(MONGODB_URI, {
  maxPoolSize: 20,
  minPoolSize: 0,
  serverSelectionTimeoutMS: 8000,
  connectTimeoutMS: 8000,
  socketTimeoutMS: 15000
});
let db;
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

const DEFAULT_PRODUCTS = [
  {id:'p1', title:'Class 12 Physics — Full Notes', subject:'Physics', type:'handwritten', price:149, description:'Chapter-wise handwritten notes covering the entire CBSE Class 12 Physics syllabus.', file:'#'},
  {id:'p2', title:'Organic Chemistry Crash Guide', subject:'Chemistry', type:'guide', price:199, description:'A compact revision guide for organic chemistry reactions and mechanisms.', file:'#'},
  {id:'p3', title:'Data Structures E-book', subject:'Computer Science', type:'ebook', price:249, description:'Beginner-friendly e-book on arrays, trees, graphs and common interview problems.', file:'#'},
  {id:'p4', title:'UPSC Essay Answer Templates', subject:'UPSC', type:'template', price:99, description:'Ready-to-adapt structures for scoring well in the essay paper.', file:'#'}
];

// Cloudflare Tunnel is the only intended public path. One trusted proxy hop lets
// Express see the visitor IP supplied by cloudflared while the app stays on 127.0.0.1.
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(helmet({
  crossOriginResourcePolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'", "'unsafe-inline'", 'https://accounts.google.com'],
      "style-src": ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      "font-src": ["'self'", 'https://fonts.gstatic.com', 'data:'],
      "img-src": ["'self'", 'data:', 'https:'],
      "connect-src": ["'self'", 'https://accounts.google.com', 'https://*.googleapis.com'],
      "frame-src": ['https://accounts.google.com'],
      "object-src": ["'none'"],
      "base-uri": ["'self'"],
      "form-action": ["'self'"],
      "frame-ancestors": ["'none'"]
    }
  }
}));
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), usb=()');
  next();
});

// Keep request bodies deliberately small. This stops giant-text/body attacks
// before route code, bcrypt, or MongoDB ever see the payload.
app.use(express.json({ limit: '32kb', strict: true, inflate: false }));
app.use(express.urlencoded({ extended: false, limit: '16kb', parameterLimit: 50, inflate: false }));

// Reject object keys commonly used for prototype pollution / NoSQL operator injection.
app.use((req, res, next) => {
  if (req.body && hasUnsafeStructure(req.body)) {
    return res.status(400).json({ error: 'Invalid request structure' });
  }
  next();
});

app.use(cors({
  origin(origin, callback) {
    // Requests from the same page normally need no CORS header. CLI/server calls
    // often have no Origin, so they are allowed; browser origins must match exactly.
    if (!origin || FRONTEND_ORIGINS.includes(origin.replace(/\/$/, ''))) {
      return callback(null, true);
    }
    return callback(httpError(403, 'Origin not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// JSON mutation endpoints only accept JSON. This also makes cookie-authenticated
// admin mutations require a CORS preflight from any different origin.
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  if (['POST', 'PUT', 'PATCH'].includes(req.method) && !req.is('application/json')) {
    return res.status(415).json({ error: 'Content-Type must be application/json' });
  }
  next();
});

const globalApiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: API_RATE_LIMIT_PER_MINUTE,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' }
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: AUTH_RATE_LIMIT_PER_15_MIN,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  message: { error: 'Too many authentication requests. Try again later.' }
});
const adminLoginNetworkLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Math.max(10, ADMIN_MAX_LOGIN_ATTEMPTS * 2),
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { error: 'Too many admin login requests from this network. Try again later.' }
});
const orderLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: ORDER_RATE_LIMIT_PER_10_MIN,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many order attempts. Please wait before trying again.' }
});
const adminWriteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many admin changes. Please slow down.' }
});
app.use('/api', globalApiLimiter);

function clampInt(value, fallback, min, max) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.max(min, Math.min(max, Math.trunc(n))) : fallback;
}
function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}
function hasUnsafeStructure(value, depth = 0) {
  if (depth > 8) return true;
  if (Array.isArray(value)) {
    if (value.length > 100) return true;
    return value.some(v => hasUnsafeStructure(v, depth + 1));
  }
  if (!value || typeof value !== 'object') return false;
  const keys = Object.keys(value);
  if (keys.length > 100) return true;
  return keys.some(key =>
    key.startsWith('$') || key.includes('.') || ['__proto__', 'prototype', 'constructor'].includes(key) ||
    hasUnsafeStructure(value[key], depth + 1)
  );
}
function textField(value, name, max, { required = false, min = 0 } = {}) {
  if (value === undefined || value === null) {
    if (required) throw httpError(400, `${name} is required`);
    return '';
  }
  if (!['string', 'number'].includes(typeof value)) throw httpError(400, `Invalid ${name}`);
  const text = String(value).trim();
  if (required && !text) throw httpError(400, `${name} is required`);
  if (text.length < min && text) throw httpError(400, `${name} is too short`);
  if (text.length > max) throw httpError(400, `${name} is too long (max ${max} characters)`);
  if (/\u0000/.test(JSON.stringify(text)) || /[\u0000\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(text)) {
    throw httpError(400, `Invalid characters in ${name}`);
  }
  return text;
}
function cleanEmail(value) {
  const email = textField(value, 'email', 254, { required: true }).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw httpError(400, 'Valid email is required');
  return email;
}
function productIdField(value) {
  const id = textField(value, 'product id', 100, { required: true });
  if (!/^[A-Za-z0-9_-]+$/.test(id)) throw httpError(400, 'Invalid product id');
  return id;
}
function utrField(value) {
  const utr = textField(value, 'UTR', 80, { required: true, min: 6 });
  if (!/^[A-Za-z0-9._-]+$/.test(utr)) throw httpError(400, 'UTR may contain only letters, numbers, dot, underscore and hyphen');
  return utr;
}
function priceField(value) {
  const price = Number(value);
  if (!Number.isFinite(price) || price < 0 || price > 1000000) throw httpError(400, 'Price must be between ₹0 and ₹10,00,000');
  return Math.round(price * 100) / 100;
}
function safeDownloadUrl(value) {
  const text = textField(value, 'download link', 2000);
  if (!text || text === '#') return text;
  let url;
  try { url = new URL(text); } catch { throw httpError(400, 'Download link must be a valid HTTPS URL'); }
  if (url.protocol !== 'https:' || url.username || url.password) throw httpError(400, 'Download link must use HTTPS');
  return url.href;
}
function validUpiId(value) {
  const upi = textField(value, 'UPI ID', 150, { required: true });
  if (!/^[A-Za-z0-9._-]{2,}@[A-Za-z0-9.-]{2,}$/.test(upi)) throw httpError(400, 'Invalid UPI ID');
  return upi;
}
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
function adminLoginKey(req) {
  const source = String(req.headers['cf-connecting-ip'] || req.ip || req.socket?.remoteAddress || 'unknown').trim();
  return crypto.createHmac('sha256', JWT_SECRET).update(source).digest('hex');
}
function newUserToken() {
  return crypto.randomBytes(32).toString('base64url');
}
function newProductId() {
  return 'p_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');
}
function newOrderId() {
  const d = new Date();
  const ymd = `${d.getUTCFullYear()}${String(d.getUTCMonth()+1).padStart(2,'0')}${String(d.getUTCDate()).padStart(2,'0')}`;
  return `TS-${ymd}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}
function parseCookies(req) {
  const out = {};
  const raw = String(req.headers.cookie || '');
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (!key) continue;
    try { out[key] = decodeURIComponent(val); } catch { out[key] = val; }
  }
  return out;
}
function isSecureRequest(req) {
  return req.secure || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
}
function setAdminCookie(req, res, token) {
  res.cookie('ts_admin', token, {
    httpOnly: true,
    secure: isSecureRequest(req),
    sameSite: 'strict',
    path: '/api/admin',
    maxAge: 12 * 60 * 60 * 1000
  });
}
function clearAdminCookie(req, res) {
  res.clearCookie('ts_admin', {
    httpOnly: true,
    secure: isSecureRequest(req),
    sameSite: 'strict',
    path: '/api/admin'
  });
}
function signAdminToken(tokenVersion = 1) {
  return jwt.sign(
    { role: 'admin', ver: Number(tokenVersion || 1) },
    JWT_SECRET,
    { expiresIn: '12h', issuer: 'team-secret-store', audience: 'team-secret-admin' }
  );
}
async function requireAdmin(req, res, next) {
  try {
    const bearer = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const token = parseCookies(req).ts_admin || bearer;
    if (!token) return res.status(401).json({ error: 'Admin authentication required' });
    const payload = jwt.verify(token, JWT_SECRET, { issuer: 'team-secret-store', audience: 'team-secret-admin' });
    if (payload.role !== 'admin') throw new Error('Not admin');
    const admin = await db.collection('admin_config').findOne({ _id: 'primary' }, { projection: { tokenVersion: 1 } });
    if (!admin || Number(payload.ver || 1) !== Number(admin.tokenVersion || 1)) throw new Error('Expired admin session');
    req.admin = payload;
    next();
  } catch {
    clearAdminCookie(req, res);
    res.status(401).json({ error: 'Admin authentication required' });
  }
}
async function requireUser(req, res, next) {
  try {
    const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!token || token.length > 200) return res.status(401).json({ error: 'User session required' });
    const user = await db.collection('users').findOne({ tokenHash: hashToken(token) }, { maxTimeMS: 3000 });
    if (!user) return res.status(401).json({ error: 'Invalid user session' });
    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
}
function publicProduct(p) {
  return { id:p.id, title:p.title, subject:p.subject, type:p.type, price:p.price, description:p.description };
}
function sanitizeOrderForUser(order) {
  const canDownload = ['paid','delivered'].includes(order.status);
  return {
    id: order.id,
    items: (order.items || []).map(it => ({
      productId: it.productId,
      title: it.title,
      qty: it.qty,
      price: it.price,
      ...(canDownload && it.file ? { file: it.file } : {})
    })),
    total: order.total,
    utr: order.utr,
    status: order.status,
    createdAt: order.createdAt,
    updatedAt: order.updatedAt || order.createdAt
  };
}
function pagination(req, defaultLimit = ADMIN_READ_PAGE_SIZE) {
  const page = clampInt(req.query.page, 1, 1, 1000000);
  const limit = clampInt(req.query.limit, defaultLimit, 10, 100);
  return { page, limit, skip: (page - 1) * limit };
}

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'team-secret-store-api' }));

app.get('/api/products', async (req, res, next) => {
  try {
    const products = await db.collection('products')
      .find({ active: { $ne: false } })
      .sort({ createdAt: 1 })
      .limit(1000)
      .maxTimeMS(3000)
      .toArray();
    res.json({ products: products.map(publicProduct) });
  } catch (err) { next(err); }
});

app.get('/api/settings/public', async (req, res, next) => {
  try {
    const settings = await db.collection('settings').findOne({ _id: 'store' }, { maxTimeMS: 3000 });
    res.json({ upiId: settings?.upiId || '' });
  } catch (err) { next(err); }
});

app.post('/api/users/guest', authLimiter, async (req, res, next) => {
  try {
    const name = textField(req.body.name, 'name', 80, { required: true, min: 2 });
    const email = cleanEmail(req.body.email);
    const existingToken = textField(req.body.userToken, 'user token', 200);
    const now = new Date();
    let rawToken = existingToken;
    let user = existingToken ? await db.collection('users').findOne({ tokenHash: hashToken(existingToken) }, { maxTimeMS: 3000 }) : null;

    if (user) {
      await db.collection('users').updateOne({ _id: user._id }, { $set: { name, email, provider:'guest', lastSeenAt:now } });
      user = { ...user, name, email, provider:'guest', lastSeenAt:now };
    } else {
      rawToken = newUserToken();
      const doc = { name, email, provider:'guest', tokenHash:hashToken(rawToken), createdAt:now, lastSeenAt:now };
      const result = await db.collection('users').insertOne(doc);
      user = { ...doc, _id: result.insertedId };
    }

    res.json({ user: { id:String(user._id), name:user.name, email:user.email, provider:user.provider }, userToken: rawToken });
  } catch (err) { next(err); }
});

app.post('/api/auth/google', authLimiter, async (req, res, next) => {
  try {
    if (!googleClient || !GOOGLE_CLIENT_ID || GOOGLE_CLIENT_ID.includes('YOUR_GOOGLE_CLIENT_ID')) {
      return res.status(503).json({ error: 'Google sign-in is not configured on the backend' });
    }
    const credential = textField(req.body.credential, 'Google credential', 6000, { required: true });
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    if (!payload?.sub || !payload?.email || payload.email_verified === false) return res.status(401).json({ error: 'Invalid Google identity' });

    const now = new Date();
    let user = await db.collection('users').findOne({ googleSub: payload.sub }, { maxTimeMS: 3000 });
    const rawToken = newUserToken();
    const update = {
      name: textField(payload.name || payload.email.split('@')[0], 'Google name', 80, { required: true }),
      email: cleanEmail(payload.email),
      provider:'google',
      googleSub: textField(payload.sub, 'Google user id', 255, { required: true }),
      tokenHash: hashToken(rawToken),
      lastSeenAt: now
    };
    if (user) {
      await db.collection('users').updateOne({ _id:user._id }, { $set:update });
      user = { ...user, ...update };
    } else {
      const doc = { ...update, createdAt:now };
      const result = await db.collection('users').insertOne(doc);
      user = { ...doc, _id:result.insertedId };
    }
    res.json({ user:{ id:String(user._id), name:user.name, email:user.email, provider:'google' }, userToken:rawToken });
  } catch (err) {
    const msg = String(err?.message || '').toLowerCase();
    if (msg.includes('token') || msg.includes('audience') || msg.includes('issuer')) return res.status(401).json({ error:'Google sign-in verification failed' });
    next(err);
  }
});

app.post('/api/orders', orderLimiter, requireUser, async (req, res, next) => {
  try {
    const utr = utrField(req.body.utr);
    const submittedItems = Array.isArray(req.body.items) ? req.body.items : [];
    if (!submittedItems.length || submittedItems.length > 30) throw httpError(400, 'Cart is empty or too large');

    const normalized = submittedItems.map(it => {
      if (!it || typeof it !== 'object' || Array.isArray(it)) throw httpError(400, 'Invalid cart item');
      const productId = productIdField(it.productId);
      const qty = Number(it.qty);
      if (!Number.isInteger(qty) || qty < 1 || qty > 20) throw httpError(400, 'Invalid item quantity');
      return { productId, qty };
    });
    const ids = [...new Set(normalized.map(it => it.productId))];
    const products = await db.collection('products')
      .find({ id:{ $in:ids }, active:{ $ne:false } })
      .maxTimeMS(3000)
      .toArray();
    const byId = new Map(products.map(p => [p.id,p]));
    if (products.length !== ids.length) throw httpError(400, 'One or more products are unavailable. Refresh the store and try again.');

    const duplicateUtr = await db.collection('orders').findOne({ utr }, { projection:{ _id:1 }, maxTimeMS:3000 });
    if (duplicateUtr) throw httpError(409, 'This UTR has already been used for an order');

    const items = normalized.map(it => {
      const p = byId.get(it.productId);
      return { productId:p.id, title:textField(p.title, 'product title', 160, { required:true }), qty:it.qty, price:priceField(p.price), file:safeDownloadUrl(p.file || '') };
    });
    const total = Math.round(items.reduce((sum,it) => sum + it.price * it.qty, 0) * 100) / 100;
    if (total > 5000000) throw httpError(400, 'Order total is too large');
    const now = new Date();
    const order = {
      id:newOrderId(), userId:req.user._id, buyerName:req.user.name, buyerEmail:req.user.email,
      utr, items, total, status:'pending', createdAt:now, updatedAt:now
    };
    await db.collection('orders').insertOne(order);
    res.status(201).json({ order:sanitizeOrderForUser(order) });
  } catch (err) { next(err); }
});

app.get('/api/orders/me', requireUser, async (req, res, next) => {
  try {
    const { page, limit, skip } = pagination(req, 30);
    const filter = { userId:req.user._id };
    const [orders, total] = await Promise.all([
      db.collection('orders').find(filter).sort({ createdAt:-1 }).skip(skip).limit(limit).maxTimeMS(3000).toArray(),
      db.collection('orders').countDocuments(filter, { maxTimeMS:3000 })
    ]);
    res.json({ orders:orders.map(sanitizeOrderForUser), page, limit, total, pages:Math.max(1, Math.ceil(total / limit)) });
  } catch (err) { next(err); }
});

app.post('/api/admin/login', adminLoginNetworkLimiter, async (req, res, next) => {
  try {
    const password = textField(req.body.password, 'password', 128, { required: true });
    const now = new Date();
    const key = adminLoginKey(req);
    const attemptsCollection = db.collection('admin_login_attempts');
    let attempt = await attemptsCollection.findOne({ _id:key }, { maxTimeMS:3000 });

    if (attempt?.lockedUntil && attempt.lockedUntil > now) {
      const retryAfterSeconds = Math.max(1, Math.ceil((attempt.lockedUntil.getTime() - now.getTime()) / 1000));
      res.set('Retry-After', String(retryAfterSeconds));
      return res.status(429).json({
        error:`Too many wrong passwords. Try again in ${Math.ceil(retryAfterSeconds / 60)} minute(s).`,
        locked:true,
        retryAfterSeconds
      });
    }
    if (attempt?.lockedUntil && attempt.lockedUntil <= now) {
      await attemptsCollection.deleteOne({ _id:key });
      attempt = null;
    }

    let admin = await db.collection('admin_config').findOne({ _id:'primary' }, { maxTimeMS:3000 });
    if (!admin) {
      const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
      const doc = { _id:'primary', passwordHash, tokenVersion:1, createdAt:now, updatedAt:now };
      await db.collection('admin_config').insertOne(doc);
      admin = doc;
    }

    const ok = await bcrypt.compare(password, admin.passwordHash);
    if (!ok) {
      const failedAttempts = Number(attempt?.failedAttempts || 0) + 1;
      if (failedAttempts >= ADMIN_MAX_LOGIN_ATTEMPTS) {
        const lockedUntil = new Date(now.getTime() + ADMIN_LOCK_MINUTES * 60 * 1000);
        const retryAfterSeconds = ADMIN_LOCK_MINUTES * 60;
        await attemptsCollection.updateOne(
          { _id:key },
          { $set:{ failedAttempts, lockedUntil, lastFailedAt:now, expiresAt:new Date(lockedUntil.getTime() + 24*60*60*1000) } },
          { upsert:true }
        );
        res.set('Retry-After', String(retryAfterSeconds));
        return res.status(429).json({
          error:`Too many wrong passwords. Admin login is locked for ${ADMIN_LOCK_MINUTES} minute(s).`,
          locked:true,
          retryAfterSeconds,
          attemptsRemaining:0
        });
      }

      const attemptsRemaining = ADMIN_MAX_LOGIN_ATTEMPTS - failedAttempts;
      await attemptsCollection.updateOne(
        { _id:key },
        { $set:{ failedAttempts, lastFailedAt:now, lockedUntil:null, expiresAt:new Date(now.getTime() + 24*60*60*1000) } },
        { upsert:true }
      );
      return res.status(401).json({
        error:`Wrong password. ${attemptsRemaining} attempt(s) remaining before temporary lock.`,
        attemptsRemaining
      });
    }

    await attemptsCollection.deleteOne({ _id:key });
    const token = signAdminToken(admin.tokenVersion || 1);
    setAdminCookie(req, res, token);
    res.json({ ok:true });
  } catch (err) { next(err); }
});

app.post('/api/admin/logout', (req, res) => {
  clearAdminCookie(req, res);
  res.json({ ok:true });
});

app.get('/api/admin/stats', requireAdmin, async (req, res, next) => {
  try {
    const [products, orders, pending, users] = await Promise.all([
      db.collection('products').countDocuments({}, { maxTimeMS:3000 }),
      db.collection('orders').countDocuments({}, { maxTimeMS:3000 }),
      db.collection('orders').countDocuments({ status:'pending' }, { maxTimeMS:3000 }),
      db.collection('users').countDocuments({}, { maxTimeMS:3000 })
    ]);
    res.json({ products, orders, pending, users });
  } catch (err) { next(err); }
});

app.get('/api/admin/products', requireAdmin, async (req, res, next) => {
  try {
    const products = await db.collection('products').find({}).sort({ createdAt:1 }).limit(1000).maxTimeMS(3000).toArray();
    res.json({ products });
  } catch (err) { next(err); }
});

app.post('/api/admin/products', requireAdmin, adminWriteLimiter, async (req, res, next) => {
  try {
    const title = textField(req.body.title, 'title', 160, { required:true, min:2 });
    const subject = textField(req.body.subject, 'subject', 120);
    const type = textField(req.body.type, 'type', 40) || 'ebook';
    const allowedTypes = new Set(['ebook','handwritten','guide','template','website']);
    if (!allowedTypes.has(type)) throw httpError(400, 'Invalid product type');
    const description = textField(req.body.description, 'description', 2000);
    const file = safeDownloadUrl(req.body.file);
    const price = priceField(req.body.price);
    const now = new Date();
    const product = { id:newProductId(), title, subject, type, price, description, file, active:true, createdAt:now, updatedAt:now };
    await db.collection('products').insertOne(product);
    res.status(201).json({ product });
  } catch (err) { next(err); }
});

app.put('/api/admin/products/:id', requireAdmin, adminWriteLimiter, async (req, res, next) => {
  try {
    const id = productIdField(req.params.id);
    const title = textField(req.body.title, 'title', 160, { required:true, min:2 });
    const subject = textField(req.body.subject, 'subject', 120);
    const type = textField(req.body.type, 'type', 40) || 'ebook';
    const allowedTypes = new Set(['ebook','handwritten','guide','template','website']);
    if (!allowedTypes.has(type)) throw httpError(400, 'Invalid product type');
    const description = textField(req.body.description, 'description', 2000);
    const file = safeDownloadUrl(req.body.file);
    const price = priceField(req.body.price);
    const result = await db.collection('products').findOneAndUpdate(
      { id },
      { $set:{ title,subject,type,price,description,file,updatedAt:new Date() } },
      { returnDocument:'after' }
    );
    if (!result) throw httpError(404, 'Product not found');
    res.json({ product:result });
  } catch (err) { next(err); }
});

app.delete('/api/admin/products/:id', requireAdmin, adminWriteLimiter, async (req, res, next) => {
  try {
    const result = await db.collection('products').deleteOne({ id:productIdField(req.params.id) });
    if (!result.deletedCount) throw httpError(404, 'Product not found');
    res.json({ ok:true });
  } catch (err) { next(err); }
});

app.get('/api/admin/orders', requireAdmin, async (req, res, next) => {
  try {
    const status = textField(req.query.status, 'status', 30);
    const allowed = new Set(['all','pending','paid','delivered','rejected']);
    if (status && !allowed.has(status)) throw httpError(400, 'Invalid status filter');
    const filter = status && status !== 'all' ? { status } : {};
    const { page, limit, skip } = pagination(req);
    const [orders, total] = await Promise.all([
      db.collection('orders').find(filter).sort({ createdAt:-1 }).skip(skip).limit(limit).maxTimeMS(3000).toArray(),
      db.collection('orders').countDocuments(filter, { maxTimeMS:3000 })
    ]);
    res.json({ orders, page, limit, total, pages:Math.max(1, Math.ceil(total / limit)) });
  } catch (err) { next(err); }
});

app.patch('/api/admin/orders/:id/status', requireAdmin, adminWriteLimiter, async (req, res, next) => {
  try {
    const allowed = new Set(['pending','paid','delivered','rejected']);
    const status = textField(req.body.status, 'status', 30, { required:true });
    if (!allowed.has(status)) throw httpError(400, 'Invalid order status');
    const id = textField(req.params.id, 'order id', 80, { required:true });
    if (!/^TS-[A-Z0-9-]+$/.test(id)) throw httpError(400, 'Invalid order id');
    const order = await db.collection('orders').findOneAndUpdate(
      { id },
      { $set:{ status, updatedAt:new Date() } },
      { returnDocument:'after' }
    );
    if (!order) throw httpError(404, 'Order not found');
    res.json({ order });
  } catch (err) { next(err); }
});

app.get('/api/admin/users', requireAdmin, async (req, res, next) => {
  try {
    const { page, limit, skip } = pagination(req);
    const [users, total] = await Promise.all([
      db.collection('users').find({}, { projection:{ tokenHash:0, googleSub:0 } }).sort({ lastSeenAt:-1 }).skip(skip).limit(limit).maxTimeMS(3000).toArray(),
      db.collection('users').countDocuments({}, { maxTimeMS:3000 })
    ]);
    const ids = users.map(u => u._id);
    const counts = ids.length ? await db.collection('orders').aggregate([
      { $match:{ userId:{ $in:ids } } },
      { $group:{ _id:'$userId', count:{ $sum:1 }, spend:{ $sum:'$total' } } }
    ], { maxTimeMS:3000 }).toArray() : [];
    const map = new Map(counts.map(c => [String(c._id),c]));
    res.json({
      users:users.map(u => ({
        id:String(u._id), name:u.name, email:u.email, provider:u.provider,
        createdAt:u.createdAt, lastSeenAt:u.lastSeenAt,
        orderCount:map.get(String(u._id))?.count || 0,
        totalOrdered:map.get(String(u._id))?.spend || 0
      })),
      page, limit, total, pages:Math.max(1, Math.ceil(total / limit))
    });
  } catch (err) { next(err); }
});

app.get('/api/admin/settings', requireAdmin, async (req, res, next) => {
  try {
    const settings = await db.collection('settings').findOne({ _id:'store' }, { maxTimeMS:3000 });
    res.json({ upiId:settings?.upiId || '' });
  } catch (err) { next(err); }
});

app.put('/api/admin/settings', requireAdmin, adminWriteLimiter, async (req, res, next) => {
  try {
    const upiId = validUpiId(req.body.upiId);
    await db.collection('settings').updateOne(
      { _id:'store' },
      { $set:{ upiId, updatedAt:new Date() }, $setOnInsert:{ createdAt:new Date() } },
      { upsert:true }
    );
    res.json({ upiId });
  } catch (err) { next(err); }
});

app.put('/api/admin/password', requireAdmin, adminWriteLimiter, async (req, res, next) => {
  try {
    const newPassword = textField(req.body.newPassword, 'new password', 128, { required:true, min:12 });
    if (Buffer.byteLength(newPassword, 'utf8') > 72) throw httpError(400, 'Admin password must be 72 bytes or fewer');
    const passwordHash = await bcrypt.hash(newPassword, 12);
    await db.collection('admin_config').updateOne(
      { _id:'primary' },
      { $set:{ passwordHash, updatedAt:new Date() }, $inc:{ tokenVersion:1 }, $setOnInsert:{ createdAt:new Date() } },
      { upsert:true }
    );
    clearAdminCookie(req, res);
    res.json({ ok:true, reauthRequired:true });
  } catch (err) { next(err); }
});

// Separate admin entry point. It is intentionally not linked from the public storefront.
app.get(['/admin', '/admin-login'], (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.set('X-Robots-Tag', 'noindex, nofollow, noarchive');
  res.sendFile(path.join(FRONTEND_DIR, 'admin.html'));
});

// Only public/ is exposed. Backend source, .env and package files are never static.
app.use(express.static(FRONTEND_DIR, {
  index: 'index.html',
  dotfiles: 'ignore',
  maxAge: '1h',
  setHeaders(res, filePath) {
    if (filePath.endsWith('config.js') || filePath.endsWith('admin.html')) res.setHeader('Cache-Control', 'no-store');
  }
}));

app.use((req, res, next) => {
  if (req.method === 'GET' && !req.path.startsWith('/api/')) {
    return res.sendFile(path.join(FRONTEND_DIR, 'index.html'));
  }
  next();
});

app.use('/api', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

app.use((err, req, res, next) => {
  const status = Number(err?.status || err?.statusCode || 0);
  if (err?.type === 'entity.too.large' || status === 413) return res.status(413).json({ error:'Request body is too large' });
  if (err instanceof SyntaxError && 'body' in err) return res.status(400).json({ error:'Invalid JSON body' });
  if (err?.code === 11000) return res.status(409).json({ error:'That value is already in use' });
  if (String(err?.message || '').includes('CORS')) return res.status(403).json({ error:'Origin not allowed' });
  if (status >= 400 && status < 500) return res.status(status).json({ error:String(err.message || 'Bad request').slice(0,200) });
  console.error('Unhandled request error:', err);
  res.status(500).json({ error:'Server error' });
});

async function start() {
  await mongo.connect();
  db = mongo.db(DB_NAME);
  await Promise.all([
    db.collection('products').createIndex({ id:1 }, { unique:true }),
    db.collection('products').createIndex({ active:1, createdAt:1 }),
    db.collection('orders').createIndex({ id:1 }, { unique:true }),
    db.collection('orders').createIndex({ userId:1, createdAt:-1 }),
    db.collection('orders').createIndex({ status:1, createdAt:-1 }),
    db.collection('orders').createIndex({ utr:1 }),
    db.collection('users').createIndex({ tokenHash:1 }, { unique:true }),
    db.collection('users').createIndex({ email:1 }),
    db.collection('users').createIndex({ lastSeenAt:-1 }),
    db.collection('users').createIndex({ googleSub:1 }, { unique:true, sparse:true }),
    db.collection('admin_login_attempts').createIndex({ expiresAt:1 }, { expireAfterSeconds:0 })
  ]);

  const count = await db.collection('products').countDocuments({}, { maxTimeMS:3000 });
  if (count === 0) {
    const now = new Date();
    await db.collection('products').insertMany(DEFAULT_PRODUCTS.map(p => ({ ...p, active:true, createdAt:now, updatedAt:now })));
  }

  // Upgrade older admin config documents created before tokenVersion existed.
  await db.collection('admin_config').updateOne(
    { _id:'primary', tokenVersion:{ $exists:false } },
    { $set:{ tokenVersion:1 } }
  );

  const server = app.listen(PORT, HOST, () => console.log(`Team Secret Store listening on http://${HOST}:${PORT}`));
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.keepAliveTimeout = 5000;
  server.maxRequestsPerSocket = 1000;
}

start().catch(err => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
