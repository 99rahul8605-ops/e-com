require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');
const { OAuth2Client } = require('google-auth-library');

const PORT = Number(process.env.PORT || 3000);
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.MONGODB_DB || 'team_secret_store';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || '')
  .split(',')
  .map(v => v.trim())
  .filter(Boolean);

if (!MONGODB_URI) throw new Error('MONGODB_URI is required');
if (!ADMIN_PASSWORD) throw new Error('ADMIN_PASSWORD is required');
if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 characters');

const app = express();
const mongo = new MongoClient(MONGODB_URI);
let db;
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

const DEFAULT_PRODUCTS = [
  {id:'p1', title:'Class 12 Physics — Full Notes', subject:'Physics', type:'handwritten', price:149, description:'Chapter-wise handwritten notes covering the entire CBSE Class 12 Physics syllabus.', file:'#'},
  {id:'p2', title:'Organic Chemistry Crash Guide', subject:'Chemistry', type:'guide', price:199, description:'A compact revision guide for organic chemistry reactions and mechanisms.', file:'#'},
  {id:'p3', title:'Data Structures E-book', subject:'Computer Science', type:'ebook', price:249, description:'Beginner-friendly e-book on arrays, trees, graphs and common interview problems.', file:'#'},
  {id:'p4', title:'UPSC Essay Answer Templates', subject:'UPSC', type:'template', price:99, description:'Ready-to-adapt structures for scoring well in the essay paper.', file:'#'}
];

app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(express.json({ limit: '200kb' }));
app.use(cors({
  origin(origin, callback) {
    if (!origin || FRONTEND_ORIGINS.length === 0 || FRONTEND_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed by CORS'));
  },
  credentials: false
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false });
const orderLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 60, standardHeaders: 'draft-8', legacyHeaders: false });

function cleanText(value, max = 300) {
  return String(value ?? '').trim().slice(0, max);
}
function cleanEmail(value) {
  return cleanText(value, 254).toLowerCase();
}
function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
function newUserToken() {
  return crypto.randomBytes(32).toString('base64url');
}
function newProductId() {
  return 'p_' + Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex');
}
function newOrderId() {
  const d = new Date();
  const ymd = `${d.getUTCFullYear()}${String(d.getUTCMonth()+1).padStart(2,'0')}${String(d.getUTCDate()).padStart(2,'0')}`;
  return `TS-${ymd}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}
function signAdminToken() {
  return jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
}
function requireAdmin(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'admin') throw new Error('Not admin');
    req.admin = payload;
    next();
  } catch {
    res.status(401).json({ error: 'Admin authentication required' });
  }
}
async function requireUser(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!token) return res.status(401).json({ error: 'User session required' });
    const user = await db.collection('users').findOne({ tokenHash: hashToken(token) });
    if (!user) return res.status(401).json({ error: 'Invalid user session' });
    req.user = user;
    req.userToken = token;
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
      ...(canDownload ? { file: it.file } : {})
    })),
    total: order.total,
    utr: order.utr,
    status: order.status,
    createdAt: order.createdAt,
    updatedAt: order.updatedAt || order.createdAt
  };
}

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'team-secret-store-api' }));

app.get('/api/products', async (req, res, next) => {
  try {
    const products = await db.collection('products').find({ active: { $ne: false } }).sort({ createdAt: 1 }).toArray();
    res.json({ products: products.map(publicProduct) });
  } catch (err) { next(err); }
});

app.get('/api/settings/public', async (req, res, next) => {
  try {
    const settings = await db.collection('settings').findOne({ _id: 'store' });
    res.json({ upiId: settings?.upiId || '' });
  } catch (err) { next(err); }
});

app.post('/api/users/guest', authLimiter, async (req, res, next) => {
  try {
    const name = cleanText(req.body.name, 100);
    const email = cleanEmail(req.body.email);
    const existingToken = cleanText(req.body.userToken, 200);
    if (!name || !validEmail(email)) return res.status(400).json({ error: 'Valid name and email are required' });

    const now = new Date();
    let rawToken = existingToken;
    let user = existingToken ? await db.collection('users').findOne({ tokenHash: hashToken(existingToken) }) : null;

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
    const credential = cleanText(req.body.credential, 5000);
    if (!credential) return res.status(400).json({ error: 'Google credential is required' });
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    if (!payload?.sub || !payload?.email) return res.status(401).json({ error: 'Invalid Google identity' });

    const now = new Date();
    let user = await db.collection('users').findOne({ googleSub: payload.sub });
    let rawToken = newUserToken();
    const update = {
      name: cleanText(payload.name || payload.email.split('@')[0], 100),
      email: cleanEmail(payload.email),
      provider:'google',
      googleSub: payload.sub,
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
    if (String(err?.message || '').toLowerCase().includes('token')) return res.status(401).json({ error:'Google sign-in verification failed' });
    next(err);
  }
});

app.post('/api/orders', orderLimiter, requireUser, async (req, res, next) => {
  try {
    const utr = cleanText(req.body.utr, 80);
    const submittedItems = Array.isArray(req.body.items) ? req.body.items : [];
    if (!utr) return res.status(400).json({ error: 'UPI transaction / UTR number is required' });
    if (!submittedItems.length || submittedItems.length > 30) return res.status(400).json({ error: 'Cart is empty or too large' });

    const normalized = submittedItems.map(it => ({ productId:cleanText(it.productId,100), qty:Math.max(1, Math.min(20, Number(it.qty)||1)) }));
    const ids = [...new Set(normalized.map(it => it.productId))];
    const products = await db.collection('products').find({ id:{ $in:ids }, active:{ $ne:false } }).toArray();
    const byId = new Map(products.map(p => [p.id,p]));
    if (products.length !== ids.length) return res.status(400).json({ error:'One or more products are unavailable. Refresh the store and try again.' });

    const items = normalized.map(it => {
      const p = byId.get(it.productId);
      return { productId:p.id, title:p.title, qty:it.qty, price:Number(p.price), file:p.file || '' };
    });
    const total = items.reduce((sum,it) => sum + it.price * it.qty, 0);
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
    const orders = await db.collection('orders').find({ userId:req.user._id }).sort({ createdAt:-1 }).limit(100).toArray();
    res.json({ orders:orders.map(sanitizeOrderForUser) });
  } catch (err) { next(err); }
});

app.post('/api/admin/login', authLimiter, async (req, res, next) => {
  try {
    const password = String(req.body.password || '');
    if (!password) return res.status(400).json({ error:'Password is required' });
    let admin = await db.collection('admin_config').findOne({ _id:'primary' });
    if (!admin) {
      const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
      await db.collection('admin_config').insertOne({ _id:'primary', passwordHash, createdAt:new Date(), updatedAt:new Date() });
      admin = { passwordHash };
    }
    const ok = await bcrypt.compare(password, admin.passwordHash);
    if (!ok) return res.status(401).json({ error:'Wrong password' });
    res.json({ token:signAdminToken() });
  } catch (err) { next(err); }
});

app.get('/api/admin/products', requireAdmin, async (req, res, next) => {
  try {
    const products = await db.collection('products').find({}).sort({ createdAt:1 }).toArray();
    res.json({ products });
  } catch (err) { next(err); }
});

app.post('/api/admin/products', requireAdmin, async (req, res, next) => {
  try {
    const title = cleanText(req.body.title,160);
    const subject = cleanText(req.body.subject,120);
    const type = cleanText(req.body.type,40) || 'ebook';
    const description = cleanText(req.body.description,2000);
    const file = cleanText(req.body.file,2000);
    const price = Number(req.body.price);
    if (!title || !Number.isFinite(price) || price < 0) return res.status(400).json({ error:'Valid title and price are required' });
    const now = new Date();
    const product = { id:newProductId(), title, subject, type, price:Math.round(price*100)/100, description, file, active:true, createdAt:now, updatedAt:now };
    await db.collection('products').insertOne(product);
    res.status(201).json({ product });
  } catch (err) { next(err); }
});

app.put('/api/admin/products/:id', requireAdmin, async (req, res, next) => {
  try {
    const id = cleanText(req.params.id,100);
    const title = cleanText(req.body.title,160);
    const subject = cleanText(req.body.subject,120);
    const type = cleanText(req.body.type,40) || 'ebook';
    const description = cleanText(req.body.description,2000);
    const file = cleanText(req.body.file,2000);
    const price = Number(req.body.price);
    if (!title || !Number.isFinite(price) || price < 0) return res.status(400).json({ error:'Valid title and price are required' });
    const result = await db.collection('products').findOneAndUpdate(
      { id },
      { $set:{ title,subject,type,price:Math.round(price*100)/100,description,file,updatedAt:new Date() } },
      { returnDocument:'after' }
    );
    if (!result) return res.status(404).json({ error:'Product not found' });
    res.json({ product:result });
  } catch (err) { next(err); }
});

app.delete('/api/admin/products/:id', requireAdmin, async (req, res, next) => {
  try {
    const result = await db.collection('products').deleteOne({ id:cleanText(req.params.id,100) });
    if (!result.deletedCount) return res.status(404).json({ error:'Product not found' });
    res.json({ ok:true });
  } catch (err) { next(err); }
});

app.get('/api/admin/orders', requireAdmin, async (req, res, next) => {
  try {
    const status = cleanText(req.query.status,30);
    const filter = status && status !== 'all' ? { status } : {};
    const orders = await db.collection('orders').find(filter).sort({ createdAt:-1 }).limit(500).toArray();
    res.json({ orders });
  } catch (err) { next(err); }
});

app.patch('/api/admin/orders/:id/status', requireAdmin, async (req, res, next) => {
  try {
    const allowed = new Set(['pending','paid','delivered','rejected']);
    const status = cleanText(req.body.status,30);
    if (!allowed.has(status)) return res.status(400).json({ error:'Invalid order status' });
    const order = await db.collection('orders').findOneAndUpdate(
      { id:cleanText(req.params.id,80) },
      { $set:{ status, updatedAt:new Date() } },
      { returnDocument:'after' }
    );
    if (!order) return res.status(404).json({ error:'Order not found' });
    res.json({ order });
  } catch (err) { next(err); }
});

app.get('/api/admin/users', requireAdmin, async (req, res, next) => {
  try {
    const users = await db.collection('users').find({}).sort({ lastSeenAt:-1 }).limit(500).toArray();
    const ids = users.map(u => u._id);
    const counts = ids.length ? await db.collection('orders').aggregate([
      { $match:{ userId:{ $in:ids } } },
      { $group:{ _id:'$userId', count:{ $sum:1 }, spend:{ $sum:'$total' } } }
    ]).toArray() : [];
    const map = new Map(counts.map(c => [String(c._id),c]));
    res.json({ users:users.map(u => ({
      id:String(u._id), name:u.name, email:u.email, provider:u.provider,
      createdAt:u.createdAt, lastSeenAt:u.lastSeenAt,
      orderCount:map.get(String(u._id))?.count || 0,
      totalOrdered:map.get(String(u._id))?.spend || 0
    })) });
  } catch (err) { next(err); }
});

app.get('/api/admin/settings', requireAdmin, async (req, res, next) => {
  try {
    const settings = await db.collection('settings').findOne({ _id:'store' });
    res.json({ upiId:settings?.upiId || '' });
  } catch (err) { next(err); }
});

app.put('/api/admin/settings', requireAdmin, async (req, res, next) => {
  try {
    const upiId = cleanText(req.body.upiId,150);
    await db.collection('settings').updateOne(
      { _id:'store' },
      { $set:{ upiId, updatedAt:new Date() }, $setOnInsert:{ createdAt:new Date() } },
      { upsert:true }
    );
    res.json({ upiId });
  } catch (err) { next(err); }
});

app.put('/api/admin/password', requireAdmin, authLimiter, async (req, res, next) => {
  try {
    const newPassword = String(req.body.newPassword || '');
    if (newPassword.length < 10) return res.status(400).json({ error:'Admin password must be at least 10 characters' });
    const passwordHash = await bcrypt.hash(newPassword, 12);
    await db.collection('admin_config').updateOne(
      { _id:'primary' },
      { $set:{ passwordHash, updatedAt:new Date() }, $setOnInsert:{ createdAt:new Date() } },
      { upsert:true }
    );
    res.json({ ok:true });
  } catch (err) { next(err); }
});

app.use((err, req, res, next) => {
  console.error(err);
  if (String(err?.message || '').includes('CORS')) return res.status(403).json({ error:'Origin not allowed' });
  res.status(500).json({ error:'Server error' });
});

async function start() {
  await mongo.connect();
  db = mongo.db(DB_NAME);
  await Promise.all([
    db.collection('products').createIndex({ id:1 }, { unique:true }),
    db.collection('orders').createIndex({ id:1 }, { unique:true }),
    db.collection('orders').createIndex({ userId:1, createdAt:-1 }),
    db.collection('orders').createIndex({ status:1, createdAt:-1 }),
    db.collection('users').createIndex({ tokenHash:1 }, { unique:true }),
    db.collection('users').createIndex({ email:1 }),
    db.collection('users').createIndex({ googleSub:1 }, { unique:true, sparse:true })
  ]);

  const count = await db.collection('products').countDocuments();
  if (count === 0) {
    const now = new Date();
    await db.collection('products').insertMany(DEFAULT_PRODUCTS.map(p => ({ ...p, active:true, createdAt:now, updatedAt:now })));
  }

  app.listen(PORT, '0.0.0.0', () => console.log(`Team Secret API listening on port ${PORT}`));
}

start().catch(err => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
