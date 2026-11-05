// ORVIX PAY public API (runs on Render, so InfinityFree bot-check does not apply)
// Routes: POST /api/create-order, GET /api/order-status/:id, POST /api/webhook
const crypto = require('crypto');

const ORDERS = new Map(); // NOTE: in-memory. Orders reset when Render restarts. Move to a DB later.
const ORDER_TTL_MS = 30 * 60 * 1000;

function cors(req, res, next) {
  const allowed = String(process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim()).filter(Boolean);
  const origin = req.headers.origin || '';
  if (allowed.includes('*')) res.setHeader('Access-Control-Allow-Origin', '*');
  else if (allowed.includes(origin)) { res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Vary', 'Origin'); }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Api-Key, X-Signature');
  res.setHeader('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
}

// very small per-IP rate limit (30 requests / minute)
const HITS = new Map();
function rateLimit(req, res, next) {
  const ip = String(req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
  const now = Date.now();
  const arr = (HITS.get(ip) || []).filter(t => now - t < 60000);
  arr.push(now); HITS.set(ip, arr);
  if (arr.length > 30) return res.status(429).json({ ok: false, error: 'too_many_requests' });
  next();
}

function publicOrder(o) {
  return { order_id: o.id, amount: o.amount, note: o.note, status: o.status, created_at: o.createdAt, expires_at: o.expiresAt, paid_at: o.paidAt || null, utr: o.utr || null };
}

function sweep() {
  const now = Date.now();
  for (const [id, o] of ORDERS) {
    if (o.status === 'created' && now > o.expiresAt) o.status = 'expired';
    if (now - o.createdAt > 24 * 3600 * 1000) ORDERS.delete(id);
  }
}
setInterval(sweep, 60000).unref();

module.exports = function mount(app) {
  app.use('/api', cors, rateLimit);

  app.post('/api/create-order', async (req, res) => {
    const b = req.body || {};
    const amount = Number(b.amount);
    if (!Number.isFinite(amount) || amount < 1 || amount > 100000)
      return res.status(400).json({ ok: false, error: 'invalid_amount' });
    const id = 'ORV' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(3).toString('hex').toUpperCase();
    const now = Date.now();
    const order = {
      id, amount: Math.round(amount * 100) / 100,
      note: String(b.note || '').slice(0, 120),
      status: 'created', createdAt: now, expiresAt: now + ORDER_TTL_MS
    };
    // TODO: call your real provider / UPI link generation here and attach its fields to `order`
    // e.g. order.paymentUrl = await createWithProvider(order);
    ORDERS.set(id, order);
    res.json({ ok: true, ...publicOrder(order), payment_url: order.paymentUrl || null });
  });

  app.get('/api/order-status/:id', (req, res) => {
    const o = ORDERS.get(String(req.params.id));
    if (!o) return res.status(404).json({ ok: false, error: 'order_not_found' });
    if (o.status === 'created' && Date.now() > o.expiresAt) o.status = 'expired';
    res.json({ ok: true, ...publicOrder(o) });
  });

  // Provider/bank callback. Must send header X-Signature = hex HMAC-SHA256(rawBody, WEBHOOK_SECRET)
  app.post('/api/webhook', (req, res) => {
    const secret = process.env.WEBHOOK_SECRET || '';
    if (!secret) return res.status(503).json({ ok: false, error: 'webhook_not_configured' });
    const sig = String(req.headers['x-signature'] || '');
    const expected = crypto.createHmac('sha256', secret).update(req.rawBody || Buffer.from('')).digest('hex');
    const a = Buffer.from(sig), c = Buffer.from(expected);
    if (a.length !== c.length || !crypto.timingSafeEqual(a, c))
      return res.status(401).json({ ok: false, error: 'bad_signature' });
    const b = req.body || {};
    const o = ORDERS.get(String(b.order_id || ''));
    if (!o) return res.status(404).json({ ok: false, error: 'order_not_found' });
    if (String(b.status).toLowerCase() === 'paid' && o.status !== 'paid') {
      o.status = 'paid'; o.paidAt = Date.now(); o.utr = String(b.utr || '').slice(0, 40);
    }
    res.json({ ok: true });
  });
};
