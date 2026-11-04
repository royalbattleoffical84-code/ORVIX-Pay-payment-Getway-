'use strict';
/* =====================================================================
   famMail.js - merchant Fam account verification for PayX
   (Node port of fampay_gateway.py's Gmail/IMAP verifier)

   A merchant connects their OWN Gmail (App Password) + Fam UPI ID. Customers pay
   straight to that UPI ID, and the payment is confirmed by finding the Fam
   "payment received" e-mail for the customer's UTR in THAT merchant's inbox.

   Everything except searchUtr()/testLogin() is pure (no network) so it can be
   unit-tested:  node famMail.test.js
   Needs (only for real IMAP):  npm i imapflow mailparser
   ===================================================================== */
const crypto = require('crypto');

const DEFAULTS = {
  senderDomains: ['famapp.in', 'famapp.com', 'fampay.in', 'famapp.co'],
  requireAuth: true,          // Gmail DKIM/SPF must pass for the Fam domain
  lookbackDays: 3,
  maxFetch: 10,
  maxMailBytes: 3000000,
  clockSkew: 300,             // seconds
  maxPaymentAge: 7200,
  emailMaxDelay: 3600,
  orderWindow: 900,           // QR validity, seconds (server overrides from expiryMin)
  imapTimeoutMs: 20000,
  breakerThreshold: 3,
  breakerPauseMs: 600000
};
const cfgOf = c => ({ ...DEFAULTS, ...(c || {}) });

/* ---------------- UTR helpers ---------------- */
function normalizeUtr(raw) {
  if (raw === null || raw === undefined) return null;
  let s = String(raw).trim();
  s = s.replace(/^(?:fam\s*pay|fam\s*app|fam|utr|upi\s*ref|upi\s*txn|txn|transaction|ref)[\s\-_]*(?:transaction|txn|upi|ref)?[\s\-_]*(?:id|no|number|num)?\.?\s*[:#\-]\s*/i, '');
  s = s.replace(/^utr\s+(?:(?:id|no|number|num)\.?\s+)?/i, '');
  s = s.replace(/^(?:fam\s*pay\s*|fam\s*app\s*)?(?:transaction|txn|upi\s*ref(?:erence)?|ref(?:erence)?)\s*(?:id|no|number|num)\.?\s+/i, '');
  s = s.replace(/[\s\-_]/g, '').toUpperCase();
  s = s.replace(/^UTR(?=\d{8,})/, '');
  if (!/^[A-Z0-9]{8,40}$/.test(s) || !/\d/.test(s)) return null;
  const m = /^FMPIB(\d{6,14})$/.exec(s);
  return m ? m[1] : s;
}
function utrAliases(utr) {
  const u = String(utr || '').trim().toUpperCase();
  const out = [u];
  const m = /^FMPIB(\d{6,14})$/.exec(u);
  if (m) out.push(m[1]); else if (/^\d{6,14}$/.test(u)) out.push('FMPIB' + u);
  return out;
}
const utrKey = utr => crypto.createHash('sha256').update(String(normalizeUtr(utr) || utr)).digest('hex');
const FAMPAY_ID = /^(?:FMPIB[A-Z0-9]{4,35}|FAM[A-Z0-9]{9,35})$/i;

/* ---------------- e-mail text parsing ---------------- */
const CUR = '(?:₹|\\brs\\.?|\\binr\\b)';
const NUM = '([0-9][0-9,]*(?:\\.[0-9]{1,2})?)';
const AMT_KEYED = [
  new RegExp('(?:received|credited|credit|payment\\s+of|paid|deposited|amount)[^0-9₹\\n]{0,40}?' + CUR + '\\s*' + NUM, 'gi'),
  new RegExp(CUR + '\\s*' + NUM + '\\s*(?:has\\s+been\\s+|was\\s+)?(?:received|credited|paid)', 'gi')
];
const AMT_ANY = new RegExp(CUR + '\\s*' + NUM, 'gi');

function toPaise(s) {
  const m = /^(\d+)(?:\.(\d{1,2}))?$/.exec(String(s).replace(/,/g, ''));
  if (!m) return null;
  return parseInt(m[1], 10) * 100 + parseInt(((m[2] || '') + '00').slice(0, 2), 10);
}
/** Amount written in the mail (paise). null when missing or ambiguous - never guesses. */
function parseAmountPaise(text) {
  const keyed = new Set();
  for (const rx of AMT_KEYED) for (const m of String(text).matchAll(rx)) { const p = toPaise(m[1]); if (p !== null) keyed.add(p); }
  if (keyed.size === 1) return [...keyed][0];
  if (keyed.size > 1) return null;
  const any = new Set();
  for (const m of String(text).matchAll(AMT_ANY)) { const p = toPaise(m[1]); if (p !== null) any.add(p); }
  return any.size === 1 ? [...any][0] : null;
}

const UTR_LABELED = /(?:\butr\b|upi\s*ref(?:erence)?(?:\s*(?:no|id|number))?|transaction\s*(?:id|no|number|ref(?:erence)?)|txn\s*(?:id|no|ref)|ref(?:erence)?\s*(?:id|no|number)|\brrn\b|fam\s*(?:pay|app)?\s*(?:transaction|txn|payment)?\s*(?:id|no|number)|payment\s*id|upi\s*(?:transaction|txn)\s*id)\s*[:#\-]?\s*(?:is\s*)?([A-Za-z0-9]{8,40})\b/gi;
function utrInText(text, utr) {
  const labeled = new Set([...String(text).matchAll(UTR_LABELED)].map(m => m[1].toUpperCase()));
  const tokens = new Set((String(text).match(/\b[A-Za-z0-9]{8,40}\b/g) || []).map(t => t.toUpperCase()));
  for (const u of utrAliases(utr)) {
    if (labeled.has(u)) return true;
    if (!labeled.size) { if (tokens.has(u)) return true; }
    else if (tokens.has(u) && (/^\d{10,12}$/.test(u) || FAMPAY_ID.test(u))) return true;
  }
  return false;
}

const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
const AP = '\\s*([AaPp]\\.?[Mm]\\.?)?';
const DT_PATTERNS = [
  [new RegExp('(\\d{4})-(\\d{2})-(\\d{2})[T ](\\d{1,2}):(\\d{2})(?::(\\d{2}))?' + AP, 'g'), 'ymd'],
  [new RegExp('(\\d{1,2})[/\\-.](\\d{1,2})[/\\-.](\\d{4}),?\\s*(?:at\\s*)?(\\d{1,2}):(\\d{2})(?::(\\d{2}))?' + AP, 'g'), 'dmy'],
  [new RegExp('(\\d{1,2})(?:st|nd|rd|th)?\\s+([A-Za-z]{3,9})\\.?,?\\s+(\\d{4}),?\\s*(?:at\\s*|-\\s*)?(\\d{1,2}):(\\d{2})(?::(\\d{2}))?' + AP, 'g'), 'dMy'],
  [new RegExp('([A-Za-z]{3,9})\\.?\\s+(\\d{1,2})(?:st|nd|rd|th)?,?\\s+(\\d{4}),?\\s*(?:at\\s*|-\\s*)?(\\d{1,2}):(\\d{2})(?::(\\d{2}))?' + AP, 'g'), 'Mdy']
];
/** Every date+time in the body. Returns candidate epoch-seconds: [read as IST, read as UTC]. */
function parseBodyDatetimes(text) {
  const out = [];
  for (const [rx, kind] of DT_PATTERNS) {
    for (const m of String(text).matchAll(rx)) {
      let y, mo, d;
      if (kind === 'ymd') { y = +m[1]; mo = +m[2]; d = +m[3]; }
      else if (kind === 'dmy') { d = +m[1]; mo = +m[2]; y = +m[3]; }
      else if (kind === 'dMy') { d = +m[1]; y = +m[3]; mo = MONTHS[m[2].slice(0, 3).toLowerCase()]; }
      else { mo = MONTHS[m[1].slice(0, 3).toLowerCase()]; d = +m[2]; y = +m[3]; }
      if (!mo) continue;
      let h = +m[4]; const mi = +m[5], s = +(m[6] || 0), ap = m[7];
      if (ap) {
        if (h < 1 || h > 12) continue;
        const a = ap.toLowerCase().replace(/\./g, '');
        if (a === 'pm' && h < 12) h += 12; else if (a === 'am' && h === 12) h = 0;
      }
      const t = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
      if (t.getUTCFullYear() !== y || t.getUTCMonth() !== mo - 1 || t.getUTCDate() !== d || h > 23 || mi > 59 || s > 59) continue;
      const utcReading = Math.floor(t.getTime() / 1000);
      out.push([utcReading - 19800, utcReading]);
    }
  }
  return out;
}

function htmlToText(h) {
  return String(h || '')
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<br\s*\/?>|<\/p>|<\/tr>|<\/div>|<\/li>/gi, '\n')
    .replace(/<\/t[dh]>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&#8377;/g, '₹');
}

/* ---------------- sender trust ---------------- */
const domainAllowed = (c, dom) => { dom = String(dom || '').toLowerCase().replace(/^\.+|\.+$/g, ''); return c.senderDomains.some(d => dom === d || dom.endsWith('.' + d)); };
const senderDomainOf = addr => { const a = String(addr || '').trim().toLowerCase(); const i = a.lastIndexOf('@'); return i >= 0 ? a.slice(i + 1).replace(/[>\s]+$/, '') : ''; };

function headerValues(rawHeaders, name) {
  const unfolded = String(rawHeaders || '').replace(/\r?\n[ \t]+/g, ' ');
  const out = [];
  for (const line of unfolded.split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i > 0 && line.slice(0, i).trim().toLowerCase() === name.toLowerCase()) out.push(line.slice(i + 1).trim());
  }
  return out;
}
/** Only Gmail's own (mx.google.com) Authentication-Results counts, so nobody can fake a "payment received" mail. */
function authOk(c, rawHeaders) {
  if (!c.requireAuth) return true;
  for (const h of headerValues(rawHeaders, 'Authentication-Results')) {
    const hs = h.replace(/\s+/g, ' ').toLowerCase();
    if (!hs.startsWith('mx.google.com')) continue;
    for (const m of hs.matchAll(/dkim=pass[^;]*?header\.(?:d|i)=@?([a-z0-9.\-]+)/g)) if (domainAllowed(c, m[1])) return true;
    for (const m of hs.matchAll(/spf=pass[^;]*?smtp\.mailfrom=(?:[^@\s;]*@)?([a-z0-9.\-]+)/g)) if (domainAllowed(c, m[1])) return true;
    return false;
  }
  return false;
}

/**
 * mail = { rawHeaders, fromAddress, subject, text }.  Never throws.
 * Body time is trusted only when consistent with Gmail's own arrival time.
 */
function parsePaymentEmail(conf, mail, utr, arrivalTs) {
  const c = cfgOf(conf);
  const info = { senderDomain: '', senderOk: false, authOk: false, utrMatch: false, amountPaise: null, paidAt: null,
    paidSrc: '', subject: '', arrivalAt: arrivalTs == null ? null : arrivalTs, headerAt: null, timeConflict: false };
  try {
    info.subject = String(mail.subject || '').slice(0, 120);
    const dom = senderDomainOf(mail.fromAddress);
    info.senderDomain = dom;
    info.authOk = authOk(c, mail.rawHeaders);
    info.senderOk = !!dom && domainAllowed(c, dom) && info.authOk;
    const text = String(mail.text || '');
    info.utrMatch = utrInText(text, utr);
    info.amountPaise = parseAmountPaise(text);

    const dh = headerValues(mail.rawHeaders, 'Date')[0];
    const hdr = dh ? Math.floor(Date.parse(dh) / 1000) : NaN;
    const hdrTs = Number.isFinite(hdr) ? hdr : null;
    info.headerAt = hdrTs;
    const ref = arrivalTs != null ? arrivalTs : hdrTs;
    const bodyTimes = parseBodyDatetimes(text);
    let chosen = null, src = '';
    if (bodyTimes.length) {
      if (ref !== null) {
        for (const cands of bodyTimes) for (const cand of cands) {
          const gap = ref - cand;
          if (gap >= -c.clockSkew && gap <= c.emailMaxDelay && (chosen === null || Math.abs(ref - cand) < Math.abs(ref - chosen))) { chosen = cand; src = 'body'; }
        }
      }
      if (chosen === null) info.timeConflict = true;      // body time doesn't match arrival -> never auto-confirm
    } else if (hdrTs !== null) {
      if (ref !== null && ref - hdrTs > c.emailMaxDelay) info.timeConflict = true; else { chosen = hdrTs; src = 'header'; }
    } else if (arrivalTs != null) { chosen = arrivalTs; src = 'arrival'; }
    if (chosen !== null) { info.paidAt = Math.floor(chosen); info.paidSrc = src; }
  } catch (e) { /* keep info as-is */ }
  return info;
}

/** Pure time validation -> [ok, reason]. All values in seconds. */
function checkPaymentTime(conf, em, created, utrSubmittedAt, now) {
  const c = cfgOf(conf), ts = em.paidAt, arr = em.arrivalAt, skew = c.clockSkew;
  if (ts === null || ts === undefined) return [false, em.timeConflict ? 'time_inconsistent' : 'time_unreadable'];
  if (ts > now + skew || (arr !== null && arr !== undefined && (ts > arr + skew || arr > now + skew))) return [false, 'future_timestamp'];
  if (ts < created - skew) return [false, 'payment_before_order'];
  const maxAge = em.paidSrc === 'body' ? c.maxPaymentAge : Math.min(c.maxPaymentAge, c.orderWindow + c.emailMaxDelay);
  if (ts > created + maxAge) return [false, 'payment_too_late'];
  if (utrSubmittedAt) {
    const tol = em.paidSrc === 'body' ? skew : c.emailMaxDelay;
    if (ts > utrSubmittedAt + tol) return [false, 'payment_after_utr_submit'];   // customer can't know a UTR before paying
  }
  return [true, ''];
}

/** emails: parsePaymentEmail() results. order: {amount(₹), created, utrSubmittedAt} in seconds. */
function evaluateEmails(conf, emails, order, now) {
  const exp = Math.round(Number(order.amount) * 100);
  const res = { state: 'not_found', reason: '', receivedPaise: null, paidAt: null };
  let matched = false, reject = '';
  for (const em of emails) {
    if (!(em.senderOk && em.utrMatch)) continue;
    matched = true;
    if (em.amountPaise === null) { reject = reject || 'amount_unreadable'; continue; }
    res.receivedPaise = em.amountPaise;
    if (em.amountPaise !== exp) { reject = 'amount_mismatch'; continue; }
    const [ok, why] = checkPaymentTime(conf, em, order.created, order.utrSubmittedAt, now);
    if (!ok) { reject = (!reject || reject === 'time_unreadable') ? why : reject; res.paidAt = em.paidAt; continue; }
    return { state: 'verified', reason: '', receivedPaise: em.amountPaise, paidAt: em.paidAt };
  }
  if (matched) { res.state = 'rejected'; res.reason = reject || 'unverified'; }
  return res;
}

/* ---------------- per-account breaker + serialisation ---------------- */
class AccountGate {
  constructor(conf) { this.c = cfgOf(conf); this.s = new Map(); this.q = new Map(); }
  _st(id) { let v = this.s.get(id); if (!v) { v = { fails: 0, pausedUntil: 0 }; this.s.set(id, v); } return v; }
  paused(id) { return Date.now() < this._st(id).pausedUntil; }
  record(id, ok) {
    const v = this._st(id);
    if (ok) { v.fails = 0; return false; }
    v.fails++;
    if (v.fails >= this.c.breakerThreshold) { v.pausedUntil = Date.now() + this.c.breakerPauseMs; v.fails = 0; return true; }
    return false;
  }
  reset(id) { this.s.delete(id); }
  /** one IMAP session per account at a time (Gmail throttles parallel logins) */
  run(id, fn) {
    const prev = this.q.get(id) || Promise.resolve();
    const next = prev.catch(() => {}).then(fn);
    this.q.set(id, next);
    next.finally(() => { if (this.q.get(id) === next) this.q.delete(id); }).catch(() => {});
    return next;
  }
}

/* ---------------- IMAP (needs: npm i imapflow mailparser) ---------------- */
function loadImap() {
  try { return { ImapFlow: require('imapflow').ImapFlow, simpleParser: require('mailparser').simpleParser }; }
  catch (e) { const err = new Error('IMAP libraries missing: run  npm i imapflow mailparser'); err.code = 'IMAP_LIBS_MISSING'; throw err; }
}
function newClient(conf, acct) {
  const c = cfgOf(conf), { ImapFlow } = loadImap();
  const client = new ImapFlow({
    host: 'imap.gmail.com', port: 993, secure: true, logger: false,
    auth: { user: acct.gmail, pass: acct.appPassword },
    connectionTimeout: c.imapTimeoutMs, greetingTimeout: c.imapTimeoutMs, socketTimeout: 30000
  });
  client.on('error', () => {});                 // an unhandled 'error' event would crash the whole server
  return client;
}
/** -> { ok, code } ; code: ok | login_failed | imap_unreachable | imap_libs_missing */
async function testLogin(conf, acct) {
  let client;
  try { client = newClient(conf, acct); await client.connect(); await client.logout(); return { ok: true, code: 'ok' }; }
  catch (e) {
    try { client && client.close(); } catch (_) {}
    if (e.code === 'IMAP_LIBS_MISSING') return { ok: false, code: 'imap_libs_missing' };
    const auth = e.authenticationFailed || /auth|invalid credentials|login|password/i.test(String(e.response || e.message || ''));
    return { ok: false, code: auth ? 'login_failed' : 'imap_unreachable' };
  }
}
/** Search the merchant's mailbox for Fam mails carrying this UTR. -> { status:'ok'|'error', emails, error } */
async function searchUtr(conf, acct, utr) {
  const c = cfgOf(conf), { simpleParser } = loadImap();
  if (!/^[A-Z0-9]{8,40}$/.test(String(utr || ''))) return { status: 'error', emails: [], error: 'bad_utr' };
  let client;
  try {
    client = newClient(c, acct);
    await client.connect();
    const emails = [];
    for (const box of ['INBOX', '[Gmail]/All Mail']) {
      let lock;
      try { lock = await client.getMailboxLock(box, { readOnly: true }); } catch (e) { continue; }
      try {
        const ids = new Set();
        for (const a of utrAliases(utr)) {
          let found;
          try { found = await client.search({ gmraw: `"${a} newer_than:${c.lookbackDays}d"` }, { uid: true }); }
          catch (e) { found = await client.search({ since: new Date(Date.now() - c.lookbackDays * 864e5), body: a }, { uid: true }); }
          (found || []).forEach(x => ids.add(x));
        }
        for (const uid of [...ids].slice(-c.maxFetch)) {
          try {
            const msg = await client.fetchOne(uid, { source: true, internalDate: true }, { uid: true });
            if (!msg || !msg.source || msg.source.length > c.maxMailBytes) continue;
            const p = await simpleParser(msg.source);
            const raw = msg.source.toString('latin1'), cut = raw.search(/\r?\n\r?\n/);
            emails.push(parsePaymentEmail(c, {
              rawHeaders: cut >= 0 ? raw.slice(0, cut) : raw,
              fromAddress: (p.from && p.from.value && p.from.value[0] && p.from.value[0].address) || '',
              subject: p.subject || '',
              text: ((p.text || '') + '\n' + (p.html ? htmlToText(p.html) : '')).replace(/\u00a0/g, ' ')
            }, utr, msg.internalDate ? Math.floor(new Date(msg.internalDate).getTime() / 1000) : null));
          } catch (e) { /* malformed mail: skip */ }
        }
      } finally { lock.release(); }
      if (emails.length) break;
    }
    await client.logout().catch(() => {});
    return { status: 'ok', emails, error: '' };
  } catch (e) {
    try { client && client.close(); } catch (_) {}
    if (e.code === 'IMAP_LIBS_MISSING') return { status: 'error', emails: [], error: 'imap_libs_missing' };
    const auth = e.authenticationFailed || /auth|invalid credentials|login|password/i.test(String(e.response || e.message || ''));
    return { status: 'error', emails: [], error: auth ? 'imap_login_failed' : 'imap_connection_failed' };
  }
}

module.exports = {
  DEFAULTS, normalizeUtr, utrAliases, utrKey, parseAmountPaise, utrInText, parseBodyDatetimes, htmlToText,
  authOk, parsePaymentEmail, checkPaymentTime, evaluateEmails, AccountGate, testLogin, searchUtr
};
