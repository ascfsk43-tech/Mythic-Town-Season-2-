'use strict';
/*
  Mythic Town Season 2 — Store server
  بدون أي مكتبات خارجية: يكفي Node.js 16 أو أحدث.
  التشغيل:  node server.js     (ثم افتح http://localhost:3000)

  كل شيء يُحفظ في ملفات:
    data/products.json   المنتجات
    data/settings.json   إعدادات المتجر (وكلمة مرور الأدمن مشفّرة)
    data/orders.json     الطلبات
    logs/orders.log      سجل الطلبات
    logs/admin.log       سجل عمليات الأدمن (دخول، تعديل، حذف...)
    logs/server.log      سجل السيرفر والأخطاء
    public/uploads/      صور المنتجات المرفوعة
*/
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT, 10) || 3000;
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const ROOT = __dirname;
const PUB = path.join(ROOT, 'public');
const DATA = path.join(ROOT, 'data');
const LOGS = path.join(ROOT, 'logs');
const UPLOADS = path.join(PUB, 'uploads');
[DATA, LOGS, UPLOADS].forEach(d => fs.mkdirSync(d, { recursive: true }));

/* ---------- ملفات ---------- */
function readJSON(name, fallback) {
  try { return JSON.parse(fs.readFileSync(path.join(DATA, name), 'utf8')); }
  catch (e) { return fallback; }
}
function writeJSON(name, value) {
  const p = path.join(DATA, name);
  fs.writeFileSync(p + '.tmp', JSON.stringify(value, null, 2));
  fs.renameSync(p + '.tmp', p);
}
function log(file, msg) {
  const line = '[' + new Date().toISOString() + '] ' + String(msg).replace(/[\r\n]+/g, ' ') + '\n';
  try { fs.appendFileSync(path.join(LOGS, file + '.log'), line); } catch (e) { console.error(e); }
}

/* ---------- كلمة المرور ---------- */
function hashPass(pass, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(String(pass), salt, 32).toString('hex');
}
function checkPass(pass, stored) {
  const [salt, hash] = String(stored || '').split(':');
  if (!salt || !hash) return false;
  const a = Buffer.from(hash, 'hex');
  const b = crypto.scryptSync(String(pass), salt, 32);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/* ---------- القيم الافتراضية (أول تشغيل) ---------- */
const DEFAULT_SETTINGS = {
  name: 'Mythic Town Season 2',
  tagline: 'متجر السيرفر الرسمي: الشخصيات والمركبات والبكجات',
  currency: '$',
  link: '',
  hero: '',
  webhook: '',
  cats: ['الشخصيات | Characters', 'المركبات الفارهة | Luxury Vehicles', 'مركبات السيدان | Sedan Vehicles', 'مركبات الدفع الرباعي | SUVs & Off-Road', 'البكجات | Packages'],
  passHash: ''
};
const DEFAULT_PRODUCTS = [
  { id: 'p1', name: 'منتج تجريبي 1', price: 25, cat: 'مركبات السيدان | Sedan Vehicles', desc: 'هذا منتج تجريبي. من وضع الأدمن عدّل الاسم والسعر والوصف والصورة.', img: '' },
  { id: 'p2', name: 'منتج تجريبي 2', price: 50, cat: 'الشخصيات | Characters', desc: 'يظهر الوصف عند الضغط على البطاقة.', img: '' },
  { id: 'p3', name: 'منتج تجريبي 3', price: 120, cat: 'المركبات الفارهة | Luxury Vehicles', desc: '', img: '' },
  { id: 'p4', name: 'منتج تجريبي 4', price: 200, cat: 'البكجات | Packages', desc: '', img: '' }
];

let settings = Object.assign({}, DEFAULT_SETTINGS, readJSON('settings.json', {}));
if (!settings.passHash) {
  settings.passHash = hashPass(process.env.ADMIN_PASSWORD || 'admin123');
  log('server', 'تم إنشاء كلمة مرور الأدمن الافتراضية');
}
writeJSON('settings.json', settings);
let products = readJSON('products.json', null);
if (!Array.isArray(products)) { products = DEFAULT_PRODUCTS; writeJSON('products.json', products); }
let orders = readJSON('orders.json', []);
if (!Array.isArray(orders)) orders = [];

const publicSettings = () => ({
  name: settings.name, tagline: settings.tagline, currency: settings.currency,
  link: settings.link, hero: settings.hero, cats: settings.cats
});

/* ---------- جلسات الأدمن ---------- */
const sessions = new Map();           // token -> انتهاء الصلاحية
const SESSION_MS = 12 * 3600 * 1000;
const failed = new Map();             // ip -> [أوقات المحاولات الفاشلة]
const orderHits = new Map();          // ip -> [أوقات الطلبات]

function ipOf(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  return req.socket.remoteAddress || '?';
}
function recent(map, ip, windowMs) {
  const now = Date.now();
  const arr = (map.get(ip) || []).filter(t => now - t < windowMs);
  map.set(ip, arr);
  return arr;
}
function authed(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  if (!m) return false;
  const exp = sessions.get(m[1]);
  if (!exp) return false;
  if (exp < Date.now()) { sessions.delete(m[1]); return false; }
  return true;
}

/* ---------- أدوات ---------- */
const str = (v, max) => String(v == null ? '' : v).trim().slice(0, max);
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject({ code: 413, msg: 'الحجم كبير جداً' }); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch (e) { reject({ code: 400, msg: 'بيانات غير صالحة' }); }
    });
    req.on('error', () => reject({ code: 400, msg: 'خطأ في الطلب' }));
  });
}
function validImg(v) {
  v = str(v, 500);
  if (!v) return '';
  if (/^\/uploads\/[a-f0-9]{16}\.(jpg|png|webp)$/.test(v)) return v;
  if (/^https?:\/\/[^\s"'<>]+$/i.test(v)) return v;
  return '';
}
function isUploadUrl(u) { return /^\/uploads\/[a-f0-9]{16}\.(jpg|png|webp)$/.test(u || ''); }
function cleanupImage(url) {
  if (!isUploadUrl(url)) return;
  if (products.some(p => p.img === url) || settings.hero === url) return;
  fs.unlink(path.join(PUB, url), () => {});
}
function validProduct(b, id) {
  const name = str(b.name, 80);
  const price = Number(b.price);
  if (!name) return { err: 'اسم المنتج مطلوب' };
  if (!isFinite(price) || price < 0 || price > 1e7) return { err: 'السعر غير صحيح' };
  return { value: { id, name, price: Math.round(price * 100) / 100, cat: str(b.cat, 80), desc: str(b.desc, 2000), img: validImg(b.img) } };
}

/* ---------- ديسكورد ويب هوك (اختياري) ---------- */
function notifyDiscord(order) {
  const url = settings.webhook;
  if (!/^https:\/\/(discord|discordapp)\.com\/api\/webhooks\/[\w\-\/]+$/.test(url || '')) return;
  const payload = JSON.stringify({
    allowed_mentions: { parse: [] },
    embeds: [{
      title: 'طلب جديد #' + order.id,
      color: 0x154bb7,
      fields: [
        { name: 'اسم اللعبة', value: order.name || '-', inline: true },
        { name: 'ديسكورد', value: order.discord || '-', inline: true },
        { name: 'المنتجات', value: order.items.map(i => i.name + ' × ' + i.qty).join('\n').slice(0, 1000) || '-' },
        { name: 'الإجمالي', value: order.total + ' ' + order.currency, inline: true },
        { name: 'اقتراح', value: order.note ? order.note.slice(0, 500) : '-' }
      ],
      timestamp: order.createdAt
    }]
  });
  const u = new URL(url);
  const r = https.request({ hostname: u.hostname, path: u.pathname + u.search, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, resp => {
    resp.resume();
    if (resp.statusCode >= 300) log('server', 'فشل إرسال الويب هوك: ' + resp.statusCode);
  });
  r.on('error', e => log('server', 'خطأ الويب هوك: ' + e.message));
  r.setTimeout(8000, () => r.destroy());
  r.end(payload);
}

/* ---------- API ---------- */
async function api(req, res, url) {
  const m = req.method;
  const p = url.pathname;
  const ip = ipOf(req);

  if (m === 'GET' && p === '/api/state') return send(res, 200, { settings: publicSettings(), products });

  if (m === 'POST' && p === '/api/login') {
    if (recent(failed, ip, 10 * 60 * 1000).length >= 5) {
      log('admin', 'دخول محظور مؤقتاً (محاولات كثيرة) ip=' + ip);
      return send(res, 429, { error: 'محاولات كثيرة، جرّب بعد 10 دقائق' });
    }
    const b = await readBody(req, 2000);
    if (checkPass(b.password, settings.passHash)) {
      const token = crypto.randomBytes(24).toString('hex');
      sessions.set(token, Date.now() + SESSION_MS);
      log('admin', 'تسجيل دخول ناجح ip=' + ip);
      return send(res, 200, { token });
    }
    failed.get(ip).push(Date.now());
    log('admin', 'محاولة دخول فاشلة ip=' + ip);
    return send(res, 401, { error: 'كلمة المرور غير صحيحة' });
  }

  if (m === 'POST' && p === '/api/orders') {
    if (recent(orderHits, ip, 60 * 1000).length >= 6) return send(res, 429, { error: 'طلبات كثيرة، انتظر دقيقة' });
    const b = await readBody(req, 20000);
    const name = str(b.name, 40), discord = str(b.discord, 40), note = str(b.note, 500);
    if (!name) return send(res, 400, { error: 'اكتب اسمك في اللعبة' });
    if (!discord) return send(res, 400, { error: 'اكتب يوزر الديسكورد' });
    if (!Array.isArray(b.items) || !b.items.length || b.items.length > 30) return send(res, 400, { error: 'السلة فارغة' });
    const items = [];
    for (const it of b.items) {
      const prod = products.find(x => x.id === it.id);
      const qty = Math.floor(Number(it.qty));
      if (!prod) return send(res, 400, { error: 'أحد المنتجات لم يعد متوفراً، حدّث الصفحة' });
      if (!(qty >= 1 && qty <= 99)) return send(res, 400, { error: 'الكمية غير صحيحة' });
      items.push({ id: prod.id, name: prod.name, price: prod.price, qty });
    }
    const total = Math.round(items.reduce((s, i) => s + i.price * i.qty, 0) * 100) / 100;
    const id = orders.reduce((mx, o) => Math.max(mx, o.id), 1000) + 1;
    const order = { id, createdAt: new Date().toISOString(), name, discord, note, items, total, currency: settings.currency, status: 'new', ip };
    orders.push(order);
    writeJSON('orders.json', orders);
    orderHits.get(ip).push(Date.now());
    log('orders', '#' + id + ' | اللعبة=' + name + ' | ديسكورد=' + discord + ' | ' +
      items.map(i => i.name + ' x' + i.qty + ' @' + i.price).join(', ') + ' | الإجمالي=' + total + ' ' + settings.currency +
      (note ? ' | اقتراح=' + note : '') + ' | ip=' + ip);
    notifyDiscord(order);
    return send(res, 200, { id, total, currency: settings.currency });
  }

  /* ---- من هنا فصاعداً: للأدمن فقط ---- */
  if (p.startsWith('/api/admin/')) {
    if (!authed(req)) return send(res, 401, { error: 'غير مصرّح، سجّل الدخول' });

    if (m === 'GET' && p === '/api/admin/settings') {
      return send(res, 200, Object.assign(publicSettings(), { webhook: settings.webhook }));
    }
    if (m === 'PUT' && p === '/api/admin/settings') {
      const b = await readBody(req, 20000);
      const cats = Array.isArray(b.cats) ? b.cats.map(c => str(c, 80)).filter(Boolean).slice(0, 30) : [];
      if (!cats.length) return send(res, 400, { error: 'أضف قسماً واحداً على الأقل' });
      const oldHero = settings.hero;
      settings.name = str(b.name, 60) || DEFAULT_SETTINGS.name;
      settings.tagline = str(b.tagline, 140);
      settings.currency = str(b.currency, 10) || '$';
      settings.link = /^https?:\/\//i.test(b.link || '') ? str(b.link, 300) : '';
      settings.hero = validImg(b.hero);
      settings.webhook = /^https:\/\/(discord|discordapp)\.com\/api\/webhooks\//.test(b.webhook || '') ? str(b.webhook, 300) : '';
      settings.cats = cats;
      writeJSON('settings.json', settings);
      if (oldHero !== settings.hero) cleanupImage(oldHero);
      log('admin', 'تعديل إعدادات المتجر ip=' + ip);
      return send(res, 200, { ok: true });
    }
    if (m === 'POST' && p === '/api/admin/password') {
      const b = await readBody(req, 1000);
      const pw = String(b.password || '');
      if (pw.length < 6) return send(res, 400, { error: 'كلمة المرور 6 أحرف على الأقل' });
      settings.passHash = hashPass(pw);
      writeJSON('settings.json', settings);
      sessions.clear();
      log('admin', 'تغيير كلمة مرور الأدمن ip=' + ip);
      return send(res, 200, { ok: true, relogin: true });
    }
    if (m === 'POST' && p === '/api/admin/upload') {
      const b = await readBody(req, 6 * 1024 * 1024);
      const mt = /^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+\/=]+)$/.exec(b.dataUrl || '');
      if (!mt) return send(res, 400, { error: 'صيغة الصورة غير مدعومة' });
      const buf = Buffer.from(mt[2], 'base64');
      if (buf.length > 4 * 1024 * 1024) return send(res, 413, { error: 'الصورة كبيرة (الحد 4MB)' });
      const ext = mt[1] === 'jpeg' ? 'jpg' : mt[1];
      const file = crypto.randomBytes(8).toString('hex') + '.' + ext;
      fs.writeFileSync(path.join(UPLOADS, file), buf);
      log('admin', 'رفع صورة ' + file + ' (' + Math.round(buf.length / 1024) + 'KB) ip=' + ip);
      return send(res, 200, { url: '/uploads/' + file });
    }
    if (m === 'POST' && p === '/api/admin/products') {
      const r = validProduct(await readBody(req, 20000), 'p' + Date.now().toString(36) + crypto.randomBytes(2).toString('hex'));
      if (r.err) return send(res, 400, { error: r.err });
      products.push(r.value);
      writeJSON('products.json', products);
      log('admin', 'إضافة منتج "' + r.value.name + '" بسعر ' + r.value.price + ' ip=' + ip);
      return send(res, 200, r.value);
    }
    let mm = /^\/api\/admin\/products\/([\w\-]+)$/.exec(p);
    if (mm && m === 'PUT') {
      const i = products.findIndex(x => x.id === mm[1]);
      if (i < 0) return send(res, 404, { error: 'المنتج غير موجود' });
      const r = validProduct(await readBody(req, 20000), mm[1]);
      if (r.err) return send(res, 400, { error: r.err });
      const old = products[i];
      products[i] = r.value;
      writeJSON('products.json', products);
      if (old.img !== r.value.img) cleanupImage(old.img);
      log('admin', 'تعديل منتج "' + old.name + '" -> "' + r.value.name + '" سعر ' + old.price + ' -> ' + r.value.price + ' ip=' + ip);
      return send(res, 200, r.value);
    }
    if (mm && m === 'DELETE') {
      const i = products.findIndex(x => x.id === mm[1]);
      if (i < 0) return send(res, 404, { error: 'المنتج غير موجود' });
      const [gone] = products.splice(i, 1);
      writeJSON('products.json', products);
      cleanupImage(gone.img);
      log('admin', 'حذف منتج "' + gone.name + '" ip=' + ip);
      return send(res, 200, { ok: true });
    }
    if (m === 'GET' && p === '/api/admin/orders') {
      return send(res, 200, { orders: orders.slice().reverse() });
    }
    mm = /^\/api\/admin\/orders\/(\d+)$/.exec(p);
    if (mm && m === 'PATCH') {
      const o = orders.find(x => x.id === Number(mm[1]));
      if (!o) return send(res, 404, { error: 'الطلب غير موجود' });
      const b = await readBody(req, 500);
      if (!['new', 'processing', 'done', 'canceled'].includes(b.status)) return send(res, 400, { error: 'حالة غير صحيحة' });
      const prev = o.status;
      o.status = b.status;
      writeJSON('orders.json', orders);
      log('admin', 'الطلب #' + o.id + ' الحالة ' + prev + ' -> ' + o.status + ' ip=' + ip);
      return send(res, 200, { ok: true });
    }
    mm = /^\/api\/admin\/logs\/(orders|admin|server)$/.exec(p);
    if (mm && m === 'GET') {
      let text = '';
      try {
        const f = path.join(LOGS, mm[1] + '.log');
        const st = fs.statSync(f);
        const max = 200 * 1024;
        const fd = fs.openSync(f, 'r');
        const len = Math.min(st.size, max);
        const buf = Buffer.alloc(len);
        fs.readSync(fd, buf, 0, len, st.size - len);
        fs.closeSync(fd);
        text = buf.toString('utf8');
      } catch (e) { text = ''; }
      return send(res, 200, { text });
    }
  }
  return send(res, 404, { error: 'غير موجود' });
}

/* ---------- ملفات الموقع ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
function serveStatic(req, res, url) {
  let rel = decodeURIComponent(url.pathname);
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(PUB, rel));
  if (!file.startsWith(PUB + path.sep)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('404'); }
    const ext = path.extname(file).toLowerCase();
    const headers = { 'Content-Type': MIME[ext] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff' };
    headers['Cache-Control'] = ext === '.html' ? 'no-cache' : 'public, max-age=3600';
    res.writeHead(200, headers);
    fs.createReadStream(file).pipe(res);
  });
}

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
    serveStatic(req, res, url);
  } catch (e) {
    if (e && e.code && e.msg) return send(res, e.code, { error: e.msg });
    log('server', 'خطأ: ' + (e && e.stack || e));
    if (!res.headersSent) send(res, 500, { error: 'خطأ في السيرفر' });
  }
}).listen(PORT, () => {
  log('server', 'تشغيل السيرفر على المنفذ ' + PORT);
  console.log('المتجر يعمل على http://localhost:' + PORT);
  console.log('كلمة مرور الأدمن الافتراضية: ' + (process.env.ADMIN_PASSWORD ? '(من ADMIN_PASSWORD)' : 'admin123') + '  — غيّرها من الإعدادات');
});
process.on('uncaughtException', e => log('server', 'uncaughtException: ' + (e && e.stack || e)));
