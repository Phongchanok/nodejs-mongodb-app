const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const QRCode = require('qrcode');
const crypto = require('crypto');
const Transaction = require('./models/Transaction');
const path = require('path');
const dotenv = require('dotenv');
const multer = require('multer');
const csv = require('csv-parse');
const fs = require('fs');

// Load environment variables
dotenv.config();

// Config
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/wallet-app';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_this_secret';
const QR_SECRET = process.env.QR_SECRET || 'dev-very-secret-change-me';

// App init
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Mongoose
mongoose.set('strictQuery', true);
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.connection.on('error', (err) => console.error('MongoDB connection error:', err));
mongoose.connection.once('open', () => console.log('MongoDB connected'));

// Session
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGO_URI }),
    cookie: { maxAge: 1000 * 60 * 60 } // 1h
  })
);

// Models
const User = require('./models/User');

// Auth middlewares
function ensureAuthenticated(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.redirect('/login.html');
}
function ensureRole(role) {
  return function (req, res, next) {
    if (req.session && req.session.role === role) return next();
    if (req.session && req.session.role) return res.redirect('/' + req.session.role + '.html');
    return res.redirect('/login.html');
  };
}

// base64url + HMAC helpers
function b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
}
function b64urlFromJSON(obj) { return b64urlEncode(JSON.stringify(obj)); }
function b64urlDecodeToJSON(b64) {
  const padded = b64.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((b64.length + 3) % 4);
  const json = Buffer.from(padded, 'base64').toString('utf8');
  return JSON.parse(json);
}
function hmacSign(rawBase64Url) {
  const mac = crypto.createHmac('sha256', QR_SECRET).update(rawBase64Url).digest();
  return b64urlEncode(mac);
}
function verifyHmac(rawBase64Url, sig) {
  const expected = hmacSign(rawBase64Url);
  const a = Buffer.from(expected);
  const b = Buffer.from(sig);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Upload (CSV)
const upload = multer({ dest: path.join(__dirname, 'uploads') });

// Root redirect
app.get('/', (req, res) => {
  if (req.session && req.session.role) return res.redirect('/' + req.session.role + '.html');
  res.redirect('/login.html');
});

// Register merchant (admin only)
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  if (role !== 'merchant') return res.status(403).send('การสมัครผู้ใช้ทั่วไปถูกปิด กรุณาติดต่อผู้ดูแลระบบ');
  if (!req.session || req.session.role !== 'admin') return res.status(403).send('มีเพียงแอดมินเท่านั้นที่สามารถสร้างบัญชีร้านค้าได้');
  if (!username || !password) return res.status(400).send('Missing required fields');

  try {
    const existing = await User.findOne({ username });
    if (existing) return res.status(400).send('User already exists');
    const hashed = await bcrypt.hash(password, 10);
    await User.create({ username, password: hashed, role });
    res.status(200).send('ร้านค้าถูกสร้างเรียบร้อยแล้ว');
  } catch (err) {
    console.error('Error creating merchant:', err);
    res.status(500).send('Server error');
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('กรุณากรอกชื่อผู้ใช้หรือรหัสผ่าน');
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).send('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).send('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
    req.session.userId = user._id.toString();
    req.session.role = user.role;
    res.redirect('/' + user.role + '.html');
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).send('Server error');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});

// Me
app.get('/api/me', ensureAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId).lean();
    if (!user) return res.status(404).send('User not found');
    const { _id, username, role, credit } = user;
    res.json({ id: _id, username, role, credit });
  } catch (err) {
    console.error('Error fetching user info:', err);
    res.status(500).send('Server error');
  }
});

// Admin: list users
app.get('/api/users', ensureAuthenticated, ensureRole('admin'), async (req, res) => {
  try {
    const users = await User.find().select('-password').lean();
    res.json(users);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).send('Server error');
  }
});

// Merchant QR (permanent, HMAC signed)
app.get('/api/merchant-qr', ensureAuthenticated, ensureRole('merchant'), async (req, res) => {
  try {
    const payload = { type: 'merchant-receive', to: req.session.userId, v: 1 };
    const raw = b64urlFromJSON(payload);
    const sig = hmacSign(raw);
    const qrText = JSON.stringify({ raw, sig });
    const dataUrl = await QRCode.toDataURL(qrText);
    res.json({ dataUrl });
  } catch (e) {
    console.error(e);
    res.status(500).send('สร้าง QR ไม่สำเร็จ');
  }
});

// Pay via QR (verify signature + atomic transfer)
app.post('/api/pay-qr', ensureAuthenticated, ensureRole('user'), async (req, res) => {
  try {
    const { payload, amount } = req.body;
    const amt = Math.trunc(Number(amount));
    if (!Number.isFinite(amt) || amt <= 0) return res.status(400).send('จำนวนเครดิตไม่ถูกต้อง');

    let merchantId = null;

    // New format: {raw, sig}
    try {
      const obj = JSON.parse(payload);
      if (obj && obj.raw && obj.sig) {
        if (!verifyHmac(obj.raw, obj.sig)) return res.status(400).send('QR ไม่ถูกต้อง (ลายเซ็นไม่ผ่าน)');
        const data = b64urlDecodeToJSON(obj.raw);
        if (data?.type !== 'merchant-receive' || !data?.to) return res.status(400).send('QR ไม่ถูกต้อง (ชนิด/ปลายทาง)');
        merchantId = data.to;
      }
    } catch (_) { /* อาจเป็น legacy */ }

    // Legacy: {type,to}
    if (!merchantId) {
      let legacy;
      try { legacy = JSON.parse(payload); } catch { /* noop */ }
      if (legacy?.type === 'merchant-receive' && legacy?.to) {
        merchantId = legacy.to;
        // (แนะนำ) ปิดโหมด legacy ในอนาคต
      }
    }

    if (!merchantId) return res.status(400).send('ไม่พบปลายทางร้านค้าจาก QR');

    const merchant = await User.findOne({ _id: merchantId, role: 'merchant' }).lean();
    if (!merchant) return res.status(400).send('ไม่พบร้านค้า');

    const sessionDb = await mongoose.startSession();
    sessionDb.startTransaction();
    try {
      const payer = await User.findOneAndUpdate(
        { _id: req.session.userId, credit: { $gte: amt } },
        { $inc: { credit: -amt } },
        { new: true, session: sessionDb }
      );
      if (!payer) throw new Error('เครดิตของคุณไม่พอ');

      const receiver = await User.findOneAndUpdate(
        { _id: merchantId, role: 'merchant' },
        { $inc: { credit: amt } },
        { new: true, session: sessionDb }
      );
      if (!receiver) throw new Error('ไม่พบปลายทางร้านค้า');

      await Transaction.create([{
        from: payer._id,
        to: receiver._id,
        type: 'pay',
        amount: amt,
        createdAt: new Date()
      }], { session: sessionDb });

      await sessionDb.commitTransaction();
      sessionDb.endSession();

      res.json({ ok: true, message: 'ชำระสำเร็จ' });
    } catch (err) {
      await sessionDb.abortTransaction().catch(()=>{});
      sessionDb.endSession();
      res.status(400).send(err.message || 'ชำระไม่สำเร็จ');
    }
  } catch (e) {
    res.status(500).send('เกิดข้อผิดพลาด');
  }
});

// Admin: set credit
const MAX_CREDIT = 1_000_000;
app.put('/api/users/:id/credit', ensureAuthenticated, ensureRole('admin'), async (req, res) => {
  const { id } = req.params;
  const incoming = req.body?.credit;
  if (typeof incoming === 'undefined') return res.status(400).json({ message: 'ต้องระบุค่า credit' });

  const normalized = Math.trunc(Number(incoming));
  if (!Number.isFinite(normalized) || normalized < 0) return res.status(400).json({ message: 'credit ต้องเป็นจำนวนเต็มตั้งแต่ 0 ขึ้นไป' });
  if (normalized > MAX_CREDIT) return res.status(400).json({ message: `credit ต้องไม่เกิน ${MAX_CREDIT}` });

  try {
    const user = await User.findByIdAndUpdate(
      id, { $set: { credit: normalized } }, { new: true, runValidators: true, context: 'query' }
    ).select('-password').lean();
    if (!user) return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
    res.json(user);
  } catch (err) {
    console.error('Error updating credit:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin: export CSV (with BOM)
app.get('/api/export-users', ensureAuthenticated, ensureRole('admin'), async (req, res) => {
  try {
    const users = await User.find().select('username role credit').lean();
    let csvText = 'Username,Role,Credit\n';
    let total = 0;
    users.forEach(u => {
      const credit = u.credit || 0;
      total += credit;
      const username = String(u.username).includes(',') ? '"' + u.username + '"' : u.username;
      const role = String(u.role).includes(',') ? '"' + u.role + '"' : u.role;
      csvText += `${username},${role},${credit}\n`;
    });
    csvText += `รวมทั้งหมด,,${total}\n`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename=summary.csv');
    res.send('\uFEFF' + csvText); // ใส่ BOM ให้ Excel อ่านไทยได้ถูก
  } catch (err) {
    console.error('Error exporting users:', err);
    res.status(500).send('Server error');
  }
});

// Admin: import employees from CSV
app.post('/api/import-employees', ensureAuthenticated, ensureRole('admin'), upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).send('ไม่พบไฟล์ที่อัปโหลด');

  const rows = [];
  fs.createReadStream(req.file.path)
    .pipe(csv.parse({ columns: true, trim: true }))
    .on('data', row => rows.push(row))
    .on('end', async () => {
      try {
        for (const row of rows) {
          const name = row.name || row.Name || row['ชื่อ'];
          const employeeCode = row.employeeCode || row.EmployeeCode || row['รหัสพนักงาน'];
          const startDate = row.startDate || row.StartDate || row['วันเริ่มงาน'];
          if (!employeeCode || !startDate) continue;
          const hashed = await bcrypt.hash(startDate, 10);
          await User.updateOne(
            { username: employeeCode },
            {
              username: employeeCode,
              password: hashed,
              role: 'user',
              name: name || employeeCode,
              employeeCode,
              startDate
            },
            { upsert: true }
          );
        }
        res.send('นำเข้าข้อมูลพนักงานเรียบร้อยแล้ว');
      } catch (err) {
        console.error('Error importing employees:', err);
        res.status(500).send('เกิดข้อผิดพลาดในการนำเข้าข้อมูล');
      } finally {
        fs.unlink(req.file.path, () => {});
      }
    });
});

// Basic lookup (for showing merchant name on user page)
app.get('/api/user-basic', ensureAuthenticated, async (req, res) => {
  try {
    const { id } = req.query;
    if (!id) return res.status(400).json({ ok: false, message: 'missing id' });
    const u = await User.findById(id).select('name username').lean();
    if (!u) return res.status(404).json({ ok: false, message: 'not found' });
    res.json(u);
  } catch (e) {
    res.status(500).json({ ok: false, message: 'server error' });
  }
});

// Start
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
