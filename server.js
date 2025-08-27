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
app.post(
  '/api/import-employees',
  ensureAuthenticated,
  ensureRole('admin'),
  upload.single('file'),
  (req, res) => {
    if (!req.file) return res.status(400).send('ไม่พบไฟล์ที่อัปโหลด');

    const rows = [];
    const cleanup = () => fs.unlink(req.file.path, () => {});

    const pick = (...cands) => cands.find(v => v != null && String(v).trim() !== '');
    const toISODate = (s) => {
      if (!s) return null;
      let str = String(s).trim().replace(/\//g, '-');
      let m = str.match(/^(\d{1,2})-(\d{1,2})-(\d{2,4})$/); // dd-mm-yyyy | dd-mm-yy
      if (m) {
        let [, d, mo, y] = m;
        let year = parseInt(y, 10);
        if (year < 100) year += 2000;      // 67 -> 2067 (ถ้าจะตีเป็น 1967 แก้ตามนโยบายคุณ)
        if (year > 2400) year -= 543;      // พ.ศ. -> ค.ศ.
        return `${year}-${String(mo).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
      }
      m = str.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/); // yyyy-mm-dd
      if (m) {
        let [, y, mo, d] = m;
        let year = parseInt(y, 10);
        if (year > 2400) year -= 543;
        return `${year}-${String(mo).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
      }
      return null; // ไม่รู้ฟอร์แมต
    };

    fs.createReadStream(req.file.path)
      .pipe(csv.parse({ columns: true, trim: true }))
      .on('data', r => rows.push(r))
      .on('error', err => {
        console.error('CSV error:', err);
        cleanup();
        res.status(500).send('อ่านไฟล์ไม่สำเร็จ');
      })
      .on('end', async () => {
        try {
          const ops = [];
          let skipped = 0;

          for (const row of rows) {
            const employeeCode = pick(row.employeeCode, row.EmployeeCode, row['รหัสพนักงาน']);
            const startDateRaw = pick(row.startDate, row.StartDate, row['วันเริ่มงาน']);
            if (!employeeCode || !startDateRaw) { skipped++; continue; }

            const startDateISO = toISODate(startDateRaw);
            if (!startDateISO) { skipped++; continue; }

            // ตั้งรหัสผ่านเฉพาะตอน insert
            const hashed = await bcrypt.hash(String(startDateISO), 10);

            ops.push({
              updateOne: {
                filter: { username: employeeCode },
                update: {
                  $set: {
                    username: employeeCode,
                    role: 'user',
                    name: employeeCode,     // ไม่มี name => ใช้ employeeCode แทน
                    employeeCode,
                    startDate: startDateISO,
                  },
                  $setOnInsert: { password: hashed }
                },
                upsert: true
              }
            });
          }

          if (ops.length === 0) return res.status(400).send('ไม่มีข้อมูลที่เหมาะสมสำหรับนำเข้า');

          const result = await User.bulkWrite(ops, { ordered: false });
          res.json({
            message: 'นำเข้าข้อมูลพนักงานเรียบร้อยแล้ว',
            summary: {
              inserted: result.upsertedCount || 0,
              updated: result.modifiedCount || 0,
              skipped
            }
          });
        } catch (err) {
          console.error('Import error:', err);
          res.status(500).send('เกิดข้อผิดพลาดในการนำเข้าข้อมูล');
        } finally {
          cleanup();
        }
      });
  }
);


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


// ===== Settlement (Lite) – Preview / Commit / Export (Admin only) =====
const { ObjectId } = mongoose.Types;

// helper: แปลง 'YYYY-MM-DD' (Bangkok) → [start,end)
function thaiDayRange(dateStr /* 'YYYY-MM-DD' */) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr || '')) {
    throw new Error('รูปแบบวันที่ไม่ถูกต้อง (ต้องเป็น YYYY-MM-DD)');
  }
  const start = new Date(`${dateStr}T00:00:00+07:00`);
  const end   = new Date(start.getTime() + 24 * 60 * 60 * 1000);
  return { start, end };
}

// helper: ทำ settlement id อ่านง่าย
function makeSettlementId(merchantId, dateStr) {
  return `d${dateStr}_m${merchantId}`;
}

// สร้างบัญชีระบบปลายทาง payout ถ้าไม่เจอ
async function ensureSystemClearingUser() {
  let u = await User.findOne({ username: '_system_clearing' });
  if (!u) {
    const pwd = crypto.randomBytes(6).toString('hex');
    const hashed = await bcrypt.hash(pwd, 10);
    u = await User.create({
      username: '_system_clearing',
      password: hashed,
      role: 'admin',
      name: 'SYSTEM_CLEARING',
      credit: 0
    });
  }
  return u;
}

/**
 * GET /api/settlement/preview?merchantId=<id>&date=YYYY-MM-DD
 * แสดงยอดรวม/จำนวนรายการของธุรกรรม pay → merchant ที่ยังไม่ปิดรอบ ของวันนั้น
 */
app.get('/api/settlement/preview',
  ensureAuthenticated, ensureRole('admin'),
  async (req, res) => {
    try {
      const { merchantId, date } = req.query;
      if (!merchantId || !ObjectId.isValid(merchantId)) {
        return res.status(400).json({ ok: false, message: 'merchantId ไม่ถูกต้อง' });
      }
      if (!date) return res.status(400).json({ ok: false, message: 'ต้องระบุ date' });

      const { start, end } = thaiDayRange(date);

      // ตรวจร้าน
      const merchant = await User.findOne({ _id: merchantId, role: 'merchant' })
        .select('username name credit').lean();
      if (!merchant) return res.status(404).json({ ok: false, message: 'ไม่พบร้านค้า' });

      const match = { to: new ObjectId(merchantId), type: 'pay', settled: false, createdAt: { $gte: start, $lt: end } };
      const agg = await Transaction.aggregate([
        { $match: match },
        { $group: { _id: null, tx_count: { $sum: 1 }, gross_amount: { $sum: '$amount' },
                    first_at: { $min: '$createdAt' }, last_at: { $max: '$createdAt' } } }
      ]);

      const tx_count = agg[0]?.tx_count || 0;
      const gross = agg[0]?.gross_amount || 0;
      const settlement_id = makeSettlementId(merchantId, date);

      return res.json({
        ok: true,
        merchant: {
          id: merchantId,
          name: merchant.name || merchant.username,
          credit_current: merchant.credit || 0
        },
        period: { start, end, date },
        settlement_id,
        tx_count,
        gross_amount: gross,
        net_amount: gross // โหมด Lite: ไม่มีค่าธรรมเนียม
      });
    } catch (e) {
      console.error('preview error:', e);
      res.status(500).json({ ok: false, message: 'server error' });
    }
  }
);

/**
 * POST /api/settlement/commit
 * body: { merchantId, date }  // date = YYYY-MM-DD (Bangkok)
 * ทำ: คำนวณยอด → บันทึก payout → มาร์ก pay เป็น settled (ทั้งหมดใน txn เดียว)
 */
app.post('/api/settlement/commit',
  ensureAuthenticated, ensureRole('admin'),
  async (req, res) => {
    const sessionDb = await mongoose.startSession();
    sessionDb.startTransaction();
    try {
      const { merchantId, date } = req.body;
      if (!merchantId || !ObjectId.isValid(merchantId)) {
        throw new Error('merchantId ไม่ถูกต้อง');
      }
      if (!date) throw new Error('ต้องระบุ date');

      const { start, end } = thaiDayRange(date);
      const merchant = await User.findOne({ _id: merchantId, role: 'merchant' })
        .select('_id username name credit').session(sessionDb);
      if (!merchant) throw new Error('ไม่พบร้านค้า');

      // ดึงยอดรวมของ pay ที่ยังไม่ปิด
      const match = { to: merchant._id, type: 'pay', settled: false, createdAt: { $gte: start, $lt: end } };
      const agg = await Transaction.aggregate([
        { $match: match },
        { $group: { _id: null, tx_count: { $sum: 1 }, gross_amount: { $sum: '$amount' } } }
      ]).session(sessionDb);

      const tx_count = agg[0]?.tx_count || 0;
      const gross = agg[0]?.gross_amount || 0;
      if (tx_count === 0 || gross <= 0) {
        await sessionDb.abortTransaction();
        sessionDb.endSession();
        return res.status(400).json({ ok: false, message: 'ไม่มีธุรกรรมที่ต้องปิดรอบในวันนั้น' });
      }

      const settlement_id = makeSettlementId(String(merchant._id), date);
      const now = new Date();

      // สร้างบัญชีระบบ (ปลายทาง payout)
      const sys = await ensureSystemClearingUser();

      // 1) ลดเครดิตร้าน
      const updated = await User.findOneAndUpdate(
        { _id: merchant._id, credit: { $gte: gross } },
        { $inc: { credit: -gross } },
        { new: true, session: sessionDb }
      );
      if (!updated) throw new Error('เครดิตร้านไม่พอสำหรับการปิดรอบ');

      // 2) บันทึก payout (journal) จากร้าน → system
      await Transaction.create([{
        from: merchant._id,
        to: sys._id,
        type: 'payout',
        amount: gross,
        createdAt: now,
        settled: true,
        settlement_id,
        settled_at: now
      }], { session: sessionDb });

      // 3) มาร์ก pay ทั้งหมดในวันนั้นว่า settled
      await Transaction.updateMany(
        match,
        { $set: { settled: true, settlement_id, settled_at: now } },
        { session: sessionDb }
      );

      await sessionDb.commitTransaction();
      sessionDb.endSession();

      return res.json({
        ok: true,
        settlement_id,
        date,
        merchant: { id: String(merchant._id), name: merchant.name || merchant.username },
        tx_count,
        gross_amount: gross,
        net_amount: gross,
        merchant_credit_after: updated.credit
      });
    } catch (e) {
      await sessionDb.abortTransaction().catch(()=>{});
      sessionDb.endSession();
      console.error('commit error:', e);
      res.status(400).json({ ok: false, message: e.message || 'commit failed' });
    }
  }
);

/**
 * GET /api/settlement/:sid/export-ledger.csv
 * ส่งออกบรรทัดธุรกรรม pay ที่ถูกปิดด้วย settlement_id = :sid
 */
app.get('/api/settlement/:sid/export-ledger.csv',
  ensureAuthenticated, ensureRole('admin'),
  async (req, res) => {
    try {
      const sid = req.params.sid;
      const txs = await Transaction.find({ settlement_id: sid, type: 'pay' })
        .select('createdAt from to amount settled settlement_id settled_at')
        .lean();

      // ชื่อร้านเพื่อออกรายงาน
      const merchantId = sid.split('_m')[1];
      const merchant = merchantId ? await User.findById(merchantId).select('name username').lean() : null;

      let csvText = 'settlement_id,merchant_id,merchant_name,tx_id,created_at_utc,created_at_th,from_id,to_id,amount,settled,settled_at_th\n';
      for (const t of txs) {
        const th = t.createdAt ? new Date(t.createdAt).toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' }) : '';
        const st = t.settled_at ? new Date(t.settled_at).toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' }) : '';
        const mName = merchant ? (merchant.name || merchant.username) : '';
        csvText += [
          sid,
          merchantId || '',
          mName.includes(',') ? `"${mName}"` : mName,
          String(t._id),
          t.createdAt ? new Date(t.createdAt).toISOString() : '',
          th,
          t.from ? String(t.from) : '',
          t.to ? String(t.to) : '',
          t.amount ?? '',
          t.settled ? 'true' : 'false',
          st
        ].join(',') + '\n';
      }
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename=${sid}_ledger.csv`);
      res.send('\uFEFF' + csvText);
    } catch (e) {
      console.error('export-ledger error:', e);
      res.status(500).send('server error');
    }
  }
);

/**
 * GET /api/settlement/:sid/export-summary.csv
 * สรุปยอดรวมของรอบนั้นจากข้อมูลใน DB
 */
app.get('/api/settlement/:sid/export-summary.csv',
  ensureAuthenticated, ensureRole('admin'),
  async (req, res) => {
    try {
      const sid = req.params.sid;

      const merchantId = sid.split('_m')[1];
      const merchant = merchantId ? await User.findById(merchantId).select('name username').lean() : null;

      const agg = await Transaction.aggregate([
        { $match: { settlement_id: sid, type: 'pay' } },
        { $group: { _id: null, tx_count: { $sum: 1 }, gross_amount: { $sum: '$amount' },
                    first_at: { $min: '$createdAt' }, last_at: { $max: '$createdAt' } } }
      ]);

      const tx_count = agg[0]?.tx_count || 0;
      const gross = agg[0]?.gross_amount || 0;
      const firstAt = agg[0]?.first_at ? new Date(agg[0].first_at) : null;
      const lastAt  = agg[0]?.last_at  ? new Date(agg[0].last_at)  : null;

      // เดาวันจาก sid (dYYYY-MM-DD_m<id>)
      const dateMatch = /^d(\d{4}-\d{2}-\d{2})_m/.exec(sid);
      const dateStr = dateMatch ? dateMatch[1] : '';

      let csvText = 'settlement_id,merchant_id,merchant_name,date,tx_count,gross_amount,net_amount,first_tx_th,last_tx_th\n';
      const mName = merchant ? (merchant.name || merchant.username) : '';
      csvText += [
        sid,
        merchantId || '',
        mName.includes(',') ? `"${mName}"` : mName,
        dateStr,
        tx_count,
        gross,
        gross, // net = gross (โหมด Lite)
        firstAt ? firstAt.toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' }) : '',
        lastAt  ? lastAt.toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })  : ''
      ].join(',') + '\n';

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename=${sid}_summary.csv`);
      res.send('\uFEFF' + csvText);
    } catch (e) {
      console.error('export-summary error:', e);
      res.status(500).send('server error');
    }
  }
);

// Start
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
