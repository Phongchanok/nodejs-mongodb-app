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
//
// NOTE: The `xlsx` library was previously used to export user data to
// Excel files. Because that package currently has known security
// vulnerabilities and we only need to generate summary reports for
// download, the export has been rewritten to produce simple CSV
// text instead. Accordingly, there is no longer a need to import
// or install `xlsx`, and the export route streams CSV data directly.

// Load environment variables from .env file if present
dotenv.config();

// Pull connection settings from environment variables with sensible defaults
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/wallet-app';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_this_secret';

// Initialise the Express application
const app = express();

// Setup body parsing middleware to handle form submissions
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Connect to MongoDB using Mongoose
// Suppress strictQuery deprecation warning by explicitly setting the option.
// See https://mongoosejs.com/docs/guide.html#strictQuery for details.
mongoose.set('strictQuery', true);

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});
mongoose.connection.once('open', () => {
  console.log('MongoDB connected');
});

// Configure session store to use MongoDB for persistence
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGO_URI }),
    cookie: {
      maxAge: 1000 * 60 * 60 // 1 hour session
    }
  })
);

// Import the User model
const User = require('./models/User');

/**
 * Middleware to ensure that a user is authenticated. If not logged in,
 * redirect them back to the login page.
 */
function ensureAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  return res.redirect('/login.html');
}

/**
 * Middleware to restrict access to users with a specific role. If the
 * currently logged in user does not have the required role, return a
 * 403 response or redirect to the appropriate dashboard.
 *
 * @param {string} role - The required role for the route (e.g. 'admin').
 */
function ensureRole(role) {
  return function (req, res, next) {
    if (req.session && req.session.role === role) {
      return next();
    }
    // If the user is authenticated but lacks the required role, redirect them
    // to their own dashboard rather than the restricted page
    if (req.session && req.session.role) {
      return res.redirect('/' + req.session.role + '.html');
    }
    // Otherwise, ask them to log in
    return res.redirect('/login.html');
  };
}

/**
 * Serve static files from the "public" directory. This allows us to
 * deliver the HTML, CSS and client-side JavaScript files without any
 * server-side templating. When a user requests a file like
 * `/login.html` the file will be served from the `public` folder.
 */
app.use(express.static(path.join(__dirname, 'public')));

// Configure multer for uploading CSV files. Files will be stored in a
// temporary directory under "uploads/" and removed after processing.
const upload = multer({ dest: path.join(__dirname, 'uploads') });

// Handle the root request by redirecting to the appropriate page.
app.get('/', (req, res) => {
  // If the user has a role in their session, send them to their
  // dashboard. Otherwise, show the login page.
  if (req.session && req.session.role) {
    return res.redirect('/' + req.session.role + '.html');
  }
  res.redirect('/login.html');
});

/**
 * POST /register
 *
 * Handles new user registrations. This endpoint expects a username,
 * password and role. It checks for existing users with the same
 * username and uses bcrypt to hash the password before saving the
 * user document. Once created, the user is logged in immediately and
 * redirected to their dashboard.
 */
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  // Only admin users may create accounts and only for the merchant role.
  if (role !== 'merchant') {
    return res.status(403).send('การสมัครผู้ใช้ทั่วไปถูกปิด กรุณาติดต่อผู้ดูแลระบบ');
  }
  if (!req.session || req.session.role !== 'admin') {
    return res.status(403).send('มีเพียงแอดมินเท่านั้นที่สามารถสร้างบัญชีร้านค้าได้');
  }
  if (!username || !password) {
    return res.status(400).send('Missing required fields');
  }
  try {
    // Check if merchant already exists
    const existing = await User.findOne({ username });
    if (existing) {
      return res.status(400).send('User already exists');
    }
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hashed, role });
    res.status(200).send('ร้านค้าถูกสร้างเรียบร้อยแล้ว');
  } catch (err) {
    console.error('Error creating merchant:', err);
    res.status(500).send('Server error');
  }
});

/**
 * POST /login
 *
 * Authenticates a user. It expects a username and password. If the
 * credentials are valid, it stores the user ID and role in the session
 * and redirects to the respective dashboard. Invalid credentials
 * result in a 401 response.
 */
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    // Provide a more user‑friendly message in Thai when username
    // or password fields are not supplied.
    return res.status(400).send('กรุณากรอกชื่อผู้ใช้หรือรหัสผ่าน');
  }
  try {
    const user = await User.findOne({ username });
    if (!user) {
      // If no user found for the given username send a generic
      // invalid credentials message (Thai).
      return res.status(401).send('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      // Password does not match; send a generic invalid credentials message
      return res.status(401).send('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
    }
    // Save user info to the session
    req.session.userId = user._id.toString();
    req.session.role = user.role;
    res.redirect('/' + user.role + '.html');
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).send('Server error');
  }
});

/**
 * GET /logout
 *
 * Destroys the current session, effectively logging the user out. The
 * browser will be redirected back to the login page upon success.
 */
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

/**
 * GET /api/me
 *
 * Returns basic information about the currently logged-in user. If
 * there is no authenticated session, a 401 status is returned. This
 * endpoint is used by the client-side JavaScript to populate the
 * dashboard pages with real data such as the credit balance and role.
 */
app.get('/api/me', ensureAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId).lean();
    if (!user) {
      return res.status(404).send('User not found');
    }
    // Don't send the password hash to the client
    const { _id, username, role, credit } = user;
    res.json({ id: _id, username, role, credit });
  } catch (err) {
    console.error('Error fetching user info:', err);
    res.status(500).send('Server error');
  }
});

/**
 * GET /api/users
 *
 * Returns a list of all users. This route is restricted to admins.
 */
app.get('/api/users', ensureAuthenticated, ensureRole('admin'), async (req, res) => {
  try {
    const users = await User.find().select('-password').lean();
    res.json(users);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).send('Server error');
  }
});

/**
 * POST /api/generate-qr
 *
 * Generates a QR code for a payment request. The logged‑in user
 * specifies an amount to transfer; the server creates a payload
 * containing the sender’s user ID, the amount and a timestamp, then
 * encodes it as a data URI via the `qrcode` package. The response
 * includes the data URI that can be used as the source of an <img>
 * element. Only authenticated users may generate QR codes.
 */
/**app.post('/api/generate-qr', ensureAuthenticated, async (req, res) => {
  const { amount } = req.body;
  const value = parseFloat(amount);
  if (isNaN(value) || value <= 0) {
    return res.status(400).send('Invalid amount');
  }
  const payload = {
    from: req.session.userId,
    amount: value,
    timestamp: Date.now()
  };
  try {
    const qrDataUri = await QRCode.toDataURL(JSON.stringify(payload));
    res.json({ qrDataUri });
  } catch (err) {
    console.error('Error generating QR code:', err);
    res.status(500).send('Error generating QR code');
  }
});*/

// POST /api/merchant-qr  (merchant-only)
// ตอบกลับเป็น data URI สำหรับ <img src="..."> ได้เลย
app.post('/api/merchant-qr', ensureAuthenticated, ensureRole('merchant'), async (req, res) => {
  try {
    const payload = {
      type: 'merchant-receive',
      to: req.session.userId, // ร้านค้าปัจจุบัน
      v: 1,                    // เวอร์ชัน payload เผื่อเปลี่ยนสคีมาในอนาคต
      ts: Date.now()
    };
    const qrDataUri = await QRCode.toDataURL(JSON.stringify(payload));
    res.json({ qrDataUri });
  } catch (err) {
    console.error('Error generating merchant QR:', err);
    res.status(500).send('Error generating merchant QR');
  }
});

// POST /api/pay-qr  (user-only)
app.post('/api/pay-qr', ensureAuthenticated, ensureRole('user'), async (req, res) => {
  const { payload, amount } = req.body;
  if (!payload) return res.status(400).send('Missing payload');

  let data;
  try { data = JSON.parse(payload); } catch { return res.status(400).send('Invalid payload'); }

  if (data?.type !== 'merchant-receive' || !data?.to) {
    return res.status(400).send('Invalid QR type or destination');
  }

  // amount ต้องเป็นจำนวนเต็มบวก
  const value = Math.trunc(Number(amount));
  if (!Number.isFinite(value) || value <= 0) {
    return res.status(400).send('Invalid amount (ต้องเป็นจำนวนเต็มมากกว่า 0)');
  }

  // ป้องกันจ่ายให้ตัวเอง (ในกรณี user มี role merchant ด้วย – กันไว้เผื่อ)
  if (String(data.to) === String(req.session.userId)) {
    return res.status(400).send('ไม่สามารถจ่ายให้ตัวเองได้');
  }

  try {
    const payer = await User.findById(req.session.userId);
    const merchant = await User.findById(data.to);
    if (!payer || !merchant) return res.status(404).send('User or merchant not found');
    if (merchant.role !== 'merchant') return res.status(400).send('ปลายทางไม่ใช่ร้านค้า');

    // เครดิตต้องพอ
    if (payer.credit < value) return res.status(400).send('เครดิตไม่พอ');

    // โอนแบบง่าย (ถ้าต้องกัน concurrent race: ใช้ transaction/atomic ops เพิ่มได้)
    payer.credit -= value;
    merchant.credit += value;
    await payer.save();
    await merchant.save();

    await Transaction.create({
      from: payer._id,
      to: merchant._id,
      amount: value,
      timestamp: new Date(),
      used: true
    });

    res.json({
      message: 'ชำระสำเร็จ',
      payerCredit: payer.credit,
      merchantCredit: merchant.credit
    });
  } catch (err) {
    console.error('Error paying via QR:', err);
    res.status(500).send('Server error');
  }
});


/**
 * POST /api/redeem-qr
 *
 * Processes a scanned QR code. The client sends the `payload` string
 * extracted from the QR code. The server parses the JSON to
 * determine the sender and amount, ensures the QR has not been
 * redeemed before, validates that the sender has sufficient credit
 * and that the merchant is not sending to themselves, then updates
 * both balances atomically. A transaction record is created to
 * prevent re-use of the QR code. Only merchants (and admins) may
 * redeem credits.
 */
/**app.post('/api/redeem-qr', ensureAuthenticated, ensureRole('merchant'), async (req, res) => {
  const { payload } = req.body;
  if (!payload) {
    return res.status(400).send('Missing payload');
  }
  let data;
  try {
    data = JSON.parse(payload);
  } catch (err) {
    return res.status(400).send('Invalid payload format');
  }
  const { from, amount, timestamp } = data;
  const value = parseFloat(amount);
  if (!from || isNaN(value) || value <= 0) {
    return res.status(400).send('Invalid payload data');
  }
  // Prevent merchants from redeeming their own QR
  if (from === req.session.userId) {
    return res.status(400).send('Cannot redeem your own QR code');
  }
  // Compute a unique token for this QR to prevent reuse
  const token = crypto.createHash('sha256').update(payload).digest('hex');
  try {
    // Check if already redeemed
    const existingTx = await Transaction.findOne({ token });
    if (existingTx) {
      return res.status(400).send('This QR code has already been redeemed');
    }
    // Validate sender and receiver exist
    const sender = await User.findById(from);
    const receiver = await User.findById(req.session.userId);
    if (!sender || !receiver) {
      return res.status(404).send('Sender or receiver not found');
    }
    if (sender.credit < value) {
      return res.status(400).send('Sender does not have enough credit');
    }
    // Perform transfer: deduct from sender and add to receiver
    sender.credit -= value;
    receiver.credit += value;
    await sender.save();
    await receiver.save();
    // Record transaction
    await Transaction.create({
      token,
      from: sender._id,
      to: receiver._id,
      amount: value,
      timestamp: new Date(timestamp),
      used: true
    });
    res.json({ message: 'เครดิตได้รับเรียบร้อย', senderCredit: sender.credit, receiverCredit: receiver.credit });
  } catch (err) {
    console.error('Error redeeming QR code:', err);
    res.status(500).send('Server error');
  }
});*/

/**
 * PUT /api/users/:id/credit
 *
 * Updates the credit balance for a given user. Only admins are allowed
 * to perform this action. The new credit value should be supplied in
 * the request body. The server responds with the updated user document
 * excluding the password hash.
 */
// แนะนำ: กำหนดเพดานบนที่เหมาะกับระบบของคุณ
const MAX_CREDIT = 1_000_000; // ปรับตามนโยบายได้

app.put('/api/users/:id/credit',
  ensureAuthenticated,
  ensureRole('admin'),
  async (req, res) => {
    const { id } = req.params;

    // รับค่ามาเป็นอะไรก็ได้ (string/number) แล้ว normalize ให้เป็นจำนวนเต็ม
    const incoming = req.body?.credit;
    if (typeof incoming === 'undefined') {
      return res.status(400).json({ message: 'ต้องระบุค่า credit' });
    }

    const normalized = Math.trunc(Number(incoming));

    // ตรวจว่าเป็นจำนวนเต็มจริงและไม่ติดลบ/ไม่เกินเพดาน
    if (!Number.isFinite(normalized) || normalized < 0) {
      return res.status(400).json({ message: 'credit ต้องเป็นจำนวนเต็มตั้งแต่ 0 ขึ้นไป' });
    }
    if (normalized > MAX_CREDIT) {
      return res.status(400).json({ message: `credit ต้องไม่เกิน ${MAX_CREDIT}` });
    }

    try {
      const user = await User.findByIdAndUpdate(
        id,
        { $set: { credit: normalized } }, // ใช้ $set เพื่อชัดเจน
        { new: true, runValidators: true, context: 'query' }
      )
      .select('-password')
      .lean();

      if (!user) {
        return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
      }
      return res.json(user);
    } catch (err) {
      console.error('Error updating credit:', err);
      return res.status(500).json({ message: 'Server error' });
    }
  }
);

/**
 * GET /api/export-users
 *
 * Generates an Excel (.xlsx) file summarising all users and their credit
 * balances. Only admins may access this endpoint. The resulting file
 * contains columns for username, role and credit, and includes a
 * final row showing the total credit across all users. The file is
 * streamed directly in the response with appropriate headers for
 * browser download.
 */
app.get('/api/export-users', ensureAuthenticated, ensureRole('admin'), async (req, res) => {
  try {
    // Fetch all users (excluding passwords)
    const users = await User.find().select('username role credit').lean();
    // Prepare CSV data: header row
    let csv = 'Username,Role,Credit\n';
    let totalCredit = 0;
    users.forEach(u => {
      // Accumulate total credit
      const credit = u.credit || 0;
      totalCredit += credit;
      // Escape commas in username or role if any by wrapping in quotes
      const username = String(u.username).includes(',') ? '"' + u.username + '"' : u.username;
      const role = String(u.role).includes(',') ? '"' + u.role + '"' : u.role;
      csv += `${username},${role},${credit}\n`;
    });
    // Add summary row
    csv += `รวมทั้งหมด,,${totalCredit}\n`;
    // Set headers for CSV download
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename=summary.csv');
    res.send('\\uFEFF' + csv);
  } catch (err) {
    console.error('Error exporting users:', err);
    res.status(500).send('Server error');
  }
});

/**
 * POST /api/import-employees
 *
 * Allows an admin to import employee records from a CSV file. The CSV
 * should contain the columns: name, employeeCode, startDate. For each
 * row, the endpoint will create or update a user document. The
 * employeeCode will be used as the username, and the startDate will
 * be hashed to become the password. The role of imported users is
 * always set to 'user'. The endpoint requires authentication and
 * admin privileges.
 */
app.post('/api/import-employees', ensureAuthenticated, ensureRole('admin'), upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('ไม่พบไฟล์ที่อัปโหลด');
  }
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
          if (!employeeCode || !startDate) {
            continue; // Skip incomplete rows
          }
          // Hash the start date as the password
          const hashed = await bcrypt.hash(startDate, 10);
          // Upsert the user document
          await User.updateOne(
            { username: employeeCode },
            {
              username: employeeCode,
              password: hashed,
              role: 'user',
              name: name || employeeCode,
              employeeCode: employeeCode,
              startDate: startDate
            },
            { upsert: true }
          );
        }
        res.send('นำเข้าข้อมูลพนักงานเรียบร้อยแล้ว');
      } catch (err) {
        console.error('Error importing employees:', err);
        res.status(500).send('เกิดข้อผิดพลาดในการนำเข้าข้อมูล');
      } finally {
        // Remove the uploaded file
        fs.unlink(req.file.path, () => {});
      }
    });
});

// ชื่อร้าน/ผู้ใช้แบบย่อ (ใช้สำหรับโชว์ในโมดัล)
app.get('/api/user-basic', ensureAuthenticated, async (req, res) => {
  const { id } = req.query;
  if (!id) return res.status(400).send('missing id');
  const u = await User.findById(id).select('username name role').lean();
  if (!u) return res.status(404).send('not found');
  res.json(u);
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});