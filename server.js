// server.js
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const path = require('path');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Robust pool creation and debug preview
const dbConfig = (() => {
  if (process.env.DATABASE_URL) {
    return { connectionString: process.env.DATABASE_URL };
  }
  return {
    host: process.env.PGHOST || 'localhost',
    port: parseInt(process.env.PGPORT || '5432', 10),
    user: process.env.PGUSER || 'postgres',
    password: process.env.PGPASSWORD ? String(process.env.PGPASSWORD) : undefined,
    database: process.env.PGDATABASE || 'otpdb'
  };
})();

console.log('DB config preview:', {
  connectionString: dbConfig.connectionString ? 'using connectionString' : undefined,
  host: dbConfig.host,
  port: dbConfig.port,
  user: dbConfig.user,
  database: dbConfig.database
});

const pool = new Pool(dbConfig);

// Config
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const OTP_TTL = parseInt(process.env.OTP_TTL_SECONDS || '300', 10);

// Nodemailer transporter (uses SMTP settings from .env, Mailtrap uses sandbox.smtp.mailtrap.io and port 2525)
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587', 10),
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// Utility functions
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOtpEmail(toEmail, otp) {
  const mailOptions = {
    from: process.env.EMAIL_FROM,
    to: toEmail,
    subject: 'Your login OTP',
    text: `Your OTP for login is: ${otp}. It is valid for ${Math.floor(OTP_TTL / 60)} minutes.`
  };
  return transporter.sendMail(mailOptions);
}

async function findUserByIdentifier(identifier) {
  const q = `SELECT id, username, email, password_hash FROM users WHERE username=$1 OR email=$1 LIMIT 1`;
  const r = await pool.query(q, [identifier]);
  return r.rows[0];
}

// Routes

// Signup
app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'Missing fields' });

    if (password.length < 6) return res.status(400).json({ error: 'Password too short' });

    const hash = await bcrypt.hash(password, 10);
    const insert = 'INSERT INTO users(username,email,password_hash) VALUES($1,$2,$3) RETURNING id, username, email';
    const r = await pool.query(insert, [username, email, hash]);
    res.json({ user: r.rows[0] });
  } catch (err) {
    if (err && err.code === '23505') { // unique violation
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    console.error('signup err', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login -> validate password and send OTP
app.post('/api/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password) return res.status(400).json({ error: 'Missing fields' });

    const user = await findUserByIdentifier(identifier);
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });

    const otp = generateOtp();
    const expiresAt = new Date(Date.now() + OTP_TTL * 1000);

    await pool.query('INSERT INTO login_otps(user_id, otp, expires_at) VALUES($1,$2,$3)', [user.id, otp, expiresAt]);

    try {
      await sendOtpEmail(user.email, otp);
    } catch (mailErr) {
      console.error('email send error', mailErr);
      return res.status(500).json({ error: 'Failed to send OTP email. Check SMTP settings.' });
    }

    res.json({ ok: true, message: 'OTP sent to registered email' });
  } catch (err) {
    console.error('login err', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify OTP -> issue JWT cookie
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { identifier, otp } = req.body;
    if (!identifier || !otp) return res.status(400).json({ error: 'Missing fields' });

    const user = await findUserByIdentifier(identifier);
    if (!user) return res.status(400).json({ error: 'Invalid request' });

    const q = `SELECT id, otp, expires_at, used FROM login_otps WHERE user_id=$1 AND used=FALSE ORDER BY created_at DESC LIMIT 1`;
    const r = await pool.query(q, [user.id]);
    const rec = r.rows[0];
    if (!rec) return res.status(400).json({ error: 'No OTP found' });

    if (rec.used) return res.status(400).json({ error: 'OTP already used' });
    if (new Date(rec.expires_at) < new Date()) return res.status(400).json({ error: 'OTP expired' });
    if (rec.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

    await pool.query('UPDATE login_otps SET used=TRUE WHERE id=$1', [rec.id]);

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    // set cookie; in production set secure:true and proper sameSite
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
    res.json({ ok: true });
  } catch (err) {
    console.error('verify otp err', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Auth middleware
function authMiddleware(req, res, next) {
  const token = (req.cookies && req.cookies.token) || (req.headers['authorization'] && req.headers['authorization'].split(' ')[1]);
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// Protected endpoint
app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query('SELECT id, username, email FROM users WHERE id=$1', [req.userId]);
    res.json({ user: r.rows[0] });
  } catch (err) {
    console.error('me err', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
