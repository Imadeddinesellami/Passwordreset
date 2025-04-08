require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'vulnerable-app-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } 
}));


const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100 
});
app.use('/login', limiter);
app.use('/forgot-password', limiter);


const users = [
  { id: 1, username: 'admin', password: crypto.createHash('md5').update('admin123').digest('hex'), email: 'admin@gmail.com' },
  { id: 2, username: 'samir', password: crypto.createHash('md5').update('douadi').digest('hex'), email: 'samir@gmail.com' },
  { id: 3, username: 'test', password: crypto.createHash('md5').update('test').digest('hex'), email: 'test@gmail.com' }
];

const resetTokens = {};


app.get('/', (req, res) => {
  if (req.session.user) {
    return res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
  console.log('Login attempt:', { username, password, hashedPassword });

  const user = users.find(u => u.username === username && u.password === hashedPassword);
  if (user) {
    req.session.user = { id: user.id, username: user.username };
    return res.redirect('/dashboard');
  }
  res.status(401).send('Invalid username or password');
});


app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});


app.get('/api/user-info', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  res.json({
    id: req.session.user.id,
    username: req.session.user.username
  });
});


app.get('/forgot-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

app.post('/forgot-password', async (req, res) => {
  const { username } = req.body;
  console.log('Password reset requested for:', username);

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(404).send('User not found');
  }

  const resetToken = crypto.randomBytes(16).toString('hex'); 
  resetTokens[resetToken] = username; // ربط الرمز بالمستخدم
  console.log('Generated reset token:', resetToken);
  console.log('Current resetTokens:', resetTokens);

 
  const resetLink = `http://localhost:${PORT}/reset-password?temp-forgot-password-token=${resetToken}`;
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: 'Password Reset',
    text: `To reset your password, use this link: ${resetLink}`
  };

  try {
    await transporter.sendMail(mailOptions);
    res.send('Reset token sent to your email');
  } catch (error) {
    console.error('Email error:', error);
    res.send(`Error sending email: ${error.message}`);
  }
});


app.get('/reset-password', (req, res) => {
  const { 'temp-forgot-password-token': token } = req.query; 
  res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

app.post('/reset-password', (req, res) => {
  const { token, username, new_password } = req.body;
  console.log('Password reset attempt:', { token, username, new_password });

 
  if (!resetTokens[token]) {
    return res.status(400).send('Invalid or expired token');
  }

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(404).send('User not found');
  }

  const oldPassword = user.password;
  user.password = crypto.createHash('md5').update(new_password).digest('hex');
  console.log(`Password changed for ${username}:`, { oldPassword, newPassword: user.password });

  // delete resetTokens[token];
  res.send(`
    <h3>Password Reset Successful</h3>
    <p>The password for user <strong>${username}</strong> has been reset.</p>
    <p><a href="/login">Login with your new password</a></p>
  `);
});


app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});


app.get('/api/users', (req, res) => {
  const safeUsers = users.map(user => ({
    id: user.id,
    username: user.username,
    email: user.email
  }));
  res.json(safeUsers);
});


app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Available users:');
  users.forEach(user => {
    console.log(`- ${user.username} (password: ${user.password} - MD5)`);
  });
});
