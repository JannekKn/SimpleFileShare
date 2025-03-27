// app.js
const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const mysql = require('mysql2/promise');

const app = express();

// --- Database Connection ---
// Adjust your connection parameters as needed.
const dbConfig = {
  host: 'localhost',
  user: 'your_db_user',
  password: 'your_db_password',
  database: 'your_database'
};

let db;
mysql.createConnection(dbConfig).then(connection => {
  db = connection;
  console.log('Connected to MariaDB');
}).catch(err => {
  console.error('DB connection error:', err);
});

// --- Middleware Setup ---
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: false
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// --- Passport Local Strategy ---
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (!rows.length) return done(null, false, { message: 'Incorrect username.' });
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return done(null, false, { message: 'Incorrect password.' });
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE id = ?', [id]);
    if (!rows.length) return done(new Error('User not found'));
    done(null, rows[0]);
  } catch (err) {
    done(err);
  }
});

// --- Multer Setup for File Uploads ---
const uploadFolder = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadFolder)) {
  fs.mkdirSync(uploadFolder);
}
const uploadStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadFolder);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + uuidv4() + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});
const uploadMiddleware = multer({
  storage: uploadStorage,
  limits: { fileSize: 5 * 1024 * 1024 * 1024 } // 5GB limit
});

// --- Authentication Middleware ---
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

// --- Routes ---

// Home page (list user's uploads)
app.get('/', ensureAuthenticated, async (req, res) => {
  try {
    const [uploads] = await db.execute('SELECT * FROM uploads WHERE user_id = ?', [req.user.id]);
    res.render('index', { user: req.user, uploads, messages: req.flash() });
  } catch (err) {
    res.send('Error loading uploads.');
  }
});

// Register
app.get('/register', (req, res) => {
  res.render('register', { messages: req.flash() });
});
app.post('/register', [
  body('username').trim().notEmpty().withMessage('Username is required.'),
  body('password').notEmpty().withMessage('Password is required.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    req.flash('error', errors.array().map(e => e.msg));
    return res.redirect('/register');
  }
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
    req.flash('success', 'Registration successful. Please log in.');
    res.redirect('/login');
  } catch (err) {
    req.flash('error', 'User registration failed. Username may already exist.');
    res.redirect('/register');
  }
});

// Login
app.get('/login', (req, res) => {
  res.render('login', { messages: req.flash() });
});
app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}));

// Logout
app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/login');
  });
});

// File Upload
app.get('/upload', ensureAuthenticated, (req, res) => {
  res.render('upload', { messages: req.flash() });
});
app.post('/upload', ensureAuthenticated, uploadMiddleware.single('file'), async (req, res) => {
  // Get delete time from form (in hours or a flag for disabled)
  // For simplicity, assume form sends deleteTime (number of days) or 'disabled'
  let deleteAt = null;
  if (req.body.deleteTime && req.body.deleteTime !== 'disabled') {
    const days = parseInt(req.body.deleteTime);
    if (!isNaN(days) && days > 0) {
      deleteAt = new Date();
      deleteAt.setDate(deleteAt.getDate() + days);
    }
  } else if (!req.body.deleteTime) {
    // default to 7 days
    deleteAt = new Date();
    deleteAt.setDate(deleteAt.getDate() + 7);
  }
  const downloadToken = uuidv4();
  try {
    await db.execute(
      'INSERT INTO uploads (user_id, filename, filepath, filesize, delete_at, download_link) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, req.file.originalname, req.file.filename, req.file.size, deleteAt, downloadToken]
    );
    req.flash('success', 'File uploaded successfully.');
    res.redirect('/');
  } catch (err) {
    req.flash('error', 'Error saving file info.');
    res.redirect('/upload');
  }
});

// Download page
app.get('/download/:token', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM uploads WHERE download_link = ?', [req.params.token]);
    if (!rows.length) return res.send('Invalid download link.');
    const file = rows[0];
    res.render('download', { file });
  } catch (err) {
    res.send('Error retrieving file.');
  }
});

// File Download Action
app.post('/download/:token', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM uploads WHERE download_link = ?', [req.params.token]);
    if (!rows.length) return res.send('Invalid download link.');
    const file = rows[0];
    const filePath = path.join(uploadFolder, file.filepath);
    res.download(filePath, file.filename);
  } catch (err) {
    res.send('Error downloading file.');
  }
});

// Delete an upload (only owner can delete)
app.post('/delete/:id', ensureAuthenticated, async (req, res) => {
  try {
    // Verify file belongs to user
    const [rows] = await db.execute('SELECT * FROM uploads WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!rows.length) {
      req.flash('error', 'File not found or unauthorized.');
      return res.redirect('/');
    }
    const file = rows[0];
    // Delete file from filesystem
    const filePath = path.join(uploadFolder, file.filepath);
    fs.unlink(filePath, (err) => {
      if (err) console.error('Error deleting file:', err);
    });
    // Remove DB entry
    await db.execute('DELETE FROM uploads WHERE id = ?', [req.params.id]);
    req.flash('success', 'File deleted.');
    res.redirect('/');
  } catch (err) {
    req.flash('error', 'Error deleting file.');
    res.redirect('/');
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
