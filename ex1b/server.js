const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const fileUpload = require('express-fileupload');
const session = require('express-session');

const app = express();
const PORT = 3000;

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload());
app.use(session({
  secret: 'your_secret_key_here',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 day
}));

// Setup DB
const db = new sqlite3.Database(path.join(__dirname, 'db/users.db'));
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    first_name TEXT,
    last_name TEXT,
    email TEXT,
    dob TEXT,
    profile_pic TEXT
  )
`);

// Routes

// Signup GET
app.get('/signup', (req, res) => {
  res.render('signup', { message: null });
});

// Signup POST
app.post('/signup', async (req, res) => {
  const { first_name, last_name, username, email, password, dob } = req.body;
  const profilePic = req.files?.profile_pic;

  if (!profilePic) {
    return res.render('signup', { message: 'Please upload a profile picture.' });
  }

  try {
    // Unique filename
    const extension = path.extname(profilePic.name);
    const sanitizedUsername = username.replace(/[^a-zA-Z0-9]/g, ''); //chatgpt helped here for renaming the filenames
    const uniqueFilename = `${sanitizedUsername}_${Date.now()}${extension}`;// here too

    const uploadPath = path.join(__dirname, 'uploads', uniqueFilename);
    await profilePic.mv(uploadPath);

    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (username, password, first_name, last_name, email, dob, profile_pic)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [username, hashedPassword, first_name, last_name, email, dob, uniqueFilename],
      function (err) {
        if (err) {
          console.error(err);
          return res.render('signup', { message: 'Username or email might already exist.' });
        }
        res.redirect('/login');
      }
    );
  } catch (error) {
    console.error(error);
    res.render('signup', { message: 'An error occurred. Please try again.' });
  }
});

// Login GET
app.get('/login', (req, res) => {
  res.render('login', { message: null });
});

// Login POST
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err) {
      console.error(err);
      return res.render('login', { message: 'Server error. Please try again later.' });
    }

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', { message: 'Invalid username or password.' });
    }

    // Save user session
    req.session.user = {
      id: user.id,
      username: user.username,
      first_name: user.first_name,
      profile_pic: user.profile_pic
    };

    res.redirect('/homepage');
  });
});

// Homepage (only for logged in users)
app.get('/homepage', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  db.get(`SELECT * FROM users WHERE id = ?`, [req.session.user.id], (err, user) => {
    if (err || !user) {
      return res.send('Error loading user data.');
    }

    res.render('homepage', { user });
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.send('Error logging out.');
    res.redirect('/login');
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
  //this is so unautherized users dont gain access to someone elses profile picture
app.get('/profile-pic/:filename', (req, res) => {
  if (!req.session.user) {
    return res.status(403).send('Unauthorized');
  }

  const filePath = path.join(__dirname, 'uploads', req.params.filename);

  res.sendFile(filePath, err => {
    if (err) {
      res.status(404).send('Image not found');
    }
  });
});
