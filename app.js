const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const port = 3000;

// MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
});

db.connect(err => {
  if (err) throw err;
  console.log('Connected to MySQL database');
});

db.query('CREATE DATABASE IF NOT EXISTS jwt_auth', err => {
  if (err) throw err;
  console.log('Database created');
})

db.query('USE jwt_auth', err => {
  if (err) throw err;
  console.log('Using jwt_auth database');
})

db.query('CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255), password VARCHAR(255))', err => {
  if (err) throw err;
  console.log('Users table created');
})


// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// Routes
app.get('/', (req, res) => {
  const token = req.cookies.jwt;

  if (!token) {
    return res.render('index');
  }

  jwt.verify(token, 'your_secret_key', (err, decoded) => {
    if (err) {
      return res.render('index');
    }

    res.redirect('/home');
  });
});

app.get('/home', (req, res) => {
  const token = req.cookies.jwt;

  if (!token) {
    return res.redirect('/login');
  }

  jwt.verify(token, 'your_secret_key', (err, decoded) => {
    if (err) {
      return res.redirect('/login');
    }

    const { id, username } = decoded;
    res.render('home', { user: { id, username } });
  });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Check if username already exists
  const checkQuery = 'SELECT * FROM users WHERE username = ?';
  db.query(checkQuery, [username], async (checkErr, checkResults) => {
    if (checkErr) {
      console.error(checkErr);
      return res.status(500).send('Error checking username');
    }

    if (checkResults.length > 0) {
      return res.status(400).send('Username already exists');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into the database
    const insertQuery = 'INSERT INTO users (username, password) VALUES (?, ?)';
    db.query(insertQuery, [username, hashedPassword], (insertErr, result) => {
      if (insertErr) {
        console.error(insertErr);
        return res.status(500).send('Error registering user');
      }
      res.status(201).send('User registered successfully');
    });
  });
});


app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Retrieve user from database
  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], async (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error logging in');
    }

    if (results.length === 0) {
      return res.status(401).send('Invalid username or password');
    }

    const user = results[0];

    // Compare passwords
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).send('Invalid username or password');
    }

    // Generate JWT
    const token = jwt.sign({ id: user.id, username: user.username }, 'your_secret_key', { expiresIn: '1h' });

    // Set JWT as cookie
    res.cookie('jwt', token, { httpOnly: true });

    res.redirect('/home');
  });
});


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});


