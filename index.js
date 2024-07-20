const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Generate JWT Token:
// Create a function to generate a token upon successful login.
module.exports = authenticateToken;

const generateToken = (user) => {
return jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, {
    expiresIn: '1h',
});
};

module.exports = generateToken;

// Secure Route Implementation:
// Use the authentication middleware to protect specific routes.
const express = require('express');
const authenticateToken = require('./middleware/authenticateToken');

const router = express.Router();

router.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is a protected route!', user: req.user });
});

module.exports = router;
// Login Route to Issue Tokens:
// Implement a route where users can log in and receive a JWT.

const express = require('express');
const bcrypt = require('bcryptjs');
const generateToken = require('./utils/generateToken');


// Sample user data
const users = [
  {
    id: 1,
    username: 'user1',
    password: bcrypt.hashSync('password1', 8),
  },
];

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  if (user && bcrypt.compareSync(password, user.password)) {
    const token = generateToken(user);
    res.json({ token });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

module.exports = router;

// Integrate Routes into Express App:
const express = require('express');
const dotenv = require('dotenv');
const loginRouter = require('./routes/login');
const protectedRouter = require('./routes/protected');

dotenv.config();
const app = express();

app.use(express.json());

app.use('/api', loginRouter);
app.use('/api', protectedRouter);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});