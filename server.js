const express = require('express');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs').promises;

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'ryu-na-x-super-secret-key-change-in-prod';
const GEMINI_API_URL = 'https://api.siputzx.my.id/api/ai/gemini-lite';

// Middleware
app.use(helmet());
app.use(cors({
  origin: ['https://hideout-web-hosting.xo.je', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: { error: 'Too many login attempts, try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: { error: 'Too many registration attempts, try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Data file
const USERS_FILE = path.join(__dirname, 'data', 'users.json');

// Ensure data directory exists
async function ensureDataDir() {
  try {
    await fs.mkdir(path.join(__dirname, 'data'), { recursive: true });
  } catch (err) {
    console.log('Data dir already exists');
  }
}

// Load users
async function loadUsers() {
  try {
    const data = await fs.readFile(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch {
    return [];
  }
}

// Save users
async function saveUsers(users) {
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

// Generate User ID
function generateUserId() {
  return 'USER-' + Math.random().toString(36).substr(2, 6).toUpperCase();
}

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Register
app.post('/api/register', registerLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    
    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const users = await loadUsers();
    const userId = generateUserId();
    const hashedPassword = await bcrypt.hash(password, 12);

    const newUser = {
      userId,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await saveUsers(users);

    const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ 
      message: 'Registration successful',
      userId,
      token 
    });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ error: 'Password required' });
    }

    const users = await loadUsers();
    const user = users.find(u => true); // Allow any registered user to login
    
    if (!user) {
      return res.status(401).json({ error: 'No users registered. Please register first.' });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ userId: user.userId }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ 
      message: 'Login successful',
      userId: user.userId,
      token 
    });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Chat with Gemini (proxy)
app.post('/api/chat', authenticateToken, async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message || message.trim().length === 0) {
      return res.status(400).json({ error: 'Message required' });
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    const response = await fetch(GEMINI_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
      },
      body: JSON.stringify({ message }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();
    res.json({ 
      reply: data.reply || data.response || 'Response received from AI',
      timestamp: new Date().toISOString()
    });

  } catch (err) {
    console.error('Gemini API error:', err.message);
    res.status(503).json({ 
      error: 'AI service temporarily unavailable',
      fallback: 'The neural network is experiencing cosmic interference. Please try again.'
    });
  }
});

// Get user info
app.get('/api/user', authenticateToken, (req, res) => {
  res.json({ userId: req.user.userId });
});

// 404 handler
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Initialize and start
async function startServer() {
  await ensureDataDir();
  app.listen(PORT, () => {
    console.log(`ryu-na x made by Elvis running on port ${PORT}`);
    console.log(`API: http://localhost:${PORT}/api/health`);
  });
}

startServer();
