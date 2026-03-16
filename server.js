const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const rateLimit = require('rate-limit');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));
app.use('/data', express.static('data'));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 5,
    standardHeaders: true, legacyHeaders: false
});

const registerLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 3,
    standardHeaders: true, legacyHeaders: false
});

const DATA_DIR = path.join(process.cwd(), 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

async function ensureDataDir() {
    try {
        await fs.mkdir(DATA_DIR, { recursive: true });
        try {
            await fs.access(USERS_FILE);
        } catch {
            await fs.writeFile(USERS_FILE, JSON.stringify([]));
        }
    } catch {}
}

async function loadUsers() {
    try {
        return JSON.parse(await fs.readFile(USERS_FILE, 'utf8'));
    } catch {
        return [];
    }
}

async function saveUsers(users) {
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

function generateUserId() {
    return `USER-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substr(2, 6).toUpperCase()}`;
}

const JWT_SECRET = process.env.JWT_SECRET || 'ryu-na-x-2026-secret-key';

app.post('/api/register', registerLimiter, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password || password.length < 6) {
            return res.status(400).json({ error: 'Password must be 6+ chars' });
        }
        await ensureDataDir();
        const users = await loadUsers();
        const userId = generateUserId();
        const hashedPassword = await bcrypt.hash(password, 12);
        users.push({ userId, password: hashedPassword });
        await saveUsers(users);
        res.json({ message: '✅ Account created!', userId, note: 'SAVE THIS USER ID!' });
    } catch {
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const { userId, password } = req.body;
        if (!userId || !password) {
            return res.status(400).json({ error: 'User ID & password required' });
        }
        await ensureDataDir();
        const users = await loadUsers();
        const user = users.find(u => u.userId === userId);
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: '❌ Invalid credentials' });
        }
        const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, userId });
    } catch {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/verify', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        jwt.verify(token, JWT_SECRET);
        res.json({ valid: true });
    } catch {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.post('/api/chat', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        jwt.verify(token, JWT_SECRET);
        const { message } = req.body;
        if (!message) return res.status(400).json({ error: 'Message required' });
        
        const aiResponse = await fetch('https://api.siputzx.my.id/api/ai/gemini-lite', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        });
        const data = await aiResponse.json();
        res.json({ reply: data.reply || data.response || 'AI is thinking...' });
    } catch {
        res.status(500).json({ error: 'Chat service unavailable' });
    }
});

// Catch-all for SPA
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

ensureDataDir().then(() => {
    app.listen(PORT, () => {
        console.log(`🎮 ryu-na x AI live on port ${PORT}`);
    });
});
