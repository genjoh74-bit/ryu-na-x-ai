const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

// Rate limiting for login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per IP
    message: 'Too many login attempts, try again later',
    standardHeaders: true,
    legacyHeaders: false,
});

// Users data file
const USERS_FILE = path.join(__dirname, 'data', 'users.json');

// Initialize users file
async function initUsersFile() {
    try {
        await fs.access(USERS_FILE);
    } catch {
        await fs.mkdir(path.dirname(USERS_FILE), { recursive: true });
        await fs.writeFile(USERS_FILE, JSON.stringify([]));
    }
}

// Generate unique User ID
function generateUserID() {
    const prefix = Math.random() > 0.5 ? 'USER-' : 'ID-';
    const numbers = Math.floor(100000 + Math.random() * 900000);
    return `${prefix}${numbers}`;
}

// Read users
async function readUsers() {
    const data = await fs.readFile(USERS_FILE, 'utf8');
    return JSON.parse(data);
}

// Write users
async function writeUsers(users) {
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

// Routes

// Registration
app.post('/api/register', async (req, res) => {
    try {
        const { password } = req.body;
        
        // Validation
        if (!password || password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        const users = await readUsers();
        let userID;
        
        // Generate unique User ID
        do {
            userID = generateUserID();
        } while (users.find(u => u.userID === userID));

        // Hash password
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Save user
        const newUser = {
            userID,
            password: hashedPassword,
            createdAt: new Date().toISOString()
        };

        users.push(newUser);
        await writeUsers(users);

        res.json({ 
            success: true, 
            userID,
            message: 'Account created successfully! Save your User ID securely.' 
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login
app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const { userID, password } = req.body;

        if (!userID || !password) {
            return res.status(400).json({ error: 'User ID and password required' });
        }

        const users = await readUsers();
        const user = users.find(u => u.userID === userID);

        if (!user) {
            return res.status(401).json({ error: 'Invalid User ID or password' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (isValidPassword) {
            // Generate simple JWT-like token (for demo)
            const token = Buffer.from(`${userID}:${Date.now()}`).toString('base64');
            res.json({ 
                success: true, 
                token,
                userID,
                message: 'Login successful!' 
            });
        } else {
            res.status(401).json({ error: 'Invalid User ID or password' });
        }

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Verify token (for dashboard)
app.post('/api/verify', async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) {
            return res.status(401).json({ valid: false });
        }
        
        // Simple token validation
        const decoded = Buffer.from(token, 'base64').toString();
        const [userID, timestamp] = decoded.split(':');
        
        if (!userID || Date.now() - parseInt(timestamp) > 24 * 60 * 60 * 1000) { // 24h expiry
            return res.status(401).json({ valid: false });
        }

        const users = await readUsers();
        const userExists = users.find(u => u.userID === userID);
        
        res.json({ valid: !!userExists, userID });
    } catch {
        res.status(401).json({ valid: false });
    }
});

// AI Chat endpoint
app.post('/api/chat', async (req, res) => {
    try {
        const { prompt, model = 'gemini-2.0-flash-lite' } = req.body;
        
        const url = `https://api.siputzx.my.id/api/ai/gemini-lite?prompt=${encodeURIComponent(prompt)}&model=${model}`;
        
        const response = await fetch(url);
        const data = await response.json();
        
        if (data.status && data.data?.parts?.[0]?.text) {
            res.json({ reply: data.data.parts[0].text });
        } else {
            res.json({ reply: "Sorry, I couldn't process that request." });
        }
    } catch (error) {
        console.error('Chat error:', error);
        res.json({ reply: "Sorry, an error occurred. Please try again." });
    }
});

async function startServer() {
    await initUsersFile();
    app.listen(PORT, () => {
        console.log(`🚀 Ryu-na X server running on http://localhost:${PORT}`);
    });
}

startServer();