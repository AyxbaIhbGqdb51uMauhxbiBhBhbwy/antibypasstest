const express = require('express');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(express.json());

// ✅ Rate limiting (lebih ketat)
const limiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 menit
    max: 100, // Maksimal 100 request per 5 menit
    message: { error: 'Rate limit exceeded. Please try again later.' }
});
app.use(limiter);

// ✅ IP Blocking System
const blockedIPs = new Set();

app.use((req, res, next) => {
    const clientIP = req.ip;

    if (blockedIPs.has(clientIP)) {
        return res.status(403).json({ error: 'Access Denied' });
    }
    next();
});

// ✅ Function untuk generate key dari API eksternal
async function generateKey() {
    try {
        const response = await axios.get('https://starxkey-backend.vercel.app/generate?expired=1d');
        if (!response.data.key) throw new Error('Key not found');
        return response.data.key;
    } catch (error) {
        console.error('Error fetching key:', error.message);
        throw error;
    }
}

// ✅ Function untuk generate token (JWT)
function generateToken() {
    if (!process.env.SECRET_KEY) throw new Error('SECRET_KEY not set');
    return jwt.sign({}, process.env.SECRET_KEY, { expiresIn: '30s' });
}

// ✅ Middleware: Validasi referer & user-agent
function validateRequest(req, res, next) {
    const allowedReferrers = ['linkvertise.com', 'work.ink', 'loot-link.com', 'direct-link.net'];
    const referer = req.get('referer') || '';
    const userAgent = req.get('User-Agent') || '';

    // ❌ Blokir jika referer tidak valid
    if (!allowedReferrers.some(valid => referer.includes(valid))) {
        return res.status(403).sendFile(path.join(__dirname, 'public', 'accessdenied.html'));
    }

    // ❌ Blokir jika User-Agent kosong (bot)
    if (!userAgent || userAgent.length < 10) {
        blockedIPs.add(req.ip);
        return res.status(403).json({ error: 'Suspicious activity detected' });
    }

    next();
}

// ✅ Route: Check Key
app.post('/check-key', async (req, res) => {
    try {
        const { key } = req.body;
        if (!key) return res.status(400).json({ error: 'Key is required' });

        const validKey = await generateKey();
        if (key === validKey) {
            return res.json({ valid: true, token: generateToken() });
        }
        res.json({ valid: false });
    } catch (error) {
        console.error('Error in /check-key:', error.message);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// ✅ Route: Validate Token
app.post('/validate-token', (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token is required' });

    jwt.verify(token, process.env.SECRET_KEY, (err) => {
        if (err) return res.json({ valid: false });
        res.json({ valid: true });
    });
});

// ✅ Route: Get Key (Anti Bypass)
app.get('/get-key', validateRequest, async (req, res) => {
    try {
        const key = await generateKey();
        const timestamp = new Date().toISOString();
        res.setHeader('Content-Type', 'text/html');
        res.send(generateHtmlResponse(key, timestamp));
    } catch (error) {
        res.status(500).json({ error: 'Error generating key' });
    }
});

// ✅ Helper function untuk generate HTML response
function generateHtmlResponse(key, timestamp) {
    const htmlPath = path.join(__dirname, 'public', 'keysite.html');
    let html = fs.readFileSync(htmlPath, 'utf8');
    return html.replace('${key}', key).replace('${timestamp}', timestamp);
}

// ✅ Global Error Handler
app.use((err, req, res, next) => {
    console.error('Global Error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
});

// ✅ Handle 404
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

// ✅ Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
