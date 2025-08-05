const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');

dotenv.config();
const prisma = new PrismaClient();
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// ===== ROUTE ROOT =====
app.get('/', (req, res) => {
    res.send('API is running...');
});

// Middleware autentikasi
function auth(role) {
    return (req, res, next) => {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: "Unauthorized" });
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            if (role && decoded.role !== role) return res.status(403).json({ error: "Forbidden" });
            req.user = decoded;
            next();
        } catch {
            res.status(401).json({ error: "Invalid token" });
        }
    };
}

// Registrasi
app.post('/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    try {
        const user = await prisma.user.create({
            data: { name, email, password: hashed, role }
        });
        res.json(user);
    } catch {
        res.status(400).json({ error: "Email already exists" });
    }
});

// Login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
});

// List konsultan
app.get('/consultants', async (req, res) => {
    const consultants = await prisma.consultant.findMany({
        include: { user: { select: { name: true, email: true } } }
    });
    res.json(consultants);
});

// Booking + komisi otomatis
app.post('/book', auth('client'), async (req, res) => {
    const { consultantId, totalFee } = req.body;
    const adminFee = totalFee * 0.10;
    const consultantEarning = totalFee - adminFee;

    const session = await prisma.session.create({
        data: {
            clientId: req.user.id,
            consultantId,
            totalFee,
            adminFee,
            consultantEarning,
            status: 'completed'
        }
    });

    await prisma.user.update({
        where: { id: consultantId },
        data: { balance: { increment: consultantEarning } }
    });

    res.json(session);
});

// Lihat saldo konsultan
app.get('/balance', auth('consultant'), async (req, res) => {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    res.json({ balance: user.balance });
});

// ===== LISTEN PORT =====
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
