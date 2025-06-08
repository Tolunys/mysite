const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/dijital_cozumler', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB bağlantısı başarılı'))
.catch(err => console.error('MongoDB bağlantı hatası:', err));

// Admin Schema
const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const Admin = mongoose.model('Admin', adminSchema);

// Contact Schema
const contactSchema = new mongoose.Schema({
    name: String,
    email: String,
    phone: String,
    message: String,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const Contact = mongoose.model('Contact', contactSchema);

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Yetkilendirme başarısız' });

    jwt.verify(token, process.env.JWT_SECRET || 'gizli_anahtar', (err, user) => {
        if (err) return res.status(403).json({ message: 'Geçersiz token' });
        req.user = user;
        next();
    });
};

// Create initial admin user
app.post('/api/admin/setup', async (req, res) => {
    try {
        // Check if admin already exists
        const adminExists = await Admin.findOne({});
        if (adminExists) {
            return res.status(400).json({ message: 'Admin kullanıcısı zaten mevcut' });
        }

        const username = 'admin';
        const password = '1245';
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const admin = new Admin({
            username,
            password: hashedPassword
        });
        
        await admin.save();
        res.status(201).json({ 
            message: 'Admin kullanıcısı oluşturuldu',
            username: username,
            password: password
        });
    } catch (error) {
        res.status(500).json({ message: 'Admin kullanıcısı oluşturulurken bir hata oluştu', error: error.message });
    }
});

// Admin login endpoint
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const admin = await Admin.findOne({ username });

        if (!admin) {
            return res.status(401).json({ message: 'Kullanıcı adı veya şifre hatalı' });
        }

        const validPassword = await bcrypt.compare(password, admin.password);
        if (!validPassword) {
            return res.status(401).json({ message: 'Kullanıcı adı veya şifre hatalı' });
        }

        const token = jwt.sign({ username: admin.username }, process.env.JWT_SECRET || 'gizli_anahtar', { expiresIn: '24h' });
        res.json({ token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Giriş yapılırken bir hata oluştu', error: error.message });
    }
});

// Contact form endpoint
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, phone, message } = req.body;
        const contact = new Contact({
            name,
            email,
            phone,
            message
        });
        await contact.save();
        res.status(201).json({ message: 'Mesajınız başarıyla gönderildi!' });
    } catch (error) {
        res.status(500).json({ message: 'Bir hata oluştu', error: error.message });
    }
});

// Get all messages (protected)
app.get('/api/contact', authenticateToken, async (req, res) => {
    try {
        const messages = await Contact.find().sort({ createdAt: -1 });
        res.json(messages);
    } catch (error) {
        res.status(500).json({ message: 'Mesajlar alınırken bir hata oluştu', error: error.message });
    }
});

// Delete message (protected)
app.delete('/api/contact/:id', authenticateToken, async (req, res) => {
    try {
        await Contact.findByIdAndDelete(req.params.id);
        res.json({ message: 'Mesaj başarıyla silindi' });
    } catch (error) {
        res.status(500).json({ message: 'Mesaj silinirken bir hata oluştu', error: error.message });
    }
});

// Update message (protected)
app.put('/api/contact/:id', authenticateToken, async (req, res) => {
    try {
        const { name, email, phone, message } = req.body;
        const updatedMessage = await Contact.findByIdAndUpdate(
            req.params.id,
            { name, email, phone, message },
            { new: true }
        );
        res.json(updatedMessage);
    } catch (error) {
        res.status(500).json({ message: 'Mesaj güncellenirken bir hata oluştu', error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server ${PORT} portunda çalışıyor`);
}); 