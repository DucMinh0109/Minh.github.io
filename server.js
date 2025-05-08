const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const cors = require('cors');
const app = express();

// Đặt múi giờ cho Node.js
process.env.TZ = 'Asia/Ho_Chi_Minh';

app.use(cors());
app.use(express.json());

// Kết nối MySQL
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '123ABCabc', // Thay bằng mật khẩu MySQL của bạn
    database: 'restaurant_db',
    timezone: '+07:00' // Đặt múi giờ cho kết nối MySQL
});

// Đăng ký người dùng
app.post('/api/register', async (req, res) => {
    const { name, phone, email, password, birthday } = req.body;
    try {
        const [existing] = await pool.query(
            'SELECT id FROM users WHERE phone = ? OR (email IS NOT NULL AND email = ?)',
            [phone, email || '']
        );
        if (existing.length > 0) {
            return res.status(400).json({ message: 'Số điện thoại hoặc email đã được sử dụng' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (name, phone, email, password, birthday) VALUES (?, ?, ?, ?, ?)',
            [name, phone, email, hashedPassword, birthday || null]
        );
        res.status(201).json({ message: 'Đăng ký thành công' });
    } catch (error) {
        console.error('Lỗi khi đăng ký:', error);
        res.status(500).json({ message: 'Lỗi server' });
    }
});

// Đăng nhập
app.post('/api/login', async (req, res) => {
    const { phone, password } = req.body;
    try {
        const [users] = await pool.query(
            'SELECT id, name, phone, email, password, DATE_FORMAT(birthday, "%Y-%m-%d") AS birthday FROM users WHERE phone = ?',
            [phone]
        );
        if (users.length === 0) {
            return res.status(400).json({ message: 'Số điện thoại không tồn tại' });
        }
        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Mật khẩu không đúng' });
        }
        res.json({
            message: 'Đăng nhập thành công',
            user: { id: user.id, name: user.name, phone: user.phone, email: user.email, birthday: user.birthday }
        });
    } catch (error) {
        console.error('Lỗi khi đăng nhập:', error);
        res.status(500).json({ message: 'Lỗi server' });
    }
});

// Cập nhật thông tin người dùng
app.put('/api/users/:id', async (req, res) => {
    const { id } = req.params;
    const { name, phone, email, birthday } = req.body;
    try {
        await pool.query(
            'UPDATE users SET name = ?, phone = ?, email = ?, birthday = ? WHERE id = ?',
            [name, phone, email || null, birthday || null, id]
        );
        res.json({ message: 'Cập nhật thông tin thành công' });
    } catch (error) {
        console.error('Lỗi khi cập nhật thông tin:', error);
        res.status(500).json({ message: 'Lỗi server' });
    }
});

// Lấy thông tin người dùng
app.get('/api/users/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [users] = await pool.query(
            'SELECT id, name, phone, email, DATE_FORMAT(birthday, "%Y-%m-%d") AS birthday FROM users WHERE id = ?',
            [id]
        );
        if (users.length === 0) {
            return res.status(404).json({ message: 'Không tìm thấy người dùng' });
        }
        res.json(users[0]);
    } catch (error) {
        console.error('Lỗi khi lấy thông tin người dùng:', error);
        res.status(500).json({ message: 'Lỗi server' });
    }
});

// Đổi mật khẩu
app.post('/api/users/:id/change-password', async (req, res) => {
    const { id } = req.params;
    const { currentPassword, newPassword } = req.body;
    try {
        const [users] = await pool.query('SELECT password FROM users WHERE id = ?', [id]);
        if (users.length === 0) {
            return res.status(404).json({ message: 'Không tìm thấy người dùng' });
        }
        const isMatch = await bcrypt.compare(currentPassword, users[0].password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Mật khẩu hiện tại không đúng' });
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, id]);
        res.json({ message: 'Đổi mật khẩu thành công' });
    } catch (error) {
        console.error('Lỗi khi đổi mật khẩu:', error);
        res.status(500).json({ message: 'Lỗi server' });
    }
});

app.listen(3000, () => console.log('Server chạy trên cổng 3000'));