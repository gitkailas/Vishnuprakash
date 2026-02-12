const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

// Simple in-memory session store (can be replaced with database later)
const sessions = {};

// SQLite Database Setup
const dbPath = path.join(__dirname, 'employees.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite database');
        initializeDatabase();
    }
});

// Initialize Database
function initializeDatabase() {
    // Create employees table
    db.run(`
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT,
            department TEXT NOT NULL,
            position TEXT NOT NULL,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) {
            console.error('Error creating employees table:', err.message);
        } else {
            console.log('Employees table ready');
        }
    });

    // Create users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            employeeId INTEGER,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(employeeId) REFERENCES employees(id)
        )
    `, (err) => {
        if (err) {
            console.error('Error creating users table:', err.message);
        } else {
            console.log('Users table ready');
            // Create default admin user
            createDefaultUser();
        }
    });

    // Create attendance table
    db.run(`
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employeeId INTEGER NOT NULL,
            date TEXT NOT NULL,
            checkInTime TEXT,
            checkOutTime TEXT,
            checkInLatitude REAL,
            checkInLongitude REAL,
            checkOutLatitude REAL,
            checkOutLongitude REAL,
            loginPhoto TEXT,
            checkOutPhoto TEXT,
            photoValidated INTEGER DEFAULT 0,
            photoValidatedBy TEXT,
            status TEXT DEFAULT 'present',
            notes TEXT,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(employeeId) REFERENCES employees(id),
            UNIQUE(employeeId, date)
        )
    `, (err) => {
        if (err) {
            console.error('Error creating attendance table:', err.message);
        } else {
            console.log('Attendance table ready');
            // Add checkOutPhoto column if it doesn't exist (migration)
            db.run(`ALTER TABLE attendance ADD COLUMN checkOutPhoto TEXT`, (alterErr) => {
                if (alterErr && !alterErr.message.includes('duplicate column')) {
                    console.error('Error adding checkOutPhoto column:', alterErr.message);
                } else if (!alterErr) {
                    console.log('checkOutPhoto column added to attendance table');
                }
            });
        }
    });

    // Create login logs table
    db.run(`
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userId INTEGER NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            latitude REAL,
            longitude REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(userId) REFERENCES users(id)
        )
    `, (err) => {
        if (err) {
            console.error('Error creating login_logs table:', err.message);
        } else {
            console.log('Login logs table ready');
        }
    });

    // Create employee session logs table
    db.run(`
        CREATE TABLE IF NOT EXISTS employee_session_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userId INTEGER NOT NULL,
            employeeId INTEGER NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            latitude REAL,
            longitude REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(userId) REFERENCES users(id),
            FOREIGN KEY(employeeId) REFERENCES employees(id)
        )
    `, (err) => {
        if (err) {
            console.error('Error creating employee_session_logs table:', err.message);
        } else {
            console.log('Employee session logs table ready');
        }
    });
}

// Create default admin user
function createDefaultUser() {
    db.get('SELECT * FROM users WHERE username = ?', ['admin'], (err, row) => {
        if (err) {
            console.error('Error checking for admin user:', err.message);
            return;
        }
        
        if (!row) {
            db.run(
                'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                ['admin', hashPassword('admin'), 'admin'],
                (err) => {
                    if (err) {
                        console.error('Error creating default admin:', err.message);
                    } else {
                        console.log('✓ Default admin user created (username: admin, password: admin)');
                    }
                }
            );
        } else {
            console.log('✓ Admin user already exists');
        }
    });
}

// Password hashing (simple SHA256, can be replaced with bcrypt for production)
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

// Verify password
function verifyPassword(password, hash) {
    return hashPassword(password) === hash;
}

// Authentication middleware
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    if (!sessions[token]) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }

    req.user = sessions[token];
    next();
}

// API Routes

// LOGIN endpoint
app.post('/api/login', (req, res) => {
    const { username, password, role, latitude, longitude } = req.body;

    if (!username || !password || !role) {
        res.status(400).json({ error: 'Username, password, and role are required' });
        return;
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }

        if (!user) {
            res.status(401).json({ error: 'Invalid username or password' });
            return;
        }

        if (!verifyPassword(password, user.password)) {
            res.status(401).json({ error: 'Invalid username or password' });
            return;
        }

        if (user.role !== role) {
            res.status(403).json({ error: `This account is not an ${role}` });
            return;
        }

        // Generate token
        const token = crypto.randomBytes(32).toString('hex');
        sessions[token] = {
            id: user.id,
            userId: user.id,
            username: user.username,
            role: user.role,
            employeeId: user.employeeId,
            userName: user.username
        };

        // Log login with location (for admins)
        if (user.role === 'admin') {
            db.run(
                'INSERT INTO login_logs (userId, username, action, latitude, longitude) VALUES (?, ?, ?, ?, ?)',
                [user.id, user.username, 'login', latitude || null, longitude || null],
                (err) => {
                    if (err) {
                        console.error('Error logging admin login:', err.message);
                    }
                }
            );
        }

        // Log login with location (for employees)
        if (user.role === 'employee' && user.employeeId) {
            db.run(
                'INSERT INTO employee_session_logs (userId, employeeId, username, action, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?)',
                [user.id, user.employeeId, user.username, 'login', latitude || null, longitude || null],
                (err) => {
                    if (err) {
                        console.error('Error logging employee login:', err.message);
                    }
                }
            );
        }

        res.json({
            token,
            userId: user.id,
            role: user.role,
            userName: user.username,
            employeeId: user.employeeId
        });
    });
});

// LOGOUT endpoint
app.post('/api/logout', authenticateToken, (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];
    const { latitude, longitude } = req.body;
    const userId = req.user.id;
    const username = req.user.username;

    // Log logout with location (for admins)
    if (req.user.role === 'admin') {
        db.run(
            'INSERT INTO login_logs (userId, username, action, latitude, longitude) VALUES (?, ?, ?, ?, ?)',
            [userId, username, 'logout', latitude || null, longitude || null],
            (err) => {
                if (err) {
                    console.error('Error logging admin logout:', err.message);
                }
            }
        );
    }

    // Log logout with location (for employees)
    if (req.user.role === 'employee' && req.user.employeeId) {
        db.run(
            'INSERT INTO employee_session_logs (userId, employeeId, username, action, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?)',
            [userId, req.user.employeeId, username, 'logout', latitude || null, longitude || null],
            (err) => {
                if (err) {
                    console.error('Error logging employee logout:', err.message);
                }
            }
        );
    }

    if (token) {
        delete sessions[token];
    }
    res.json({ message: 'Logged out successfully' });
});

// GET user info
app.get('/api/user/info', authenticateToken, (req, res) => {
    res.json(req.user);
});

// CREATE user account (Admin only - for creating employee accounts)
app.post('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only admins can create users' });
    }

    const { username, password, role, employeeId } = req.body;

    if (!username || !password || !role) {
        res.status(400).json({ error: 'Username, password, and role are required' });
        return;
    }

    db.run(
        'INSERT INTO users (username, password, role, employeeId) VALUES (?, ?, ?, ?)',
        [username, hashPassword(password), role, employeeId || null],
        function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    res.status(409).json({ error: 'Username already exists' });
                } else {
                    res.status(500).json({ error: err.message });
                }
                return;
            }
            res.status(201).json({ 
                id: this.lastID,
                username,
                role,
                employeeId
            });
        }
    );
});

// CHANGE password
app.post('/api/users/change-password', authenticateToken, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    if (!currentPassword || !newPassword) {
        res.status(400).json({ error: 'Current password and new password are required' });
        return;
    }

    db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }

        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }

        if (!verifyPassword(currentPassword, user.password)) {
            res.status(401).json({ error: 'Current password is incorrect' });
            return;
        }

        db.run(
            'UPDATE users SET password = ? WHERE id = ?',
            [hashPassword(newPassword), userId],
            function(err) {
                if (err) {
                    res.status(500).json({ error: err.message });
                    return;
                }
                res.json({ message: 'Password changed successfully' });
            }
        );
    });
});

// RESET user password (Admin only)
app.post('/api/users/:userId/reset-password', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only admins can reset passwords' });
    }

    const { userId } = req.params;
    const { newPassword } = req.body;

    if (!newPassword) {
        res.status(400).json({ error: 'New password is required' });
        return;
    }

    db.run(
        'UPDATE users SET password = ? WHERE id = ?',
        [hashPassword(newPassword), userId],
        function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            if (this.changes === 0) {
                res.status(404).json({ error: 'User not found' });
                return;
            }
            res.json({ message: 'Password reset successfully' });
        }
    );
});

// GET all users (Admin only)
app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only admins can view all users' });
    }

    db.all('SELECT id, username, role, employeeId FROM users ORDER BY id DESC', [], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// GET login logs (Admin only)
app.get('/api/login-logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only admins can view login logs' });
    }

    const { limit, startDate, endDate } = req.query;
    let query = 'SELECT * FROM login_logs WHERE 1=1';
    const params = [];

    // Date filtering
    if (startDate) {
        query += ' AND DATE(timestamp) >= ?';
        params.push(startDate);
    }
    if (endDate) {
        query += ' AND DATE(timestamp) <= ?';
        params.push(endDate);
    }

    query += ' ORDER BY timestamp DESC';

    if (limit) {
        query += ' LIMIT ?';
        params.push(parseInt(limit));
    }

    db.all(query, params, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// GET login logs for specific user (Admin only)
app.get('/api/login-logs/user/:userId', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only admins can view login logs' });
    }

    const { userId } = req.params;
    const { limit } = req.query;

    let query = 'SELECT * FROM login_logs WHERE userId = ? ORDER BY timestamp DESC';
    const params = [userId];

    if (limit) {
        query += ' LIMIT ?';
        params.push(parseInt(limit));
    }

    db.all(query, params, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// GET employee session logs (admin only)
app.get('/api/employee-session-logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only admins can view employee session logs' });
    }

    const { employeeId, startDate, endDate, limit } = req.query;
    let query = 'SELECT * FROM employee_session_logs WHERE 1=1';
    const params = [];

    if (employeeId) {
        query += ' AND employeeId = ?';
        params.push(employeeId);
    }

    if (startDate) {
        query += ' AND DATE(timestamp) >= ?';
        params.push(startDate);
    }

    if (endDate) {
        query += ' AND DATE(timestamp) <= ?';
        params.push(endDate);
    }

    query += ' ORDER BY timestamp DESC';

    if (limit) {
        query += ' LIMIT ?';
        params.push(parseInt(limit));
    }

    db.all(query, params, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

app.get('/api/employees', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only admins can view all employees' });
    }

    db.all('SELECT * FROM employees ORDER BY id DESC', [], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// GET single employee
app.get('/api/employees/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    
    if (req.user.role !== 'admin' && req.user.employeeId !== parseInt(id)) {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    db.get('SELECT * FROM employees WHERE id = ?', [id], (err, row) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        if (!row) {
            res.status(404).json({ error: 'Employee not found' });
            return;
        }
        res.json(row);
    });
});

// POST create new employee
app.post('/api/employees', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only admins can create employees' });
    }

    const { name, email, phone, department, position } = req.body;

    if (!name || !email || !department || !position) {
        res.status(400).json({ error: 'Missing required fields' });
        return;
    }

    db.run(
        'INSERT INTO employees (name, email, phone, department, position) VALUES (?, ?, ?, ?, ?)',
        [name, email, phone || '', department, position],
        function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    res.status(409).json({ error: 'Email already exists' });
                } else {
                    res.status(500).json({ error: err.message });
                }
                return;
            }
            res.status(201).json({ 
                id: this.lastID, 
                name, 
                email, 
                phone, 
                department, 
                position
            });
        }
    );
});

// PUT update employee
app.put('/api/employees/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only admins can update employees' });
    }

    const { id } = req.params;
    const { name, email, phone, department, position } = req.body;

    if (!name || !email || !department || !position) {
        res.status(400).json({ error: 'Missing required fields' });
        return;
    }

    db.run(
        'UPDATE employees SET name = ?, email = ?, phone = ?, department = ?, position = ? WHERE id = ?',
        [name, email, phone || '', department, position, id],
        function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    res.status(409).json({ error: 'Email already exists' });
                } else {
                    res.status(500).json({ error: err.message });
                }
                return;
            }
            if (this.changes === 0) {
                res.status(404).json({ error: 'Employee not found' });
                return;
            }
            res.json({ message: 'Employee updated successfully' });
        }
    );
});

// DELETE employee
app.delete('/api/employees/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only admins can delete employees' });
    }

    const { id } = req.params;

    db.run('DELETE FROM employees WHERE id = ?', [id], function(err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            res.status(404).json({ error: 'Employee not found' });
            return;
        }
        res.json({ message: 'Employee deleted successfully' });
    });
});

// ATTENDANCE ENDPOINTS

// Mark attendance / Check-in
app.post('/api/attendance/checkin', authenticateToken, (req, res) => {
    const { latitude, longitude, photo } = req.body;
    const employeeId = req.user.employeeId;
    const today = new Date().toISOString().split('T')[0];
    const checkInTime = new Date().toLocaleTimeString();

    if (!employeeId) {
        res.status(400).json({ error: 'Employee ID not found in session' });
        return;
    }

    db.run(
        'INSERT INTO attendance (employeeId, date, checkInTime, checkInLatitude, checkInLongitude, loginPhoto, status) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(employeeId, date) DO UPDATE SET checkInTime = ?, checkInLatitude = ?, checkInLongitude = ?, loginPhoto = ?',
        [employeeId, today, checkInTime, latitude || null, longitude || null, photo || null, 'present', checkInTime, latitude || null, longitude || null, photo || null],
        function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({ 
                message: 'Check-in recorded successfully',
                checkInTime,
                location: latitude && longitude ? `${latitude}, ${longitude}` : 'Location not available'
            });
        }
    );
});

// Check-out
app.post('/api/attendance/checkout', authenticateToken, (req, res) => {
    const { latitude, longitude, checkOutPhoto } = req.body;
    const employeeId = req.user.employeeId;
    const today = new Date().toISOString().split('T')[0];
    const checkOutTime = new Date().toLocaleTimeString();

    if (!employeeId) {
        res.status(400).json({ error: 'Employee ID not found in session' });
        return;
    }

    if (!checkOutPhoto) {
        res.status(400).json({ error: 'Check-out photo is required. Please capture a photo before checking out.' });
        return;
    }

    // Check if today's attendance exists
    db.get(
        'SELECT * FROM attendance WHERE employeeId = ? AND date = ?',
        [employeeId, today],
        (err, row) => {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            if (!row) {
                res.status(400).json({ error: 'No check-in record found for today' });
                return;
            }

            // Proceed with checkout with photo
            db.run(
                'UPDATE attendance SET checkOutTime = ?, checkOutLatitude = ?, checkOutLongitude = ?, checkOutPhoto = ? WHERE employeeId = ? AND date = ?',
                [checkOutTime, latitude || null, longitude || null, checkOutPhoto, employeeId, today],
                function(err) {
                    if (err) {
                        res.status(500).json({ error: err.message });
                        return;
                    }
                    if (this.changes === 0) {
                        res.status(400).json({ error: 'Failed to record check-out' });
                        return;
                    }
                    res.json({ 
                        message: 'Check-out recorded successfully',
                        checkOutTime,
                        location: latitude && longitude ? `${latitude}, ${longitude}` : 'Location not available'
                    });
                }
            );
        }
    );
});

// GET today's attendance
app.get('/api/attendance/today', authenticateToken, (req, res) => {
    const employeeId = req.user.employeeId;
    const today = new Date().toISOString().split('T')[0];

    if (!employeeId) {
        res.status(400).json({ error: 'Employee ID not found in session' });
        return;
    }

    db.get(
        'SELECT * FROM attendance WHERE employeeId = ? AND date = ?',
        [employeeId, today],
        (err, row) => {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json(row || {});
        }
    );
});

// GET all attendance records (admin only)
app.get('/api/attendance', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only admins can view all attendance records' });
    }

    const { employeeId, startDate, endDate } = req.query;

    let query = `
        SELECT a.*, e.name, e.email, e.department 
        FROM attendance a 
        JOIN employees e ON a.employeeId = e.id
    `;
    const params = [];

    if (employeeId) {
        query += ' WHERE a.employeeId = ?';
        params.push(employeeId);
    }

    if (startDate && endDate) {
        query += params.length > 0 ? ' AND' : ' WHERE';
        query += ' a.date BETWEEN ? AND ?';
        params.push(startDate, endDate);
    }

    query += ' ORDER BY a.date DESC, e.name';

    db.all(query, params, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// GET attendance for specific employee (admin only)
app.get('/api/attendance/employee/:employeeId', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only admins can view employee attendance' });
    }

    const { employeeId } = req.params;
    const { startDate, endDate } = req.query;

    let query = 'SELECT * FROM attendance WHERE employeeId = ?';
    const params = [employeeId];

    if (startDate && endDate) {
        query += ' AND date BETWEEN ? AND ?';
        params.push(startDate, endDate);
    }

    query += ' ORDER BY date DESC';

    db.all(query, params, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// Validate employee login photo (admin only)
app.post('/api/attendance/validate-photo', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only admins can validate photos' });
    }

    const { attendanceId, approved } = req.body;
    const adminName = req.user.username;

    db.run(
        'UPDATE attendance SET photoValidated = ?, photoValidatedBy = ? WHERE id = ?',
        [approved ? 1 : 0, adminName, attendanceId],
        function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            if (this.changes === 0) {
                res.status(404).json({ error: 'Attendance record not found' });
                return;
            }
            res.json({ message: `Photo ${approved ? 'approved' : 'rejected'} successfully` });
        }
    );
});

// GET attendance records with unvalidated photos (admin only)
app.get('/api/attendance/unvalidated-photos', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only admins can view unvalidated photos' });
    }

    db.all(`
        SELECT a.*, e.name, e.email, e.department 
        FROM attendance a 
        JOIN employees e ON a.employeeId = e.id
        WHERE a.loginPhoto IS NOT NULL AND a.photoValidated = 0
        ORDER BY a.date DESC, e.name
    `, [], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// GET statistics
app.get('/api/stats', authenticateToken, (req, res) => {
    db.all(`
        SELECT 
            COUNT(*) as totalEmployees,
            COUNT(DISTINCT department) as departmentCount
        FROM employees
    `, [], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows[0]);
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Employee Management System running on http://localhost:${PORT}`);
    console.log('Database file: ' + dbPath);
});

// Graceful Shutdown
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err.message);
        } else {
            console.log('Database connection closed');
        }
        process.exit(0);
    });
});
