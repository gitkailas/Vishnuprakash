const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

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
    db.run(`
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT,
            department TEXT NOT NULL,
            position TEXT NOT NULL,
            salary REAL,
            dateAdded TEXT DEFAULT CURRENT_TIMESTAMP,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) {
            console.error('Error creating table:', err.message);
        } else {
            console.log('Employees table ready');
        }
    });
}

// API Routes

// GET all employees
app.get('/api/employees', (req, res) => {
    db.all('SELECT * FROM employees ORDER BY id DESC', [], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// GET single employee
app.get('/api/employees/:id', (req, res) => {
    const { id } = req.params;
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
app.post('/api/employees', (req, res) => {
    const { name, email, phone, department, position, salary } = req.body;

    if (!name || !email || !department || !position) {
        res.status(400).json({ error: 'Missing required fields' });
        return;
    }

    db.run(
        'INSERT INTO employees (name, email, phone, department, position, salary, dateAdded) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [name, email, phone || '', department, position, salary || 0, new Date().toLocaleDateString()],
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
                position, 
                salary,
                dateAdded: new Date().toLocaleDateString()
            });
        }
    );
});

// PUT update employee
app.put('/api/employees/:id', (req, res) => {
    const { id } = req.params;
    const { name, email, phone, department, position, salary } = req.body;

    if (!name || !email || !department || !position) {
        res.status(400).json({ error: 'Missing required fields' });
        return;
    }

    db.run(
        'UPDATE employees SET name = ?, email = ?, phone = ?, department = ?, position = ?, salary = ? WHERE id = ?',
        [name, email, phone || '', department, position, salary || 0, id],
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
app.delete('/api/employees/:id', (req, res) => {
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

// GET statistics
app.get('/api/stats', (req, res) => {
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
