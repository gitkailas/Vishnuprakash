# Employee Management System with SQLite

A modern web-based employee management system using Node.js/Express backend and SQLite database.

## Features

- ✅ Add, edit, and delete employees
- ✅ SQLite database for persistent data storage
- ✅ RESTful API endpoints
- ✅ Real-time statistics
- ✅ Responsive modern UI
- ✅ Email uniqueness validation
- ✅ Data persistence across sessions

## Prerequisites

- Node.js (v14 or higher)
- npm (comes with Node.js)

## Installation

1. Navigate to the project directory:
```bash
cd c:\Users\kaila\Vishnuprakash
```

2. Install dependencies:
```bash
npm install
```

This will install:
- `express` - Web server framework
- `sqlite3` - SQLite database driver
- `cors` - Cross-Origin Resource Sharing
- `body-parser` - JSON request parsing

## Running the Application

1. Start the server:
```bash
npm start
```

Or:
```bash
node server.js
```

You should see:
```
Employee Management System running on http://localhost:3000
Database file: c:\Users\kaila\Vishnuprakash\employees.db
```

2. Open your browser and go to:
```
http://localhost:3000
```

## Database

The SQLite database (`employees.db`) is automatically created on first run. It contains:

### Employees Table Schema
```sql
CREATE TABLE employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT,
    department TEXT NOT NULL,
    position TEXT NOT NULL,
    salary REAL,
    dateAdded TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
)
```

## API Endpoints

### GET all employees
```
GET /api/employees
```

### GET single employee
```
GET /api/employees/:id
```

### CREATE new employee
```
POST /api/employees
Content-Type: application/json

{
    "name": "John Doe",
    "email": "john@example.com",
    "phone": "(123) 456-7890",
    "department": "IT",
    "position": "Developer",
    "salary": 75000
}
```

### UPDATE employee
```
PUT /api/employees/:id
Content-Type: application/json

{
    "name": "John Doe",
    "email": "john@example.com",
    "phone": "(123) 456-7890",
    "department": "IT",
    "position": "Senior Developer",
    "salary": 85000
}
```

### DELETE employee
```
DELETE /api/employees/:id
```

### GET statistics
```
GET /api/stats
```

## File Structure

```
c:\Users\kaila\Vishnuprakash\
├── index.html          # Frontend web page
├── server.js           # Express backend server
├── package.json        # Project dependencies
├── employees.db        # SQLite database (auto-created)
└── README.md           # This file
```

## Troubleshooting

### "Cannot find module" error
Make sure you've run `npm install` to install all dependencies.

### Port 3000 already in use
Either close the application using port 3000 or change the PORT variable in `server.js`.

### CORS errors
The server has CORS enabled, but make sure you're accessing from `http://localhost:3000`.

### Database errors
If you encounter database issues, simply delete the `employees.db` file and restart the server - it will be recreated.

## Notes

- All employee emails must be unique
- Required fields: name, email, department, position
- Phone and salary are optional
- The database persists all data between server restarts
- The frontend will show an alert if it cannot connect to the server

## License

ISC
