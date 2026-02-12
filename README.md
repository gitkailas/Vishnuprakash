# Employee Management System with SQLite

A comprehensive web-based employee management system with attendance tracking and device location support. Features separate login interfaces for employees and administrators with role-based access control.

## Features

- ✅ **Authentication System**
  - Admin/Admin credentials (modifiable)
  - Role-based access control (Admin & Employee)
  - Secure session management

- ✅ **Employee Dashboard**
  - Mark attendance with check-in/check-out
  - Device GPS location tracking
  - Attendance summary for the day
  - Location permission handling

- ✅ **Admin Dashboard**
  - Manage employees (CRUD operations)
  - View all attendance records
  - View real-time statistics
  - Department-wise employee organization
  - Employee location tracking for attendance

- ✅ **Database**
  - SQLite with three main tables: employees, users, attendance
  - Email uniqueness validation
  - Location data (latitude/longitude) for check-ins
  - Date-based attendance tracking

## Prerequisites

- Node.js (v14 or higher)
- npm (comes with Node.js)
- Modern web browser with geolocation support

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
Default admin user created (username: admin, password: admin)
```

2. Open your browser and go to:
```
http://localhost:3000/login.html
```

## Default Credentials

- **Username:** admin
- **Password:** admin
- **Role:** Admin

These credentials can be modified later in the system settings.

## User Flows

### For Employees
1. Login with employee credentials (role: Employee)
2. View dashboard with attendance status
3. Click "Mark Check-In" to start attendance with location
4. Click "Mark Check-Out" to end attendance
5. View today's summary

### For Administrators
1. Login with admin credentials (role: Admin)
2. **Employees Tab:** Add, edit, delete employees; view employee list and statistics
3. **Attendance Tab:** View all attendance records with location data
4. **Reports Tab:** View comprehensive reports (coming soon)

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    employeeId INTEGER,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
)
```

### Employees Table
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

### Attendance Table
```sql
CREATE TABLE attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employeeId INTEGER NOT NULL,
    date TEXT NOT NULL,
    checkInTime TEXT,
    checkOutTime TEXT,
    latitude REAL,
    longitude REAL,
    status TEXT DEFAULT 'present',
    notes TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(employeeId, date)
)
```

## API Endpoints

### Authentication
- `POST /api/login` - User login
- `POST /api/logout` - User logout
- `GET /api/user/info` - Get current user info

### Employees (Admin Only)
- `GET /api/employees` - Get all employees
- `GET /api/employees/:id` - Get single employee
- `POST /api/employees` - Create employee
- `PUT /api/employees/:id` - Update employee
- `DELETE /api/employees/:id` - Delete employee

### Attendance
- `POST /api/attendance/checkin` - Mark check-in with location
- `POST /api/attendance/checkout` - Mark check-out
- `GET /api/attendance/today` - Get today's attendance
- `GET /api/attendance` - Get all attendance (Admin only)
- `GET /api/attendance/employee/:employeeId` - Get employee attendance (Admin only)

### Statistics
- `GET /api/stats` - Get system statistics

## File Structure

```
c:\Users\kaila\Vishnuprakash\
├── login.html           # Login page for both roles
├── employee.html        # Employee dashboard
├── admin.html           # Alias for index.html (admin dashboard)
├── index.html           # Admin dashboard
├── server.js            # Express backend server
├── package.json         # Project dependencies
├── employees.db         # SQLite database (auto-created)
└── README.md            # This file
```

## Troubleshooting

### "Cannot find module" error
Make sure you've run `npm install` to install all dependencies.

### Port 3000 already in use
Either close the application using port 3000 or change the PORT variable in `server.js`.

### CORS errors
The server has CORS enabled. Make sure you're accessing from `http://localhost:3000`.

### Location not being captured
- Check browser geolocation permissions
- Ensure HTTPS or localhost (required for geolocation)
- Grant permission when prompted

### Database errors
If you encounter database issues, simply delete the `employees.db` file and restart the server - it will be recreated.

### Session expires
If your session expires, you'll be redirected to the login page automatically.

## Security Notes

- Passwords are hashed using SHA256 (suitable for development; use bcrypt for production)
- Sessions are stored in memory (use Redis or database for production)
- All authenticated endpoints require valid token
- Role-based access control is enforced on all endpoints

## Future Enhancements

- [ ] Password change functionality
- [ ] Leave management system
- [ ] Payroll integration
- [ ] Advanced attendance reports
- [ ] Database-backed sessions
- [ ] Production-grade password hashing (bcrypt)
- [ ] Email notifications
- [ ] Mobile app
- [ ] Multi-language support

## Notes

- All employee emails must be unique
- Required fields: name, email, department, position (for employees)
- Phone and salary are optional
- The database persists all data between server restarts
- Location data is optional but recommended for attendance tracking
- Each employee can have one check-in per day
- Check-out will fail if there's no check-in for that day

## License

ISC
