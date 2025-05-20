# Online Banking System

A simple online banking system built with Flask, SQLite, and plain HTML/CSS/JavaScript. This project is designed as a DBMS mini project to demonstrate basic online banking operations.

## Features

- User Registration & Login with secure password storage
- Dashboard showing balance and recent transactions
- Money Transfers between users
- Complete Transaction History
- Admin Panel for system oversight

## Installation & Setup

1. Clone the repository:
```bash
git clone https://github.com/AnasMohammedLalameyan/bank-management.git
cd online-banking
```

2. Create and activate a virtual environment (optional but recommended):
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python -c "from app import init_db; init_db()"
```

5. Run the application:
```bash
python run.py
```

6. Access the application at [http://localhost:5000](http://localhost:5000)

## Admin Access

To access the admin panel, use the following credentials:

- Email: admin@bank.com
- Password: admin123

(Note: In a production environment, you should use a much stronger password and consider additional security measures)

## Database Schema

The application uses SQLite with the following tables:
- Users: Stores user information including hashed passwords
- Accounts: Holds account balances and details
- Transactions: Records all financial transactions
- Admin logs: Tracks admin actions in the system

## Testing

The system comes with dummy data for testing purposes. After initialization, you can login with:

- Regular User:
  - Email: user@example.com
  - Password: password123

## Security Features

- Password hashing using Werkzeug's security functions
- Flask-Login for session management
- CSRF protection with Flask-WTF
- Input validation for all forms
- Transaction validations (sufficient balance, valid recipient, etc.)

## Development

This project follows a modular structure with routes, templates, and static files organized in separate directories for maintainability.

## License

This project is created for educational purposes only.