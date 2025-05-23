import os
from datetime import datetime
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets

# Configuration
DATABASE = 'instance/banking.db'
SECRET_KEY = secrets.token_hex(16)  # Generate a random secret key

app = Flask(__name__)
app.config.from_mapping(
    SECRET_KEY=SECRET_KEY,
    DATABASE=os.path.join(app.instance_path, 'banking.db'),
)

# Ensure the instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

# Database connection
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

app.teardown_appcontext(close_db)

# Helper function to get transaction type ID
def get_transaction_type_id(type_name):
    db = get_db()
    result = db.execute('SELECT id FROM transaction_types WHERE type_name = ?', (type_name,)).fetchone()
    return result['id'] if result else None

# Initialize database
def init_db():
    db = get_db()
    with app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))
    
    # Add admin user
    admin_password = generate_password_hash('admin123')
    db.execute(
        'INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)',
        ('Admin', 'admin@bank.com', admin_password, 1)
    )
    
    # Create admin account
    db.execute(
        'INSERT INTO accounts (user_id, account_number, balance, created_at) VALUES (?, ?, ?, ?)',
        (1, '1000000001', 100000.00, datetime.now())
    )
    
    # Add test user
    user_password = generate_password_hash('password123')
    db.execute(
        'INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)',
        ('Test User', 'user@example.com', user_password, 0)
    )
    
    # Create test user account
    db.execute(
        'INSERT INTO accounts (user_id, account_number, balance, created_at) VALUES (?, ?, ?, ?)',
        (2, '1000000002', 5000.00, datetime.now())
    )
    
    db.commit()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Helper to get logged in user
def get_current_user():
    user_id = session.get('user_id')
    if user_id is None:
        return None
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    return user

# Helper to get user account
def get_user_account(user_id):
    db = get_db()
    account = db.execute('SELECT * FROM accounts WHERE user_id = ?', (user_id,)).fetchone()
    return account

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('auth/login.html')

# Authentication routes
@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        db = get_db()
        error = None
        
        if not username:
            error = 'Username is required.'
        elif not email:
            error = 'Email is required.'
        elif not password:
            error = 'Password is required.'
        elif password != confirm_password:
            error = 'Passwords do not match.'
        elif db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone() is not None:
            error = f'User with email {email} is already registered.'
            
        if error is None:
            # Create user
            db.execute(
                'INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)',
                (username, email, generate_password_hash(password), 0)
            )
            db.commit()
            
            # Get the new user's ID
            user = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
            user_id = user['id']
            
            # Generate account number (simple implementation)
            account_number = f'10{user_id:08d}'
            
            # Create account for the user
            db.execute(
                'INSERT INTO accounts (user_id, account_number, balance, created_at) VALUES (?, ?, ?, ?)',
                (user_id, account_number, 1000.00, datetime.now())  # Start with $1000 for demo
            )
            db.commit()
            
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        
        flash(error, 'danger')
        
    return render_template('auth/register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        error = None
        if user is None:
            error = 'Invalid email address.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'
            
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            
            if user['is_admin']:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        
        flash(error, 'danger')
        
    return render_template('auth/login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Dashboard routes
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    db = get_db()
    
    # Get user account
    account = get_user_account(user_id)
    
    # Get recent transactions with transaction types
    transactions = db.execute(
        '''SELECT t.*, 
                tt.type_name,
                u_from.username as sender_name, 
                u_to.username as receiver_name
           FROM transactions t
           JOIN transaction_types tt ON t.transaction_type_id = tt.id
           LEFT JOIN accounts a_from ON t.from_account_id = a_from.id
           LEFT JOIN accounts a_to ON t.to_account_id = a_to.id
           LEFT JOIN users u_from ON a_from.user_id = u_from.id
           LEFT JOIN users u_to ON a_to.user_id = u_to.id
           WHERE a_from.user_id = ? OR a_to.user_id = ?
           ORDER BY t.created_at DESC LIMIT 10''',
        (user_id, user_id)
    ).fetchall()
    
    return render_template('dashboard/index.html', 
                          account=account, 
                          transactions=transactions)

@app.route('/profile')
@login_required
def profile():
    user = get_current_user()
    return render_template('dashboard/profile.html', user=user)

# New route to demonstrate the view
@app.route('/account_summary')
@login_required
def account_summary():
    user_id = session['user_id']
    db = get_db()
    
    # Use the account_summary view
    summary = db.execute(
        '''SELECT * FROM account_summary 
           WHERE account_id IN (SELECT id FROM accounts WHERE user_id = ?)''',
        (user_id,)
    ).fetchone()
    
    return render_template('dashboard/account_summary.html', summary=summary)

# Transaction routes
@app.route('/transfer', methods=('GET', 'POST'))
@login_required
def transfer():
    user_id = session['user_id']
    db = get_db()
    
    if request.method == 'POST':
        amount = float(request.form['amount'])
        recipient_account = request.form['recipient_account']
        description = request.form['description']
        
        error = None
        
        # Validate input
        if amount <= 0:
            error = 'Amount must be greater than zero.'
        
        # Get sender's account
        sender_account = get_user_account(user_id)
        if not sender_account:
            error = 'Your account could not be found.'
        elif amount > sender_account['balance']:
            error = 'Insufficient funds for this transfer.'
        
        # Get recipient's account
        recipient = db.execute(
            'SELECT * FROM accounts WHERE account_number = ?', 
            (recipient_account,)
        ).fetchone()
        
        if not recipient:
            error = 'Recipient account not found.'
        elif recipient['id'] == sender_account['id']:
            error = 'Cannot transfer to your own account.'
        
        if error is None:
            try:
                # Begin transaction
                db.execute('BEGIN TRANSACTION')
                
                # Deduct from sender
                db.execute(
                    'UPDATE accounts SET balance = balance - ? WHERE id = ?',
                    (amount, sender_account['id'])
                )
                
                # Add to recipient
                db.execute(
                    'UPDATE accounts SET balance = balance + ? WHERE id = ?',
                    (amount, recipient['id'])
                )
                
                # Get transaction type ID
                transfer_type_id = get_transaction_type_id('TRANSFER')
                
                # Record transaction
                db.execute(
                    '''INSERT INTO transactions 
                       (from_account_id, to_account_id, amount, transaction_type_id, description, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    (sender_account['id'], recipient['id'], amount, transfer_type_id, description, datetime.now())
                )
                
                db.execute('COMMIT')
                flash('Transfer completed successfully!', 'success')
                return redirect(url_for('dashboard'))
                
            except sqlite3.Error as e:
                db.execute('ROLLBACK')
                error = f'Database error: {e}'
        
        flash(error, 'danger')
    
    return render_template('transactions/transfer.html')

@app.route('/deposit', methods=('GET', 'POST'))
@login_required
def deposit():
    user_id = session['user_id']
    db = get_db()
    
    if request.method == 'POST':
        amount = float(request.form['amount'])
        
        error = None
        
        # Validate input
        if amount <= 0:
            error = 'Amount must be greater than zero.'
        
        # Get user's account
        account = get_user_account(user_id)
        if not account:
            error = 'Your account could not be found.'
        
        if error is None:
            try:
                # Update account balance
                db.execute(
                    'UPDATE accounts SET balance = balance + ? WHERE id = ?',
                    (amount, account['id'])
                )
                
                # Get transaction type ID
                deposit_type_id = get_transaction_type_id('DEPOSIT')
                
                # Record transaction (deposit has no sender)
                db.execute(
                    '''INSERT INTO transactions 
                       (from_account_id, to_account_id, amount, transaction_type_id, description, created_at)
                       VALUES (NULL, ?, ?, ?, ?, ?)''',
                    (account['id'], amount, deposit_type_id, 'Deposit', datetime.now())
                )
                
                db.commit()
                flash('Deposit completed successfully!', 'success')
                return redirect(url_for('dashboard'))
                
            except sqlite3.Error as e:
                error = f'Database error: {e}'
        
        flash(error, 'danger')
    
    return render_template('transactions/deposit.html')

@app.route('/withdraw', methods=('GET', 'POST'))
@login_required
def withdraw():
    user_id = session['user_id']
    db = get_db()
    
    if request.method == 'POST':
        amount = float(request.form['amount'])
        
        error = None
        
        # Validate input
        if amount <= 0:
            error = 'Amount must be greater than zero.'
        
        # Get user's account
        account = get_user_account(user_id)
        if not account:
            error = 'Your account could not be found.'
        elif amount > account['balance']:
            error = 'Insufficient funds for this withdrawal.'
        
        if error is None:
            try:
                # Update account balance
                db.execute(
                    'UPDATE accounts SET balance = balance - ? WHERE id = ?',
                    (amount, account['id'])
                )
                
                # Get transaction type ID
                withdrawal_type_id = get_transaction_type_id('WITHDRAWAL')
                
                # Record transaction (withdrawal has no recipient)
                db.execute(
                    '''INSERT INTO transactions 
                       (from_account_id, to_account_id, amount, transaction_type_id, description, created_at)
                       VALUES (?, NULL, ?, ?, ?, ?)''',
                    (account['id'], amount, withdrawal_type_id, 'Withdrawal', datetime.now())
                )
                
                db.commit()
                flash('Withdrawal completed successfully!', 'success')
                return redirect(url_for('dashboard'))
                
            except sqlite3.Error as e:
                error = f'Database error: {e}'
        
        flash(error, 'danger')
    
    return render_template('transactions/withdraw.html')

@app.route('/history')
@login_required
def transaction_history():
    user_id = session['user_id']
    db = get_db()
    
    # Get user account
    account = get_user_account(user_id)
    
    # Get all transactions with transaction types
    transactions = db.execute(
        '''SELECT t.*, 
                tt.type_name,
                u_from.username as sender_name, 
                u_to.username as receiver_name,
                a_from.account_number as sender_account,
                a_to.account_number as receiver_account
           FROM transactions t
           JOIN transaction_types tt ON t.transaction_type_id = tt.id
           LEFT JOIN accounts a_from ON t.from_account_id = a_from.id
           LEFT JOIN accounts a_to ON t.to_account_id = a_to.id
           LEFT JOIN users u_from ON a_from.user_id = u_from.id
           LEFT JOIN users u_to ON a_to.user_id = u_to.id
           WHERE a_from.user_id = ? OR a_to.user_id = ?
           ORDER BY t.created_at DESC''',
        (user_id, user_id)
    ).fetchall()
    
    return render_template('transactions/history.html', 
                          account=account, 
                          transactions=transactions)

# Admin routes
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    db = get_db()
    
    # Count users
    user_count = db.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    
    # Calculate total money in system
    total_money = db.execute('SELECT SUM(balance) as total FROM accounts').fetchone()['total']
    
    # Get recent transactions
    transactions = db.execute(
        '''SELECT t.*, 
                tt.type_name,
                u_from.username as sender_name, 
                u_to.username as receiver_name,
                a_from.account_number as sender_account,
                a_to.account_number as receiver_account
           FROM transactions t
           JOIN transaction_types tt ON t.transaction_type_id = tt.id
           LEFT JOIN accounts a_from ON t.from_account_id = a_from.id
           LEFT JOIN accounts a_to ON t.to_account_id = a_to.id
           LEFT JOIN users u_from ON a_from.user_id = u_from.id
           LEFT JOIN users u_to ON a_to.user_id = u_to.id
           ORDER BY t.created_at DESC LIMIT 10'''
    ).fetchall()
    
    return render_template('admin/dashboard.html', 
                          user_count=user_count,
                          total_money=total_money, 
                          transactions=transactions)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    db = get_db()
    # Use the account_summary view for admin users page
    users = db.execute('SELECT * FROM account_summary ORDER BY account_id').fetchall()
    
    return render_template('admin/users.html', users=users)

@app.route('/admin/logs')
@login_required
@admin_required
def admin_logs():
    db = get_db()
    logs = db.execute('SELECT * FROM admin_logs ORDER BY created_at DESC').fetchall()
    
    return render_template('admin/logs.html', logs=logs)

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error='Internal server error'), 500

if __name__ == '__main__':
    app.run(debug=True)