-- Initialize the database schema for online banking system
-- Enhanced version with View, Trigger, and 3NF normalization

-- Drop tables if they exist (in correct order due to foreign keys)
DROP TABLE IF EXISTS admin_logs;
DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS transaction_types;

-- New table for 3NF normalization: Transaction Types
CREATE TABLE transaction_types (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type_name TEXT UNIQUE NOT NULL,
  description TEXT
);

-- Insert default transaction types
INSERT INTO transaction_types (type_name, description) VALUES 
  ('TRANSFER', 'Money transfer between accounts'),
  ('DEPOSIT', 'Money deposit into account'),
  ('WITHDRAWAL', 'Money withdrawal from account');

-- Users table (already normalized)
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Accounts table (already normalized)
CREATE TABLE accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  account_number TEXT UNIQUE NOT NULL,
  balance REAL NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Enhanced Transactions table (normalized to 3NF)
CREATE TABLE transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_account_id INTEGER,
  to_account_id INTEGER,
  amount REAL NOT NULL,
  transaction_type_id INTEGER NOT NULL,
  description TEXT,
  created_at TIMESTAMP NOT NULL,
  FOREIGN KEY (from_account_id) REFERENCES accounts (id),
  FOREIGN KEY (to_account_id) REFERENCES accounts (id),
  FOREIGN KEY (transaction_type_id) REFERENCES transaction_types (id)
);

-- Admin logs table (already normalized)
CREATE TABLE admin_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER NOT NULL,
  action TEXT NOT NULL,
  description TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (admin_id) REFERENCES users (id)
);

-- VIEW: Account Summary View
-- This view provides a comprehensive overview of each account with user details and transaction summary
CREATE VIEW account_summary AS
SELECT 
    a.id as account_id,
    a.account_number,
    a.balance,
    u.username,
    u.email,
    a.created_at as account_created,
    COUNT(t_out.id) as outgoing_transactions,
    COUNT(t_in.id) as incoming_transactions,
    COALESCE(SUM(CASE WHEN t_out.from_account_id = a.id THEN t_out.amount ELSE 0 END), 0) as total_sent,
    COALESCE(SUM(CASE WHEN t_in.to_account_id = a.id THEN t_in.amount ELSE 0 END), 0) as total_received
FROM accounts a
JOIN users u ON a.user_id = u.id
LEFT JOIN transactions t_out ON t_out.from_account_id = a.id
LEFT JOIN transactions t_in ON t_in.to_account_id = a.id
GROUP BY a.id, a.account_number, a.balance, u.username, u.email, a.created_at;

-- TRIGGER: Audit Trail Trigger
-- This trigger automatically logs all balance changes for audit purposes
CREATE TRIGGER balance_change_audit
    AFTER UPDATE OF balance ON accounts
    FOR EACH ROW
    WHEN OLD.balance != NEW.balance
BEGIN
    INSERT INTO admin_logs (admin_id, action, description, created_at)
    VALUES (
        1, -- Default to admin user ID 1 for system actions
        'BALANCE_CHANGE',
        'Account ' || NEW.account_number || ' balance changed from $' || 
        printf('%.2f', OLD.balance) || ' to $' || printf('%.2f', NEW.balance) || 
        ' (Change: $' || printf('%.2f', NEW.balance - OLD.balance) || ')',
        datetime('now')
    );
END;

-- Indexes for better performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_accounts_user_id ON accounts(user_id);
CREATE INDEX idx_accounts_account_number ON accounts(account_number);
CREATE INDEX idx_transactions_from_account ON transactions(from_account_id);
CREATE INDEX idx_transactions_to_account ON transactions(to_account_id);
CREATE INDEX idx_transactions_created_at ON transactions(created_at);
CREATE INDEX idx_transactions_type ON transactions(transaction_type_id);
CREATE INDEX idx_transaction_types_name ON transaction_types(type_name);