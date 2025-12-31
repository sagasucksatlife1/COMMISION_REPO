import sqlite3
from datetime import datetime
import hashlib
import secrets

class Database:
    def __init__(self, db_name="/tmp/commission_system.db"):  # Changed to /data/ for Render
        self.db_name = db_name
        self.init_db()
    
    def get_connection(self):
        conn = sqlite3.connect(self.db_name)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('employee', 'admin')),
            full_name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS commissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            sale_date DATE NOT NULL,
            unlisted_sales REAL NOT NULL DEFAULT 0,
            loans REAL NOT NULL DEFAULT 0,
            third_party_sales REAL NOT NULL DEFAULT 0,
            calculated_commission REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        conn.commit()
        conn.close()
        self.create_default_admin()
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def create_default_admin(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
        if not cursor.fetchone():
            password_hash = self.hash_password("admin123")
            cursor.execute('INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)', 
                         ("admin", password_hash, "admin", "System Admin"))
            conn.commit()
        conn.close()
    
    def create_user(self, username, password, role, full_name):
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)',
                         (username, self.hash_password(password), role, full_name))
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            return user_id
        except sqlite3.IntegrityError:
            conn.close()
            return None
    
    def verify_user(self, username, password):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role, full_name FROM users WHERE username = ? AND password_hash = ?',
                      (username, self.hash_password(password)))
        user = cursor.fetchone()
        conn.close()
        return dict(user) if user else None
    
    def create_session(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now().timestamp() + (24 * 60 * 60)
        cursor.execute('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, datetime(?, "unixepoch"))',
                      (user_id, token, expires_at))
        conn.commit()
        conn.close()
        return token
    
    def verify_session(self, token):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''SELECT s.user_id, u.username, u.role, u.full_name FROM sessions s
                         JOIN users u ON s.user_id = u.id WHERE s.token = ? AND s.expires_at > datetime('now')''', (token,))
        session = cursor.fetchone()
        conn.close()
        return dict(session) if session else None
    
    def delete_session(self, token):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    
    def create_commission(self, user_id, sale_date, unlisted_sales, loans, third_party_sales):
        calculated_commission = (loans / 3) + (unlisted_sales / 3) + third_party_sales
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO commissions (user_id, sale_date, unlisted_sales, loans, third_party_sales, calculated_commission) VALUES (?, ?, ?, ?, ?, ?)',
                      (user_id, sale_date, unlisted_sales, loans, third_party_sales, calculated_commission))
        conn.commit()
        commission_id = cursor.lastrowid
        conn.close()
        return commission_id
    
    def update_commission(self, commission_id, user_id, sale_date, unlisted_sales, loans, third_party_sales):
        calculated_commission = (loans / 3) + (unlisted_sales / 3) + third_party_sales
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE commissions SET sale_date=?, unlisted_sales=?, loans=?, third_party_sales=?, calculated_commission=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?',
                      (sale_date, unlisted_sales, loans, third_party_sales, calculated_commission, commission_id, user_id))
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        return affected > 0
    
    def delete_commission(self, commission_id, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM commissions WHERE id=? AND user_id=?', (commission_id, user_id))
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        return affected > 0
    
    def get_user_commissions(self, user_id, months=1):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM commissions WHERE user_id=? AND sale_date >= date("now", "-" || ? || " months") ORDER BY sale_date DESC',
                      (user_id, months))
        commissions = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return commissions
    
    def get_all_commissions(self, months=1, employee_id=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        if employee_id:
            cursor.execute('SELECT c.*, u.full_name as employee_name FROM commissions c JOIN users u ON c.user_id=u.id WHERE c.user_id=? AND c.sale_date >= date("now", "-" || ? || " months") ORDER BY c.sale_date DESC',
                          (employee_id, months))
        else:
            cursor.execute('SELECT c.*, u.full_name as employee_name FROM commissions c JOIN users u ON c.user_id=u.id WHERE c.sale_date >= date("now", "-" || ? || " months") ORDER BY c.sale_date DESC',
                          (months,))
        commissions = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return commissions
    
    def update_commission_status(self, commission_id, status):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE commissions SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', (status, commission_id))
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        return affected > 0
    
    def get_all_employees(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, full_name FROM users WHERE role="employee" ORDER BY full_name')
        employees = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return employees
    
    def delete_user(self, user_id):
        """Delete employee and all related data"""
        conn = self.get_connection()
        cursor = conn.cursor()
        # First delete all commissions by this user
        cursor.execute('DELETE FROM commissions WHERE user_id=?', (user_id,))
        # Then delete all sessions by this user
        cursor.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
        # Finally delete the user (only if employee)
        cursor.execute('DELETE FROM users WHERE id=? AND role="employee"', (user_id,))
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        return affected > 0
    
    def get_monthly_totals(self, employee_id=None, months=1):
        """Get monthly commission totals (approved only)"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if employee_id:
            # For specific employee
            cursor.execute('''
                SELECT 
                    strftime('%Y-%m', sale_date) as month,
                    SUM(calculated_commission) as total_commission,
                    COUNT(*) as total_entries
                FROM commissions 
                WHERE user_id=? 
                AND status='approved' 
                AND sale_date >= date("now", "-" || ? || " months")
                GROUP BY strftime('%Y-%m', sale_date)
                ORDER BY month DESC
            ''', (employee_id, months))
        else:
            # For all employees (admin view)
            cursor.execute('''
                SELECT 
                    u.full_name as employee_name,
                    u.id as employee_id,
                    strftime('%Y-%m', c.sale_date) as month,
                    SUM(c.calculated_commission) as total_commission,
                    COUNT(*) as total_entries
                FROM commissions c
                JOIN users u ON c.user_id = u.id
                WHERE c.status='approved'
                AND c.sale_date >= date("now", "-" || ? || " months")
                GROUP BY u.id, strftime('%Y-%m', c.sale_date)
                ORDER BY month DESC, u.full_name
            ''', (months,))
        
        totals = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return totals
    
    def admin_create_commission(self, user_id, sale_date, unlisted_sales, loans, third_party_sales, status='approved'):
        """Admin can create commission for any employee with custom status"""
        calculated_commission = (loans / 3) + (unlisted_sales / 3) + third_party_sales
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO commissions 
            (user_id, sale_date, unlisted_sales, loans, third_party_sales, calculated_commission, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, sale_date, unlisted_sales, loans, third_party_sales, calculated_commission, status))
        conn.commit()
        commission_id = cursor.lastrowid
        conn.close()
        return commission_id
        
    def change_password(self, user_id, new_password):
        """Change user password"""
        conn = self.get_connection()
        cursor = conn.cursor()
        password_hash = self.hash_password(new_password)
        cursor.execute('UPDATE users SET password_hash=? WHERE id=?', (password_hash, user_id))
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        return affected > 0
