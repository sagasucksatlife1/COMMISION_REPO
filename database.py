import os
import psycopg2
import psycopg2.extras
from datetime import datetime
import hashlib
import secrets

class Database:
    def __init__(self):
        self.db_url = os.getenv("DATABASE_URL")
        if not self.db_url:
            raise Exception("DATABASE_URL environment variable not set")
        self.conn = psycopg2.connect(self.db_url)
        self.conn.autocommit = True
        self.init_db()
    
    def cursor(self):
        return self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    def init_db(self):
        with self.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('employee','admin')),
                full_name TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
            """)

            cur.execute("""
            CREATE TABLE IF NOT EXISTS commissions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                sale_date DATE NOT NULL,
                unlisted_sales NUMERIC DEFAULT 0,
                loans NUMERIC DEFAULT 0,
                third_party_sales NUMERIC DEFAULT 0,
                calculated_commission NUMERIC NOT NULL,
                status TEXT DEFAULT 'pending'
                    CHECK(status IN ('pending','approved','rejected')),
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
            """)

            cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMPTZ NOT NULL
            )
            """)

        self.create_default_admin()
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def create_default_admin(self):
        with self.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username=%s", ("admin",))
            if cur.fetchone():
                return

            cur.execute("""
            INSERT INTO users (username,password_hash,role,full_name)
            VALUES (%s,%s,'admin','System Admin')
            """, ("admin", self.hash_password("admin123")))
    
    def create_user(self, username, password, role, full_name):
        try:
            with self.cursor() as cur:
                cur.execute("""
                INSERT INTO users (username,password_hash,role,full_name)
                VALUES (%s,%s,%s,%s)
                RETURNING id
                """, (username, self.hash_password(password), role, full_name))
                result = cur.fetchone()
                return result["id"] if result else None
        except:
            return None
    
    def verify_user(self, username, password):
        with self.cursor() as cur:
            cur.execute("""
            SELECT id, username, role, full_name
            FROM users
            WHERE username=%s AND password_hash=%s
            """, (username, self.hash_password(password)))
            user = cur.fetchone()
            return dict(user) if user else None
    
    def create_session(self, user_id):
        token = secrets.token_urlsafe(32)
        expires = datetime.utcnow().timestamp() + (24 * 60 * 60)

        with self.cursor() as cur:
            cur.execute("""
            INSERT INTO sessions (user_id, token, expires_at)
            VALUES (%s,%s,TO_TIMESTAMP(%s))
            """, (user_id, token, expires))

        return token
    
    def verify_session(self, token):
        with self.cursor() as cur:
            cur.execute("""
            SELECT s.user_id, u.username, u.role, u.full_name
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token=%s AND s.expires_at > NOW()
            """, (token,))
            session = cur.fetchone()
            return dict(session) if session else None
    
    def delete_session(self, token):
        with self.cursor() as cur:
            cur.execute("DELETE FROM sessions WHERE token=%s", (token,))
    
    def create_commission(self, user_id, sale_date, unlisted_sales, loans, third_party_sales):
        calculated_commission = (loans / 3) + (unlisted_sales / 3) + third_party_sales

        with self.cursor() as cur:
            cur.execute("""
            INSERT INTO commissions
            (user_id,sale_date,unlisted_sales,loans,third_party_sales,calculated_commission)
            VALUES (%s,%s,%s,%s,%s,%s)
            RETURNING id
            """, (user_id, sale_date, unlisted_sales, loans, third_party_sales, calculated_commission))
            result = cur.fetchone()
            return result["id"] if result else None
    
    def update_commission(self, commission_id, user_id, sale_date, unlisted_sales, loans, third_party_sales):
        calculated_commission = (loans / 3) + (unlisted_sales / 3) + third_party_sales

        with self.cursor() as cur:
            cur.execute("""
            UPDATE commissions
            SET sale_date=%s,
                unlisted_sales=%s,
                loans=%s,
                third_party_sales=%s,
                calculated_commission=%s,
                updated_at=NOW()
            WHERE id=%s AND user_id=%s
            """, (sale_date, unlisted_sales, loans, third_party_sales, calculated_commission, commission_id, user_id))
            return cur.rowcount > 0
    
    def delete_commission(self, commission_id, user_id):
        with self.cursor() as cur:
            cur.execute("DELETE FROM commissions WHERE id=%s AND user_id=%s", (commission_id, user_id))
            return cur.rowcount > 0
    
    def get_user_commissions(self, user_id, months=1):
        with self.cursor() as cur:
            cur.execute("""
            SELECT * FROM commissions
            WHERE user_id=%s
              AND sale_date >= NOW() - (%s || ' months')::interval
            ORDER BY sale_date DESC
            """, (user_id, months))
            return cur.fetchall()
    
    def get_all_commissions(self, months=1, employee_id=None):
        with self.cursor() as cur:
            if employee_id:
                cur.execute("""
                SELECT c.*, u.full_name AS employee_name
                FROM commissions c
                JOIN users u ON u.id=c.user_id
                WHERE c.user_id=%s
                  AND c.sale_date >= NOW() - (%s || ' months')::interval
                ORDER BY c.sale_date DESC
                """, (employee_id, months))
            else:
                cur.execute("""
                SELECT c.*, u.full_name AS employee_name
                FROM commissions c
                JOIN users u ON u.id=c.user_id
                WHERE c.sale_date >= NOW() - (%s || ' months')::interval
                ORDER BY c.sale_date DESC
                """, (months,))
            return cur.fetchall()
    
    def update_commission_status(self, commission_id, status):
        with self.cursor() as cur:
            cur.execute("""
            UPDATE commissions
            SET status=%s, updated_at=NOW()
            WHERE id=%s
            """, (status, commission_id))
            return cur.rowcount > 0
    
    def get_all_employees(self):
        with self.cursor() as cur:
            cur.execute("""
            SELECT id, username, full_name
            FROM users
            WHERE role='employee'
            ORDER BY full_name
            """)
            return cur.fetchall()
    
    def delete_user(self, user_id):
        """Delete employee and all related data (cascades automatically)"""
        with self.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id=%s AND role='employee'", (user_id,))
            return cur.rowcount > 0
    
    def get_monthly_totals(self, employee_id=None, months=1):
        """Get monthly commission totals (approved only)"""
        with self.cursor() as cur:
            if employee_id:
                cur.execute("""
                SELECT 
                    TO_CHAR(sale_date, 'YYYY-MM') as month,
                    SUM(calculated_commission) as total_commission,
                    COUNT(*) as total_entries
                FROM commissions 
                WHERE user_id=%s 
                AND status='approved' 
                AND sale_date >= NOW() - (%s || ' months')::interval
                GROUP BY TO_CHAR(sale_date, 'YYYY-MM')
                ORDER BY month DESC
                """, (employee_id, months))
            else:
                cur.execute("""
                SELECT 
                    u.full_name as employee_name,
                    u.id as employee_id,
                    TO_CHAR(c.sale_date, 'YYYY-MM') as month,
                    SUM(c.calculated_commission) as total_commission,
                    COUNT(*) as total_entries
                FROM commissions c
                JOIN users u ON c.user_id = u.id
                WHERE c.status='approved'
                AND c.sale_date >= NOW() - (%s || ' months')::interval
                GROUP BY u.id, u.full_name, TO_CHAR(c.sale_date, 'YYYY-MM')
                ORDER BY month DESC, u.full_name
                """, (months,))
            return cur.fetchall()
    
    def admin_create_commission(self, user_id, sale_date, unlisted_sales, loans, third_party_sales, status='approved'):
        """Admin can create commission for any employee with custom status"""
        calculated_commission = (loans / 3) + (unlisted_sales / 3) + third_party_sales
        
        with self.cursor() as cur:
            cur.execute("""
            INSERT INTO commissions 
            (user_id, sale_date, unlisted_sales, loans, third_party_sales, calculated_commission, status) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """, (user_id, sale_date, unlisted_sales, loans, third_party_sales, calculated_commission, status))
            result = cur.fetchone()
            return result["id"] if result else None
    
    def change_password(self, user_id, new_password):
        """Change user password"""
        with self.cursor() as cur:
            password_hash = self.hash_password(new_password)
            cur.execute('UPDATE users SET password_hash=%s WHERE id=%s', (password_hash, user_id))
            return cur.rowcount > 0
