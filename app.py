from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import time
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "supersecretkey"

def get_db_connection():
    conn = sqlite3.connect('bank.db')
    conn.row_factory = sqlite3.Row
    return conn

# Setup database
def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            balance REAL DEFAULT 0,
            loan_amount REAL DEFAULT 0,
            loan_time TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    conn.execute('CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY, sender TEXT, receiver TEXT, amount REAL, timestamp TEXT)')
    conn.commit()

    # 🛡️ Insert admin user if not already there
    existing_admin = conn.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
    if not existing_admin:
        conn.execute('INSERT INTO users (username, password, balance, role) VALUES (?, ?, ?, ?)',
                     ('admin', 'admin123', 10000, 'admin'))
        conn.commit()

    conn.close()

# Initialize database
init_db()


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password, balance) VALUES (?, ?, 0)', (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists!"
        conn.close()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        conn.close()
        if user:
            
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials!"
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    transactions = conn.execute('SELECT * FROM transactions ORDER BY timestamp DESC').fetchall()
    conn.close()

    return render_template('dashboard.html', user=user, transactions=transactions)

@app.route('/send', methods=['POST'])
def send():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    receiver = request.form['receiver']
    amount = float(request.form['amount'])
    
    conn = get_db_connection()
    sender = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    receiver_user = conn.execute('SELECT * FROM users WHERE username = ?', (receiver,)).fetchone()
    
    if not receiver_user:
        conn.close()
        return "Receiver not found!"

    if sender['balance'] < amount:
        conn.close()
        return "Not enough balance!"

    # Update balances
    conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (amount, sender['id']))
    conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, receiver_user['id']))
    
    # Add transaction record
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute('INSERT INTO transactions (sender, receiver, amount, timestamp) VALUES (?, ?, ?, ?)',
                 (sender['username'], receiver_user['username'], amount, now))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))

@app.route('/loan', methods=['GET', 'POST'])
def loan():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if request.method == 'POST':
        if user['loan_amount'] == 0:
            now = datetime.now()
            conn.execute('UPDATE users SET loan_amount = 1000, balance = balance + 1000, loan_time = ? WHERE id = ?', (now.strftime("%Y-%m-%d %H:%M:%S"), user['id']))
            conn.commit()
        else:
            return "You already have an active loan!"
        conn.close()
        return redirect(url_for('dashboard'))

    conn.close()
    return render_template('loan.html', user=user)
@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if user['role'] != 'admin':
        conn.close()
        return "Unauthorized!"

    found_user = None

    if request.method == 'POST':
        search_username = request.form['username']
        found_user = conn.execute('SELECT * FROM users WHERE username = ?', (search_username,)).fetchone()

    conn.close()
    return render_template('admin.html', admin=user, found_user=found_user)

@app.route('/admin/add_money', methods=['POST'])
def add_money():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if admin['role'] != 'admin':
        conn.close()
        return "Unauthorized!"

    user_id = request.form['user_id']
    amount = float(request.form['amount'])

    conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, user_id))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_panel'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Deduct late loan penalty
@app.before_request
def check_loans():
    if 'user_id' in session:
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if user and user['loan_amount'] > 0 and user['loan_time']:
            loan_time = datetime.strptime(user['loan_time'], "%Y-%m-%d %H:%M:%S")
            now = datetime.now()
            if now > loan_time + timedelta(hours=1):
                minutes_late = (now - (loan_time + timedelta(hours=1))).total_seconds() // 600  # 10 mins
                penalty = minutes_late * 100
                if penalty > 0:
                    conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (penalty, user['id']))
                    conn.commit()
        conn.close()

if __name__ == "__main__":
    app.run(debug=True)
