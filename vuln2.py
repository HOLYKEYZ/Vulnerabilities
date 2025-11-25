"""
User Management API - Internal Tool v2.3
Author: Security Team
Last Modified: 2024-03-15

TODO: Migrate to ORM in Q3
"""

from flask import Flask, request, jsonify, session
import sqlite3
import hashlib
import json
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = "prod_secret_key_2024"

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, 
                  email TEXT, role TEXT, created_at TEXT, api_key TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT, 
                  timestamp TEXT, ip_address TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS products
                 (id INTEGER PRIMARY KEY, name TEXT, price REAL, 
                  category TEXT, stock INTEGER)''')
    conn.commit()
    conn.close()

init_db()

# Helper function - looks safe but isn't
def sanitize_input(data):
    """Basic input sanitization"""
    # Remove obvious SQL keywords (incomplete list - false sense of security)
    dangerous = ['DROP', 'DELETE', 'INSERT', 'UPDATE']
    for word in dangerous:
        data = data.replace(word, '')
    return data

# Vulnerability 1: Classic SQL injection in login
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    
    # Hash password for "security"
    hashed_pw = hashlib.md5(password.encode()).hexdigest()
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Vulnerable: Direct string concatenation
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed_pw}'"
    
    try:
        c.execute(query)
        user = c.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['role'] = user[4]
            return jsonify({"status": "success", "role": user[4]})
        return jsonify({"status": "failed"}), 401
    except Exception as e:
        return jsonify({"error": "Database error"}), 500

# Vulnerability 2: Second-order SQL injection
@app.route('/api/user/profile', methods=['GET'])
def get_profile():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = request.args.get('id', session['user_id'])
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Looks parameterized but user_id is from session which could be manipulated
    c.execute(f"SELECT username, email, role FROM users WHERE id={user_id}")
    user = c.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            "username": user[0],
            "email": user[1],
            "role": user[2]
        })
    return jsonify({"error": "User not found"}), 404

# Vulnerability 3: SQL injection in ORDER BY clause
@app.route('/api/users/search', methods=['GET'])
def search_users():
    search_term = request.args.get('q', '')
    sort_by = request.args.get('sort', 'username')
    order = request.args.get('order', 'ASC')
    
    # "Sanitized" search term
    search_term = sanitize_input(search_term)
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Vulnerable: ORDER BY can't be parameterized easily, often left as string concat
    query = f"""SELECT username, email, role, created_at 
                FROM users 
                WHERE username LIKE '%{search_term}%' 
                ORDER BY {sort_by} {order}"""
    
    try:
        c.execute(query)
        results = c.fetchall()
        conn.close()
        
        return jsonify({
            "results": [
                {"username": r[0], "email": r[1], "role": r[2], "created": r[3]}
                for r in results
            ]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Vulnerability 4: SQL injection via JSON field
@app.route('/api/products/filter', methods=['POST'])
def filter_products():
    filters = request.json.get('filters', {})
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Build dynamic query from JSON - common pattern in modern APIs
    conditions = []
    for key, value in filters.items():
        # Regex check gives false sense of security
        if re.match(r'^[a-zA-Z_]+$', key):
            conditions.append(f"{key}='{value}'")
    
    where_clause = " AND ".join(conditions) if conditions else "1=1"
    query = f"SELECT * FROM products WHERE {where_clause}"
    
    try:
        c.execute(query)
        products = c.fetchall()
        conn.close()
        return jsonify({"products": products})
    except Exception as e:
        return jsonify({"error": "Query failed"}), 500

# Vulnerability 5: SQL injection in LIMIT clause
@app.route('/api/logs', methods=['GET'])
def get_logs():
    if session.get('role') != 'admin':
        return jsonify({"error": "Forbidden"}), 403
    
    page = request.args.get('page', '1')
    per_page = request.args.get('per_page', '10')
    
    # Basic validation - but not enough
    if not page.isdigit() or not per_page.isdigit():
        return jsonify({"error": "Invalid pagination"}), 400
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    offset = (int(page) - 1) * int(per_page)
    
    # Vulnerable: LIMIT clause injection (less common but possible)
    query = f"SELECT * FROM logs LIMIT {per_page} OFFSET {offset}"
    
    c.execute(query)
    logs = c.fetchall()
    conn.close()
    
    return jsonify({"logs": logs, "page": page})

# Vulnerability 6: Blind SQL injection via User-Agent logging
@app.route('/api/track', methods=['POST'])
def track_action():
    action = request.json.get('action', 'page_view')
    user_agent = request.headers.get('User-Agent', 'Unknown')
    ip = request.remote_addr
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Vulnerable: Logging user-controlled header without sanitization
    query = f"""INSERT INTO logs (user_id, action, timestamp, ip_address) 
                VALUES (
                    {session.get('user_id', 0)}, 
                    '{action} - {user_agent}', 
                    '{datetime.now().isoformat()}', 
                    '{ip}'
                )"""
    
    try:
        c.execute(query)
        conn.commit()
        conn.close()
        return jsonify({"status": "tracked"})
    except Exception as e:
        return jsonify({"error": "Tracking failed"}), 500

# Vulnerability 7: SQL injection via LIKE pattern
@app.route('/api/autocomplete', methods=['GET'])
def autocomplete():
    prefix = request.args.get('prefix', '')
    field = request.args.get('field', 'username')
    
    # Whitelist check - but incomplete
    allowed_fields = ['username', 'email']
    if field not in allowed_fields:
        field = 'username'
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Vulnerable: LIKE pattern not properly escaped
    query = f"SELECT DISTINCT {field} FROM users WHERE {field} LIKE '{prefix}%' LIMIT 10"
    
    try:
        c.execute(query)
        results = [row[0] for row in c.fetchall()]
        conn.close()
        return jsonify({"suggestions": results})
    except Exception as e:
        return jsonify({"error": "Query error"}), 500

# Vulnerability 8: SQL injection in subquery
@app.route('/api/stats/user', methods=['GET'])
def user_stats():
    username = request.args.get('username', '')
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Complex query with subquery - easy to miss vulnerability
    query = f"""
        SELECT 
            u.username,
            u.role,
            (SELECT COUNT(*) FROM logs WHERE user_id = u.id) as action_count,
            (SELECT action FROM logs WHERE user_id = u.id 
             AND action LIKE '%{username}%' ORDER BY timestamp DESC LIMIT 1) as last_action
        FROM users u
        WHERE u.username = '{username}'
    """
    
    try:
        c.execute(query)
        result = c.fetchone()
        conn.close()
        
        if result:
            return jsonify({
                "username": result[0],
                "role": result[1],
                "action_count": result[2],
                "last_action": result[3]
            })
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)