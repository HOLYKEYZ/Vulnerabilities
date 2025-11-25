from flask import Flask, request
import sqlite3

app = Flask(__name__)

# ========== TEST 1: Whitelist Validation (Should NOT Report) ==========
@app.route('/test1')
def test_whitelist_safe():
    """Path-sensitive: validated in then branch"""
    user_id = request.args.get('id')
    
    if user_id in ['1', '2', '3']:  # Whitelist validation
        conn = sqlite3.connect('db.sqlite')
        cursor = conn.cursor()
        # ✅ Should be SAFE (validated)
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)
    
    return "OK"


# ========== TEST 2: No Validation (Should Report) ==========
@app.route('/test2')
def test_no_validation():
    """No validation - should report"""
    user_id = request.args.get('id')
    
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    # ❌ Should be UNSAFE (not validated)
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    return "OK"


# ========== TEST 3: Else Branch Unsafe (Should Report in Else Only) ==========
@app.route('/test3')
def test_else_branch():
    """Validation only in then branch"""
    user_id = request.args.get('id')
    
    if user_id in ['1', '2', '3']:
        conn = sqlite3.connect('db.sqlite')
        cursor = conn.cursor()
        # ✅ SAFE in then branch
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)
    else:
        conn = sqlite3.connect('db.sqlite')
        cursor = conn.cursor()
        # ❌ UNSAFE in else branch
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)
    
    return "OK"


# ========== TEST 4: Validation Function (Should NOT Report) ==========
@app.route('/test4')
def test_validation_function():
    """Using validation function"""
    user_id = request.args.get('id')
    validated_id = validate_number(user_id)  # Assume this is a validation function
    
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    # ✅ Should be SAFE (validated by function)
    query = f"SELECT * FROM users WHERE id = {validated_id}"
    cursor.execute(query)
    
    return "OK"

def validate_number(value):
    """Medium-strength validation function"""
    if value and value.isdigit():
        return int(value)
    raise ValueError("Invalid number")


# ========== TEST 5: Parameterized Query (Should NOT Report) ==========
@app.route('/test5')
def test_parameterized():
    """Parameterized query - safe"""
    user_id = request.args.get('id')  # Tainted
    
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    # ✅ Should be SAFE (parameterized)
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    
    return "OK"


# ========== TEST 6: HTTP Header Injection (Should Report as CRITICAL) ==========
@app.route('/test6')
def test_header_injection():
    """HTTP header in SQL - critical"""
    user_agent = request.headers.get('User-Agent')
    
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    # ❌ Should be CRITICAL (HTTP header)
    query = f"INSERT INTO analytics (user_agent) VALUES ('{user_agent}')"
    cursor.execute(query)
    
    return "OK"


# ========== TEST 7: Weak Sanitization (Should Report as CRITICAL) ==========
@app.route('/test7')
def test_weak_sanitization():
    """Weak sanitization - bypassable"""
    user_input = request.args.get('name')
    safe_input = user_input.replace("'", "")  # Weak sanitization
    
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    # ❌ Should be CRITICAL (weak sanitization)
    query = f"SELECT * FROM users WHERE name = '{safe_input}'"
    cursor.execute(query)
    
    return "OK"
