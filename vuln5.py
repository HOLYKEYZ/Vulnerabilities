#!/usr/bin/env python3
"""
Test validation tracking - comprehensive test cases
"""

from flask import Flask, abort, request, session
import sqlite3

app = Flask(__name__)
cursor = sqlite3.connect('db.sqlite').cursor()

# ============================================================================
# VALIDATION FUNCTIONS (These should be recognized as strong validation)
# ============================================================================

def validate_identifier(name):
    """Strong validation - whitelist"""
    allowed = ['id', 'name', 'email', 'created_at', 'updated_at']
    if name not in allowed:
        raise ValueError(f"Invalid column: {name}")
    return name

def validate_table(table_name):
    """Strong validation - whitelist"""
    allowed = ['users', 'posts', 'comments']
    if table_name not in allowed:
        raise ValueError(f"Invalid table: {table_name}")
    return table_name

def validate_date(date_str):
    """Medium validation - regex"""
    import re
    if not re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
        raise ValueError("Invalid date format")
    return date_str

def sanitize_sql_input(value):
    """Weak sanitization - should still be flagged"""
    return value.replace("'", "")

# ============================================================================
# TEST CASE 1: All variables validated (should NOT be flagged)
# ============================================================================

@app.route('/test1_all_validated')
def test1_all_validated():
    """Should NOT be flagged - all variables are strongly validated"""
    column = validate_identifier(request.args.get('column', 'id'))
    table = validate_table(request.args.get('table', 'users'))
    
    query = f"SELECT {column} FROM {table}"
    cursor = sqlite3.connect('db.sqlite').cursor()
    cursor.execute(query)
    return "OK"

# ============================================================================
# TEST CASE 2: Mixed validated and unvalidated (should flag ONLY unvalidated)
# ============================================================================

@app.route('/test2_mixed')
def test2_mixed():
    """Should be flagged - date is not validated"""
    column = validate_identifier(request.args.get('column', 'id'))  # ✅ Validated
    date_from = request.args.get('date_from', '2024-01-01')        # ❌ NOT validated
    date_to = request.args.get('date_to', '2024-12-31')            # ❌ NOT validated
    
    query = f"""SELECT {column}, COUNT(*) 
                FROM transactions 
                WHERE date BETWEEN '{date_from}' AND '{date_to}'
                GROUP BY {column}"""
    
    cursor = sqlite3.connect('db.sqlite').cursor()
    cursor.execute(query)
    return "OK"

# ============================================================================
# TEST CASE 3: Nothing validated (should be flagged)
# ============================================================================

@app.route('/test3_unvalidated')
def test3_unvalidated():
    """Should be flagged - nothing validated"""
    column = request.args.get('column', 'id')  # ❌ NOT validated
    
    query = f"SELECT {column} FROM users"
    cursor = sqlite3.connect('db.sqlite').cursor()
    cursor.execute(query)
    return "OK"

# ============================================================================
# TEST CASE 4: Weak validation (should still be flagged)
# ============================================================================

@app.route('/test4_weak_validation')
def test4_weak_validation():
    """Should be flagged - weak sanitization"""
    user_input = request.args.get('name', '')
    clean_input = sanitize_sql_input(user_input)  # ❌ Weak validation
    
    query = f"SELECT * FROM users WHERE name = '{clean_input}'"
    cursor = sqlite3.connect('db.sqlite').cursor()
    cursor.execute(query)
    return "OK"

# ============================================================================
# TEST CASE 5: Validated with medium strength (should NOT be flagged)
# ============================================================================

@app.route('/test5_medium_validation')
def test5_medium_validation():
    """Should NOT be flagged - date is validated with regex"""
    date = request.args.get('date', '2024-01-01')
    validated_date = validate_date(date)  # ✅ Medium validation (regex)
    
    query = f"SELECT * FROM logs WHERE date = '{validated_date}'"
    cursor = sqlite3.connect('db.sqlite').cursor()
    cursor.execute(query)
    return "OK"

# ============================================================================
# TEST CASE 6: Multiple validated, one unvalidated (should flag the one)
# ============================================================================

@app.route('/test6_mostly_validated')
def test6_mostly_validated():
    """Should flag only the unvalidated variable"""
    column1 = validate_identifier(request.args.get('col1', 'id'))      # ✅ Validated
    column2 = validate_identifier(request.args.get('col2', 'name'))    # ✅ Validated
    table = validate_table(request.args.get('table', 'users'))         # ✅ Validated
    search = request.args.get('search', '')                            # ❌ NOT validated
    
    query = f"SELECT {column1}, {column2} FROM {table} WHERE name LIKE '%{search}%'"
    cursor = sqlite3.connect('db.sqlite').cursor()
    cursor.execute(query)
    return "OK"

# ============================================================================
# TEST CASE 7: Session data without validation (should be flagged)
# ============================================================================

@app.route('/test7_session_unvalidated')
def test7_session_unvalidated():
    """Should be flagged - session data without validation"""
    user_id = session.get('user_id', 1)  # ❌ Session data, not validated
    
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = sqlite3.connect('db.sqlite').cursor()
    cursor.execute(query)
    return "OK"

# ============================================================================
# TEST CASE 8: HTTP header without validation (should be flagged as CRITICAL)
# ============================================================================

@app.route('/test8_header_unvalidated')
def test8_header_unvalidated():
    """Should be flagged as CRITICAL - HTTP header"""
    user_agent = request.headers.get('User-Agent', '')  # ❌ HTTP header
    
    query = f"INSERT INTO analytics (user_agent) VALUES ('{user_agent}')"
    cursor = sqlite3.connect('db.sqlite').cursor()
    cursor.execute(query)
    return "OK"

# ============================================================================
# TEST CASE 9: Parameterized query (should NOT be flagged)
# ============================================================================

@app.route('/test9_parameterized')
def test9_parameterized():
    """Should NOT be flagged - uses parameterized query"""
    user_id = request.args.get('id', 1)  # Even though not validated...
    
    query = "SELECT * FROM users WHERE id = ?"  # ✅ Parameterized
    cursor = sqlite3.connect('db.sqlite').cursor()
    cursor.execute(query, (user_id,))  # ✅ Safe
    return "OK"

# ============================================================================
# TEST CASE 10: Deceptive naming (should be flagged with warning)
# ============================================================================

@app.route('/test10_deceptive_naming')
def test10_deceptive_naming():
    """Should be flagged - deceptive variable name"""
    safe_input = request.args.get('input', '')  # ❌ Name suggests safety but isn't validated
    
    query = f"SELECT * FROM users WHERE name = '{safe_input}'"
    cursor = sqlite3.connect('db.sqlite').cursor()
    cursor.execute(query)
    return "OK"


@app.route('/safe1')
def safe1():
    user_id = request.args.get('id')
    query = "SELECT * FROM users WHERE id = ?"
    cursor = sqlite3.connect('db.sqlite').cursor()
    cursor.execute(query, (user_id,))  # ✅ Parameterized - SAFE
    # Expected: No finding

@app.route('/safe2')
def safe2():
    user_id = request.args.get('id')
    if not user_id.isdigit():
        abort(400)
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)  # ✅ Validated - SAFE
    # Expected: No finding (if you track .isdigit() validation)

@app.route('/vuln11')
def vuln11():
    data = request.args.get('data')
    temp = data  # Indirect assignment
    another = temp  # Another hop
    query = f"SELECT * FROM users WHERE name = '{another}'"
    cursor.execute(query)
    # Expected: Should detect (taint propagates through assignments)


if __name__ == '__main__':
    app.run(debug=True)
