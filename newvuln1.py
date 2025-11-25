"""
Ultimate SQL Injection Scanner Benchmark
========================================
This benchmark is designed to test advanced SQL injection detection capabilities.
It includes 50 challenging test cases across 10 categories.

Categories:
1. Second-Order SQL Injection (Advanced)
2. Type Confusion & Coercion Bypasses
3. Multi-Step Data Flow
4. Context-Dependent Validation Bypasses
5. ORM & Framework-Specific Patterns
6. Encoding & Obfuscation
7. Time-Based & Blind SQL Injection Patterns
8. Complex Control Flow
9. Lambda & Functional Programming
10. Real-World Framework Patterns

Expected Results: All 50 functions should be detected as vulnerable
"""

import sqlite3
import re
from flask import request, session
from typing import Dict, List, Any

# ============================================================================
# CATEGORY 1: ADVANCED SECOND-ORDER SQL INJECTION (10 cases)
# ============================================================================

def second_order_001():
    """Second-order via JSON storage"""
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Store tainted data in JSON column
    user_data = request.json.get('data')
    cur.execute('INSERT INTO cache (json_data) VALUES (?)', (user_data,))
    
    # Later retrieval - scanner must track JSON columns
    stored = cur.execute('SELECT json_data FROM cache').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{stored}'")  # VULN


def second_order_002():
    """Second-order via multiple table hops"""
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Store in table A
    tainted = request.args.get('input')
    cur.execute('INSERT INTO table_a (val) VALUES (?)', (tainted,))
    
    # Copy to table B
    cur.execute('INSERT INTO table_b SELECT val FROM table_a')
    
    # Read from table B - both tables should be poisoned
    data = cur.execute('SELECT val FROM table_b').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE id = {data}")  # VULN


def second_order_003():
    """Second-order via UPDATE statement"""
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Poison via UPDATE instead of INSERT
    evil = request.form.get('name')
    cur.execute('UPDATE settings SET value = ? WHERE key = "admin"', (evil,))
    
    # Read back
    admin = cur.execute('SELECT value FROM settings WHERE key = "admin"').fetchone()[0]
    cur.execute(f"DELETE FROM logs WHERE user = '{admin}'")  # VULN


def second_order_004():
    """Second-order via session storage"""
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Store in session (persisted to database)
    user_input = request.args.get('search')
    session['last_search'] = user_input
    cur.execute('INSERT INTO sessions (data) VALUES (?)', (session['last_search'],))
    
    # Retrieve from database later
    saved_search = cur.execute('SELECT data FROM sessions LIMIT 1').fetchone()[0]
    cur.execute(f"SELECT * FROM products WHERE name LIKE '%{saved_search}%'")  # VULN


def second_order_005():
    """Second-order via aggregate function"""
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Store tainted data
    comment = request.json.get('comment')
    cur.execute('INSERT INTO comments (text) VALUES (?)', (comment,))
    
    # Aggregate retrieval - scanner must track aggregates
    latest = cur.execute('SELECT MAX(text) FROM comments').fetchone()[0]
    cur.execute(f"INSERT INTO audit_log VALUES ('{latest}')")  # VULN


def second_order_006():
    """Second-order via UNION query"""
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Poison table
    payload = request.headers.get('X-Custom-Header')
    cur.execute('INSERT INTO temp_data (val) VALUES (?)', (payload,))
    
    # Read via UNION
    result = cur.execute('SELECT val FROM temp_data UNION SELECT val FROM temp_data').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE status = '{result}'")  # VULN


def second_order_007():
    """Second-order via subquery result"""
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Store malicious data
    user_role = request.cookies.get('role')
    cur.execute('INSERT INTO user_roles (role) VALUES (?)', (user_role,))
    
    # Use in subquery - result is tainted
    role_data = cur.execute('SELECT role FROM user_roles WHERE id = (SELECT MAX(id) FROM user_roles)').fetchone()[0]
    cur.execute(f"SELECT * FROM permissions WHERE role = '{role_data}'")  # VULN


def second_order_008():
    """Second-order via JOIN result"""
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Poison table A
    category = request.args.get('category')
    cur.execute('INSERT INTO categories (name) VALUES (?)', (category,))
    
    # JOIN with table B - result is tainted
    joined = cur.execute('SELECT c.name FROM categories c JOIN products p ON c.id = p.cat_id').fetchone()[0]
    cur.execute(f"SELECT * FROM items WHERE category = '{joined}'")  # VULN


def second_order_009():
    """Second-order via CASE expression"""
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Store tainted value
    status = request.form.get('status')
    cur.execute('INSERT INTO orders (status) VALUES (?)', (status,))
    
    # Retrieve via CASE - result is tainted
    mapped = cur.execute("SELECT CASE WHEN status = 'pending' THEN status ELSE 'done' END FROM orders").fetchone()[0]
    cur.execute(f"UPDATE logs SET status = '{mapped}'")  # VULN


def second_order_010():
    """Second-order via GROUP BY with HAVING"""
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Poison data
    tag = request.json.get('tag')
    cur.execute('INSERT INTO tags (name) VALUES (?)', (tag,))
    
    # Aggregate with GROUP BY
    popular_tag = cur.execute('SELECT name FROM tags GROUP BY name HAVING COUNT(*) > 1').fetchone()[0]
    cur.execute(f"SELECT * FROM posts WHERE tag = '{popular_tag}'")  # VULN


# ============================================================================
# CATEGORY 2: TYPE CONFUSION & COERCION BYPASSES (5 cases)
# ============================================================================

def type_confusion_001():
    """Type coercion bypass - int() doesn't sanitize for SQL context"""
    user_id = request.args.get('id')
    
    # Developer thinks int() makes it safe
    safe_id = int(user_id) if user_id.isdigit() else 0
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Still vulnerable - int is converted back to string in f-string
    cur.execute(f"SELECT * FROM users WHERE id = {safe_id} OR 1=1")  # VULN


def type_confusion_002():
    """Boolean coercion bypass"""
    admin_flag = request.args.get('admin')
    
    # Convert to bool
    is_admin = bool(admin_flag)
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Boolean in SQL context is still dangerous
    cur.execute(f"SELECT * FROM users WHERE admin = {is_admin}")  # VULN


def type_confusion_003():
    """Float coercion bypass"""
    price = request.form.get('price')
    
    # Developer thinks float() sanitizes
    safe_price = float(price)
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Still vulnerable
    cur.execute(f"SELECT * FROM products WHERE price < {safe_price}")  # VULN


def type_confusion_004():
    """List comprehension type confusion"""
    ids = request.args.getlist('ids')
    
    # Convert to ints
    safe_ids = [int(x) for x in ids if x.isdigit()]
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Join creates string - still vulnerable
    id_list = ','.join(map(str, safe_ids))
    cur.execute(f"SELECT * FROM users WHERE id IN ({id_list})")  # VULN


def type_confusion_005():
    """Tuple unpacking confusion"""
    data = request.json.get('coords')
    
    # Unpack tuple
    x, y = data.split(',')
    x = int(x)
    y = int(y)
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Coordinates in SQL
    cur.execute(f"SELECT * FROM locations WHERE x = {x} AND y = {y}")  # VULN


# ============================================================================
# CATEGORY 3: MULTI-STEP DATA FLOW (5 cases)
# ============================================================================

def multi_step_001():
    """Five-step taint propagation"""
    step1 = request.args.get('input')
    step2 = step1.upper()
    step3 = step2.strip()
    step4 = step3.replace(' ', '_')
    step5 = f"user_{step4}"
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE username = '{step5}'")  # VULN


def multi_step_002():
    """Taint through dictionary"""
    user_data = {
        'name': request.form.get('name'),
        'email': request.form.get('email')
    }
    
    # Extract from dict
    username = user_data['name']
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{username}'")  # VULN


def multi_step_003():
    """Taint through list operations"""
    parts = []
    parts.append(request.args.get('first'))
    parts.append(request.args.get('last'))
    
    # Join list
    full_name = ' '.join(parts)
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{full_name}'")  # VULN


def multi_step_004():
    """Taint through set operations"""
    tags = set()
    tags.add(request.json.get('tag1'))
    tags.add(request.json.get('tag2'))
    
    # Pop from set
    selected_tag = tags.pop()
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM posts WHERE tag = '{selected_tag}'")  # VULN


def multi_step_005():
    """Taint through class attribute"""
    class UserData:
        def __init__(self):
            self.username = request.args.get('user')
    
    user = UserData()
    name = user.username
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE username = '{name}'")  # VULN


# ============================================================================
# CATEGORY 4: CONTEXT-DEPENDENT VALIDATION BYPASSES (5 cases)
# ============================================================================

def validation_bypass_001():
    """Validation in wrong branch"""
    user_id = request.args.get('id')
    
    if request.method == 'POST':
        # Validation only in POST
        if not user_id.isdigit():
            return "Invalid"
    
    # GET requests bypass validation
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")  # VULN


def validation_bypass_002():
    """Incomplete whitelist"""
    table_name = request.args.get('table')
    
    # Whitelist check
    allowed = ['users', 'products', 'orders']
    
    if table_name in allowed:
        # Seems safe, but table_name can still contain SQL
        conn = sqlite3.connect('db.sqlite')
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM {table_name} WHERE id = 1")  # VULN (if table_name = "users WHERE 1=1 --")


def validation_bypass_003():
    """Validation after taint propagation"""
    original = request.form.get('input')
    modified = original + "_suffix"
    
    # Validate original, but use modified
    if original.isalnum():
        conn = sqlite3.connect('db.sqlite')
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM data WHERE key = '{modified}'")  # VULN


def validation_bypass_004():
    """Case-sensitive validation bypass"""
    command = request.args.get('cmd')
    
    # Check for SQL keywords (case-sensitive)
    if 'DROP' in command or 'DELETE' in command:
        return "Blocked"
    
    # Lowercase bypass
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"{command}")  # VULN (if command = "drop table users")


def validation_bypass_005():
    """Length-based validation bypass"""
    search = request.args.get('q')
    
    # Only validate if short
    if len(search) < 10:
        if not search.isalnum():
            return "Invalid"
    
    # Long inputs bypass validation
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM products WHERE name LIKE '%{search}%'")  # VULN


# ============================================================================
# CATEGORY 5: ORM & FRAMEWORK-SPECIFIC PATTERNS (5 cases)
# ============================================================================

def orm_bypass_001():
    """SQLAlchemy text() with bind params - but wrong usage"""
    from sqlalchemy import text
    
    user_id = request.args.get('id')
    
    # Looks safe but isn't
    query = text(f"SELECT * FROM users WHERE id = {user_id}")  # VULN
    # Should be: text("SELECT * FROM users WHERE id = :id").bindparams(id=user_id)


def orm_bypass_002():
    """Django raw() with string formatting"""
    from django.db import connection
    
    username = request.POST.get('username')
    
    # Django raw() with f-string
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM auth_user WHERE username = '{username}'")  # VULN


def orm_bypass_003():
    """SQLAlchemy literal_column abuse"""
    from sqlalchemy import literal_column
    
    col_name = request.args.get('sort')
    
    # Dynamic column name
    query = f"SELECT * FROM users ORDER BY {literal_column(col_name)}"  # VULN


def orm_bypass_004():
    """Peewee raw query"""
    from peewee import Database
    
    db = Database(None)
    search_term = request.args.get('search')
    
    # Peewee raw query
    db.execute_sql(f"SELECT * FROM products WHERE name LIKE '%{search_term}%'")  # VULN


def orm_bypass_005():
    """SQLAlchemy execute with TextClause"""
    from sqlalchemy import create_engine
    
    engine = create_engine('sqlite:///db.sqlite')
    user_role = request.args.get('role')
    
    # TextClause with f-string
    with engine.connect() as conn:
        conn.execute(f"SELECT * FROM users WHERE role = '{user_role}'")  # VULN


# ============================================================================
# CATEGORY 6: ENCODING & OBFUSCATION (5 cases)
# ============================================================================

def encoding_001():
    """Base64 decode doesn't sanitize"""
    import base64
    
    encoded = request.args.get('data')
    decoded = base64.b64decode(encoded).decode()
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE token = '{decoded}'")  # VULN


def encoding_002():
    """URL decode doesn't sanitize"""
    from urllib.parse import unquote
    
    encoded_name = request.args.get('name')
    name = unquote(encoded_name)
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")  # VULN


def encoding_003():
    """JSON parse doesn't sanitize"""
    import json
    
    json_data = request.data.decode()
    parsed = json.loads(json_data)
    username = parsed['username']
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE username = '{username}'")  # VULN


def encoding_004():
    """Hex decode doesn't sanitize"""
    hex_input = request.args.get('hex')
    decoded = bytes.fromhex(hex_input).decode()
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM data WHERE value = '{decoded}'")  # VULN


def encoding_005():
    """HTML unescape doesn't sanitize"""
    import html
    
    escaped = request.form.get('comment')
    unescaped = html.unescape(escaped)
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"INSERT INTO comments (text) VALUES ('{unescaped}')")  # VULN


# ============================================================================
# CATEGORY 7: TIME-BASED & BLIND SQL INJECTION PATTERNS (5 cases)
# ============================================================================

def blind_sqli_001():
    """Boolean-based blind SQLi"""
    user_id = request.args.get('id')
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Boolean condition in WHERE
    result = cur.execute(f"SELECT * FROM users WHERE id = {user_id} AND 1=1").fetchone()  # VULN
    
    if result:
        return "User exists"
    return "Not found"


def blind_sqli_002():
    """Time-based blind SQLi pattern"""
    username = request.args.get('user')
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Attacker can inject: admin' AND (SELECT CASE WHEN (1=1) THEN sleep(5) ELSE 0 END)--
    cur.execute(f"SELECT * FROM users WHERE username = '{username}'")  # VULN


def blind_sqli_003():
    """Error-based blind SQLi"""
    product_id = request.args.get('id')
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    try:
        # Attacker can cause errors to leak info
        cur.execute(f"SELECT * FROM products WHERE id = {product_id}")  # VULN
    except Exception as e:
        return str(e)  # Leaks SQL error


def blind_sqli_004():
    """Content-based blind SQLi"""
    search = request.args.get('q')
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Response differs based on query result
    results = cur.execute(f"SELECT * FROM products WHERE name LIKE '%{search}%'").fetchall()  # VULN
    
    if len(results) > 0:
        return "Found"
    return "Not found"


def blind_sqli_005():
    """Union-based blind SQLi"""
    order_id = request.args.get('order')
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    
    # Attacker can UNION to extract data
    cur.execute(f"SELECT order_id, total FROM orders WHERE order_id = {order_id}")  # VULN


# ============================================================================
# CATEGORY 8: COMPLEX CONTROL FLOW (5 cases)
# ============================================================================

def control_flow_001():
    """Taint through nested if-else"""
    user_input = request.args.get('input')
    
    if len(user_input) > 10:
        if user_input.startswith('admin'):
            value = user_input
        else:
            value = user_input.lower()
    else:
        value = user_input.upper()
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{value}'")  # VULN


def control_flow_002():
    """Taint through try-except"""
    raw_id = request.args.get('id')
    
    try:
        user_id = int(raw_id)
    except ValueError:
        user_id = raw_id  # Falls back to string
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")  # VULN


def control_flow_003():
    """Taint through while loop"""
    base = request.form.get('base')
    result = base
    
    count = 0
    while count < 3:
        result = result + "_"
        count += 1
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM data WHERE key = '{result}'")  # VULN


def control_flow_004():
    """Taint through for-else"""
    search_terms = request.args.getlist('terms')
    
    for term in search_terms:
        if term == 'admin':
            break
    else:
        term = search_terms[0] if search_terms else ''
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")  # VULN


def control_flow_005():
    """Taint through match-case (Python 3.10+)"""
    action = request.args.get('action')
    
    match action:
        case 'read':
            query_part = action
        case 'write':
            query_part = action
        case _:
            query_part = action
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM logs WHERE action = '{query_part}'")  # VULN


# ============================================================================
# CATEGORY 9: LAMBDA & FUNCTIONAL PROGRAMMING (5 cases)
# ============================================================================

def lambda_001():
    """Taint through lambda"""
    user_input = request.args.get('name')
    
    # Lambda transformation
    transform = lambda x: x.strip().upper()
    processed = transform(user_input)
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{processed}'")  # VULN


def lambda_002():
    """Taint through map()"""
    inputs = request.args.getlist('ids')
    
    # Map to uppercase
    processed = list(map(lambda x: x.upper(), inputs))
    first_id = processed[0] if processed else ''
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = '{first_id}'")  # VULN


def lambda_003():
    """Taint through filter()"""
    tags = request.json.get('tags', [])
    
    # Filter non-empty
    valid_tags = list(filter(lambda x: len(x) > 0, tags))
    selected = valid_tags[0] if valid_tags else ''
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM posts WHERE tag = '{selected}'")  # VULN


def lambda_004():
    """Taint through reduce()"""
    from functools import reduce
    
    parts = request.args.getlist('parts')
    
    # Reduce to single string
    combined = reduce(lambda a, b: a + '_' + b, parts, '')
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM data WHERE key = '{combined}'")  # VULN


def lambda_005():
    """Taint through sorted() with key"""
    names = request.json.get('names', [])
    
    # Sort by length
    sorted_names = sorted(names, key=lambda x: len(x))
    first_name = sorted_names[0] if sorted_names else ''
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{first_name}'")  # VULN


# ============================================================================
# CATEGORY 10: REAL-WORLD FRAMEWORK PATTERNS (5 cases)
# ============================================================================

def framework_001():
    """Flask session-based SQLi"""
    # Session data can be manipulated
    user_role = session.get('role', 'user')
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM permissions WHERE role = '{user_role}'")  # VULN


def framework_002():
    """Flask g object SQLi"""
    from flask import g
    
    # g object stores request-scoped data
    g.username = request.args.get('user')
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE username = '{g.username}'")  # VULN


def framework_003():
    """Flask before_request taint"""
    from flask import g
    
    # Assume this runs in @app.before_request
    g.search_query = request.args.get('q', '')
    
    # Later in view function
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM products WHERE name LIKE '%{g.search_query}%'")  # VULN


def framework_004():
    """Environment variable SQLi"""
    import os
    
    # Environment variables can be tainted in some contexts
    db_table = os.environ.get('TABLE_NAME', 'users')
    user_id = request.args.get('id')
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {db_table} WHERE id = {user_id}")  # VULN


def framework_005():
    """Werkzeug MultiDict SQLi"""
    from werkzeug.datastructures import MultiDict
    
    # MultiDict from request
    params = MultiDict(request.args)
    search_term = params.get('search')
    
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM products WHERE name = '{search_term}'")  # VULN


# ============================================================================
# BENCHMARK RUNNER
# ============================================================================

if __name__ == '__main__':
    print("SQL Injection Scanner Benchmark")
    print("=" * 60)
    print("This file contains 50 vulnerable functions across 10 categories")
    print("Expected: All 50 should be detected as vulnerable")
    print()
    print("Categories:")
    print("  1. Advanced Second-Order SQL Injection (10)")
    print("  2. Type Confusion & Coercion Bypasses (5)")
    print("  3. Multi-Step Data Flow (5)")
    print("  4. Context-Dependent Validation Bypasses (5)")
    print("  5. ORM & Framework-Specific Patterns (5)")
    print("  6. Encoding & Obfuscation (5)")
    print("  7. Time-Based & Blind SQL Injection (5)")
    print("  8. Complex Control Flow (5)")
    print("  9. Lambda & Functional Programming (5)")
    print(" 10. Real-World Framework Patterns (5)")
    print()
    print("Run your scanner against this file to test detection capabilities!")
