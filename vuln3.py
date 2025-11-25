import sqlite3
from flask import request

def vulnerable_1():
    """Direct f-string injection"""
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    user_input = request.args.get('id')
    
    # This should trigger PY-SQLI-001 (tainted data)
    query = f"SELECT * FROM users WHERE id = {user_input}"
    cursor.execute(query)
    
    return cursor.fetchall()

def vulnerable_2():
    """String concatenation"""
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    name = request.form.get('name')
    
    # This should trigger PY-SQLI-003 (string concatenation)
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)
    
    return cursor.fetchall()

def vulnerable_3():
    """F-string in execute"""
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    user_id = request.json.get('user_id')
    
    # This should trigger PY-SQLI-002 (f-string)
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")

def vulnerable_4():
    """Tainted variable flow"""
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    
    # Taint flows through variable
    search_term = request.args.get('search')
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    
    # This should trigger PY-SQLI-001
    cursor.execute(query)

def vulnerable_5():
    """String formatting"""
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    table = request.args.get('table')
    
    # This should trigger PY-SQLI-003 (% formatting)
    query = "SELECT * FROM %s" % table
    cursor.execute(query)

def safe_example():
    """This is safe - parameterized query"""
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    user_input = request.args.get('id')
    
    # Safe: using parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
    
    return cursor.fetchall()
