#!/usr/bin/env python3
"""Minimal test for SQL injection scanner"""

import sqlite3
from flask import request

# Setup database connection (global for simplicity)
conn = sqlite3.connect('test.db')
cursor = conn.cursor()

# Test 1: VULNERABLE - Should report
def test_vulnerable():
    user_id = request.args.get('id')
    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")

# Test 2: SAFE - Should NOT report
def test_safe():
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))

# Test 3: VULNERABLE - Should report
def test_alias():
    user_input = request.args.get('name')
    safe_name = user_input
    cursor.execute(f"SELECT * FROM users WHERE name='{safe_name}'")

# Test 4: SAFE - Should NOT report
def test_whitelist():
    column = request.args.get('sort')
    if column in ['id', 'name', 'email']:
        cursor.execute(f"SELECT * FROM users ORDER BY {column}")
