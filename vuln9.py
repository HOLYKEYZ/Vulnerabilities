import sqlite3
import time
from flask import request, session
import re

# ============================================================================
# BASIC VULNERABILITIES (Should be detected)
# ============================================================================

def vulnerable_1():
    """F-string injection - basic"""
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    uid = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return cursor.fetchall()

def vulnerable_2():
    """String concatenation - basic"""
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    conn = sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_3():
    """% formatting - basic"""
    table = request.args.get("table")
    query = "SELECT * FROM %s" % table  # SQLi
    sqlite3.connect('db.sqlite').cursor().execute(query)

# ============================================================================
# INTERMEDIATE OBFUSCATION (Testing detection depth)
# ============================================================================

def vulnerable_4():
    """Multi-step variable assignment"""
    user_input = request.args.get("search")
    temp = user_input
    search_term = temp
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_5():
    """Hidden in function call"""
    def build_query(term):
        return f"SELECT * FROM users WHERE username = '{term}'"
    
    username = request.args.get("user")
    sql = build_query(username)
    sqlite3.connect('db.sqlite').cursor().execute(sql)

def vulnerable_6():
    """Deceptive variable naming"""
    safe_input = request.args.get("id")  # Not actually safe!
    validated_id = safe_input  # No validation actually happens
    clean_id = validated_id  # Still tainted
    query = f"SELECT * FROM users WHERE id = {clean_id}"
    sqlite3.connect('db.sqlite').cursor().execute(query)

# ============================================================================
# ADVANCED OBFUSCATION (Challenging the scanner)
# ============================================================================

def vulnerable_7():
    """Weak sanitization bypass - single quote removal"""
    user_input = request.args.get("name")
    # Attacker can use: SELSELECTECT to bypass
    sanitized = user_input.replace("'", "")
    query = f"SELECT * FROM users WHERE name = '{sanitized}'"
    sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_8():
    """Weak sanitization - quote doubling"""
    user_input = request.args.get("comment")
    # Quote doubling is NOT secure
    escaped = user_input.replace("'", "''")
    query = f"INSERT INTO comments (text) VALUES ('{escaped}')"
    sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_9():
    """List join vulnerability"""
    filters = []
    if request.args.get("name"):
        filters.append(f"name = '{request.args.get('name')}'")
    if request.args.get("email"):
        filters.append(f"email = '{request.args.get('email')}'")
    
    where_clause = " AND ".join(filters)
    query = f"SELECT * FROM users WHERE {where_clause}"
    sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_10():
    """Dictionary-based query building"""
    params = request.args.to_dict()
    conditions = []
    for key, value in params.items():
        conditions.append(f"{key} = '{value}'")
    
    where = " AND ".join(conditions)
    query = f"SELECT * FROM users WHERE {where}"
    sqlite3.connect('db.sqlite').cursor().execute(query)

# ============================================================================
# EXPERT LEVEL - COMPLEX DATA FLOW (Real challenge)
# ============================================================================

def vulnerable_11():
    """Session-based SQL injection"""
    # User ID stored in session (can be manipulated via session fixation)
    user_id = session.get("user_id")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_12():
    """HTTP Header injection"""
    user_agent = request.headers.get("User-Agent")
    query = f"INSERT INTO analytics (user_agent) VALUES ('{user_agent}')"
    sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_13():
    """Second-order SQL injection"""
    # Step 1: Store tainted data
    username = request.args.get("username")
    query1 = f"INSERT INTO users (username) VALUES ('{username}')"
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute(query1)
    
    # Step 2: Retrieve and use in another query (second-order)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id = 1")
    stored_username = cursor.fetchone()[0]
    
    query2 = f"SELECT * FROM profiles WHERE username = '{stored_username}'"
    cursor.execute(query2)

def vulnerable_14():
    """Conditional query building"""
    base_query = "SELECT * FROM users"
    user_filter = request.args.get("filter")
    
    if user_filter:
        # Vulnerable: filter not validated
        query = base_query + f" WHERE status = '{user_filter}'"
    else:
        query = base_query
    
    sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_15():
    """Format string with multiple variables"""
    first_name = request.args.get("first")
    last_name = request.args.get("last")
    query = "SELECT * FROM users WHERE first_name = '{}' AND last_name = '{}'".format(
        first_name, last_name
    )
    sqlite3.connect('db.sqlite').cursor().execute(query)

# ============================================================================
# MASTER LEVEL - STEALTH TECHNIQUES (Ultimate challenge)
# ============================================================================

def vulnerable_16():
    """Hidden in complex control flow"""
    search = request.args.get("q")
    
    if search:
        if len(search) > 0:
            if search.isalnum():
                # Looks safe but isalnum() check is AFTER query building
                query = f"SELECT * FROM products WHERE name = '{search}'"
                sqlite3.connect('db.sqlite').cursor().execute(query)
            else:
                # Vulnerable path - no validation
                filt = search
                query = "SELECT * FROM products WHERE description LIKE '%" + filt + "%'"
                sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_17():
    """Obfuscated through lambda"""
    get_param = lambda key: request.args.get(key)
    build_sql = lambda table, col, val: f"SELECT * FROM {table} WHERE {col} = '{val}'"
    
    table_name = get_param("table")
    column = get_param("column")
    value = get_param("value")
    
    query = build_sql(table_name, column, value)
    sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_18():
    """Nested function with closure"""
    def create_query_builder(table):
        def build(condition):
            return f"SELECT * FROM {table} WHERE {condition}"
        return build
    
    user_table = request.args.get("table")
    query_builder = create_query_builder(user_table)
    
    user_condition = request.args.get("condition")
    final_query = query_builder(user_condition)
    
    sqlite3.connect('db.sqlite').cursor().execute(final_query)

def vulnerable_19():
    """Weak regex validation"""
    date_param = request.args.get("date")
    
    # Weak validation - only checks format, not content
    if re.match(r"\d{4}-\d{2}-\d{2}", date_param):
        # Still vulnerable! Attacker can append: 2024-01-01' OR '1'='1
        query = f"SELECT * FROM logs WHERE date = '{date_param}'"
        sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_20():
    """Encoding-based bypass"""
    encoded_input = request.args.get("data")
    
    # Decode base64 (attacker controls decoded content)
    import base64
    decoded = base64.b64decode(encoded_input).decode('utf-8')
    
    query = f"SELECT * FROM secrets WHERE key = '{decoded}'"
    sqlite3.connect('db.sqlite').cursor().execute(query)

# ============================================================================
# GRANDMASTER LEVEL - EXTREME STEALTH (Nearly undetectable)
# ============================================================================

def vulnerable_21():
    """Type confusion vulnerability"""
    # Looks like int conversion makes it safe
    user_id = request.args.get("id")
    
    try:
        # This LOOKS safe but...
        numeric_id = int(user_id) if user_id.isdigit() else user_id
    except:
        numeric_id = user_id
    
    # Still vulnerable if exception occurs or non-digit path taken
    query = f"SELECT * FROM users WHERE id = {numeric_id}"
    sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_22():
    """Whitelist bypass via case manipulation"""
    table = request.args.get("table")
    
    allowed_tables = ["users", "products", "orders"]
    
    # Attacker can use: UsErS or USERS to bypass lowercase check
    if table.lower() in allowed_tables:
        # Vulnerable: uses original case, not validated version
        query = f"SELECT * FROM {table}"
        sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_23():
    """Time-of-check to time-of-use (TOCTOU)"""
    username = request.args.get("user")
    
    # Check happens here
    if username and len(username) < 50:
        # But variable can be modified between check and use
        # (In real scenario, this could be via race condition)
        time.sleep(0.1)  # Simulated delay
        
        query = f"SELECT * FROM users WHERE username = '{username}'"
        sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_24():
    """SQL in JSON payload"""
    import json
    
    json_data = request.get_json()
    
    if json_data and "query_params" in json_data:
        params = json_data["query_params"]
        
        # Build query from JSON (attacker controls JSON structure)
        query = f"SELECT * FROM {params['table']} WHERE {params['column']} = '{params['value']}'"
        sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_25():
    """Polyglot injection via comment"""
    search = request.args.get("search")
    
    # Remove SQL comments (but attacker can use nested comments)
    cleaned = search.replace("--", "").replace("/*", "").replace("*/", "")
    
    # Still vulnerable: attacker can use /*!50000 ... */ MySQL-style comments
    query = f"SELECT * FROM products WHERE name LIKE '%{cleaned}%'"
    sqlite3.connect('db.sqlite').cursor().execute(query)

# ============================================================================
# EDGE CASES (Boundary testing)
# ============================================================================

def edgecase_1():
    """Empty parameterization (false sense of security)"""
    user_input = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {user_input}"
    
    # Empty tuple doesn't prevent SQLi in first argument
    sqlite3.connect('db.sqlite').cursor().execute(query, ())

def edgecase_2():
    """Parameterization with wrong variable"""
    user_input = request.args.get("id")
    safe_value = "1"  # Hardcoded safe value
    
    # Query uses user_input but parameterization uses safe_value
    query = f"SELECT * FROM users WHERE id = {user_input}"
    sqlite3.connect('db.sqlite').cursor().execute(query, (safe_value,))

def edgecase_3():
    """Mixed safe and unsafe"""
    safe_id = 123  # Hardcoded
    unsafe_name = request.args.get("name")
    
    # First parameter safe, second vulnerable
    query = f"SELECT * FROM users WHERE id = {safe_id} AND name = '{unsafe_name}'"
    sqlite3.connect('db.sqlite').cursor().execute(query)

def edgecase_4():
    """Validation after use"""
    user_id = request.args.get("id")
    
    # Query executed BEFORE validation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = sqlite3.connect('db.sqlite').cursor().execute(query)
    
    # Validation too late!
    if not user_id.isdigit():
        raise ValueError("Invalid ID")
    
    return result

def edgecase_5():
    """Validation in wrong branch"""
    mode = request.args.get("mode")
    user_input = request.args.get("input")
    
    if mode == "safe":
        # Validation only happens in safe mode
        if not user_input.isalnum():
            raise ValueError("Invalid input")
    
    # But query always executes (vulnerable in non-safe mode)
    query = f"SELECT * FROM data WHERE value = '{user_input}'"
    sqlite3.connect('db.sqlite').cursor().execute(query)