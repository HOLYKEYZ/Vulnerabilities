import sqlite3
from flask import request, session

###############################################################################
#                                VULNERABILITIES
#                           (20 real SQL injection cases)
###############################################################################

def vulnerable_1():
    """F-string injection"""
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    uid = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return cursor.fetchall()

def vulnerable_2():
    """String concatenation"""
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    conn = sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_3():
    """% formatting"""
    table = request.args.get("table")
    query = "SELECT * FROM %s" % table  # SQLi
    sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_4():
    """format() injection"""
    col = request.args.get("col")
    query = "SELECT {} FROM users".format(col)  # SQLi
    sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_5():
    """Taint through variable reuse"""
    data = request.args.get("search")
    temp = data
    final = temp
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT * FROM items WHERE name LIKE '%{final}%'"
    )

def vulnerable_6():
    """Deep taint propagation"""
    a = request.args.get("input")
    b = a
    c = b
    q = f"DELETE FROM logs WHERE message LIKE '%{c}%'"
    sqlite3.connect('db.sqlite').cursor().execute(q)

def vulnerable_7():
    """Header-based injection (critical)"""
    ua = request.headers.get("User-Agent")
    sqlite3.connect('db.sqlite').cursor().execute(
        f"INSERT INTO analytics(user_agent) VALUES('{ua}')"
    )

def vulnerable_8():
    """Session-based taint"""
    uid = session.get("uid")
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT * FROM payments WHERE user_id = {uid}"
    )

def vulnerable_9():
    """JSON input"""
    user = request.json.get("username")
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT * FROM users WHERE username = '{user}'"
    )

def vulnerable_10():
    """Path parameter injection"""
    path_val = request.args.get("column")
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT {path_val} FROM audit_logs"
    )

def vulnerable_11():
    """SQL fragment concatenation"""
    base = "SELECT * FROM users WHERE "
    cond = "role = '" + request.args.get("role") + "'"  # SQLi
    sqlite3.connect('db.sqlite').cursor().execute(base + cond)

def vulnerable_12():
    """Conditional taint"""
    p = request.args.get("price")
    if p:
        q = f"SELECT * FROM products WHERE price > {p}"
        sqlite3.connect('db.sqlite').cursor().execute(q)

def vulnerable_13():
    """Function call indirection"""

    def build_where(x):
        return f"WHERE id = {x}"  # tainted

    uid = request.args.get("id")
    query = "SELECT * FROM users " + build_where(uid)
    sqlite3.connect('db.sqlite').cursor().execute(query)

def vulnerable_14():
    """Loop-constructed injection"""
    filters = []
    for key in ["min", "max"]:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")  # taint
    sql = "SELECT * FROM items WHERE " + " AND ".join(filters)
    sqlite3.connect('db.sqlite').cursor().execute(sql)

def vulnerable_15():
    """ORM-like raw SQL builder"""
    expr = request.args.get("expr")
    sql = f"SELECT * FROM orders WHERE {expr}"  # SQLi expression
    sqlite3.connect('db.sqlite').cursor().execute(sql)

def vulnerable_16():
    """Second-order SQL injection"""
    conn = sqlite3.connect("db.sqlite")
    cur = conn.cursor()
    tainted = request.args.get("data")
    cur.execute("INSERT INTO temp_store(val) VALUES(?)", (tainted,))
    # Later reused unsafely
    row = cur.execute("SELECT val FROM temp_store").fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # SQLi

def vulnerable_17():
    """Implicit join string building"""
    col = request.args.get("col")
    sql = "SELECT id, " + col + " FROM users"
    sqlite3.connect('db.sqlite').cursor().execute(sql)

def vulnerable_18():
    """UNION injection pattern"""
    inp = request.args.get("q")
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT * FROM logs WHERE action = '{inp}'"
    )

def vulnerable_19():
    """ORDER BY injection"""
    order = request.args.get("sort")
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT * FROM products ORDER BY {order}"
    )

def vulnerable_20():
    """Subquery injection"""
    sub = request.args.get("sub")
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT * FROM items WHERE id IN ({sub})"
    )


###############################################################################
#                                DECOYS (SAFE)
#                         10 functions your scanner MUST ignore
###############################################################################

def decoy_1():
    """Parameterized query"""
    u = request.args.get("id")
    sqlite3.connect('db.sqlite').cursor().execute(
        "SELECT * FROM users WHERE id = ?", (u,)
    )

def decoy_2():
    """Strict digit check"""
    uid = request.args.get("id")
    if not uid.isdigit(): return "bad"
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT * FROM users WHERE id = {uid}"
    )

def decoy_3():
    """Table name validation"""
    t = request.args.get("t")
    if t not in ["users", "orders"]: return "no"
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT * FROM {t}"
    )

def decoy_4():
    """Whitelist column"""
    col = request.args.get("c")
    allowed = {"name", "email"}
    if col not in allowed: return "bad"
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT {col} FROM users"
    )

def decoy_5():
    """Safe string formatting with constants only"""
    table = "users"
    sqlite3.connect('db.sqlite').cursor().execute(
        "SELECT * FROM {}".format(table)
    )

def decoy_6():
    """Safe formatted logging—not SQL"""
    data = request.args.get("x")
    print(f"LOG: {data}")  # not a SQL sink

def decoy_7():
    """JSON safe usage"""
    obj = request.json
    return obj.get("safe")

def decoy_8():
    """Header safe usage"""
    ua = request.headers.get("User-Agent")
    print(ua)  # Not SQL

def decoy_9():
    """Multi variable safe parameterization"""
    uid = request.args.get("id")
    name = request.args.get("name")
    sqlite3.connect('db.sqlite').cursor().execute(
        "SELECT * FROM u WHERE id=? AND name=?", (uid, name)
    )

def decoy_10():
    """Safe empty query builder"""
    base = "SELECT * FROM users"
    sqlite3.connect('db.sqlite').cursor().execute(base)


###############################################################################
#                     ADVANCED EDGE CASES (Optional Extra 10)
#         These ensure production-grade performance & real-world handling
###############################################################################

def edgecase_1():
    """Taint hidden inside dict"""
    data = {"a": request.args.get("x")}
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT * FROM items WHERE id = {data['a']}"
    )

def edgecase_2():
    """Taint passed via list"""
    vals = [request.args.get("v")]
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT * FROM x WHERE id = {vals[0]}"
    )

def edgecase_3():
    """Taint through chained function calls"""

    def a(x): return x
    def b(y): return y
    def c(z): return z

    inp = c(b(a(request.args.get("id"))))
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT * FROM users WHERE id = {inp}"
    )

def edgecase_4():
    """SQL fragment inside a loop accumulator"""
    frags = []
    for p in request.args.getlist("p"):
        frags.append(f"value = '{p}'")  # tainted
    q = " OR ".join(frags)
    sqlite3.connect('db.sqlite').cursor().execute(
        "SELECT * FROM tbl WHERE " + q
    )

def edgecase_5():
    """Fake validation (deceptive naming)"""
    safe_input = request.args.get("x")  # NOT ACTUALLY SAFE
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT * FROM u WHERE name = '{safe_input}'"
    )

def edgecase_6():
    """Computed SQL keyword injection"""
    part = request.args.get("field")
    sql = "SELECT id, {} FROM users".format(part)
    sqlite3.connect('db.sqlite').cursor().execute(sql)

def edgecase_7():
    """JOIN clause injection"""
    join = request.args.get("join")
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT * FROM a JOIN b ON {join}"
    )

def edgecase_8():
    """Order clause with multiple taints"""
    fields = request.args.get("f")
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT * FROM r ORDER BY {fields}"
    )

def edgecase_9():
    """Indirect SQL building via a helper class"""

    class Builder:
        def __init__(self): self.base = "SELECT * FROM users WHERE "
        def add(self, cond): self.base += cond  # tainted

    b = Builder()
    b.add(f"id = {request.args.get('id')}")
    sqlite3.connect('db.sqlite').cursor().execute(b.base)

def edgecase_10():
    """Taint in subquery expression"""
    sub = request.args.get("sub")
    sqlite3.connect('db.sqlite').cursor().execute(
        f"SELECT name FROM users WHERE id IN (SELECT uid FROM orders WHERE id={sub})"
    )



# ============================================================================
# MISSING TEST CASES - Add these to vulnlist2.py
# ============================================================================
from django.contrib.auth.models import User  # Import the User model

# Test PY-SQLI-003: SQLAlchemy text() with tainted input
from sqlalchemy import text
def vulnerable_sqlalchemy(request):
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # PY-SQLI-003
    return query

# Test PY-SQLI-004: Django raw() with tainted input
def vulnerable_django(request):
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # PY-SQLI-004

# Test PY-SQLI-005: executescript with tainted input
def vulnerable_executescript(request):
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # PY-SQLI-005 - CRITICAL

# Test PY-SQLI-008: Weak sanitization (replace single quotes)
def vulnerable_weak_sanitization(request):
    user_input = request.args.get('name')
    safe_input = user_input.replace("'", "")  # PY-SQLI-008 - Bypassable!
    query = f"SELECT * FROM users WHERE name = '{safe_input}'"
    sqlite3.connect('db.sqlite').cursor().execute(query)

# Test PY-SQLI-009: Unvalidated date parameter
def vulnerable_date_param(request):
    date_from = request.args.get('date_from')  # No validation!
    query = f"SELECT * FROM logs WHERE date BETWEEN '{date_from}' AND '2024-12-31'"  # PY-SQLI-009
    sqlite3.connect('db.sqlite').cursor().execute(query)
