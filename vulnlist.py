import sqlite3
from flask import request

##########################################
# 20 REAL VULNERABILITIES
##########################################

def vulnerable_1():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    uid = request.args.get('id')
    query = f"SELECT * FROM users WHERE id = {uid}"
    cur.execute(query)
    return cur.fetchall()

def vulnerable_2():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    name = request.form.get('name')
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cur.execute(query)
    return cur.fetchall()

def vulnerable_3():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    uid = request.json.get('uid')
    cur.execute(f"DELETE FROM users WHERE id = {uid}")

def vulnerable_4():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    term = request.args.get('search')
    query = f"SELECT * FROM products WHERE name LIKE '%{term}%'"
    cur.execute(query)
    return cur.fetchall()

def vulnerable_5():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    table = request.args.get('table')
    query = "SELECT * FROM %s" % table
    cur.execute(query)
    return cur.fetchall()

def vulnerable_6():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    where = request.args.get('filter')
    query = "SELECT * FROM logs WHERE " + where
    cur.execute(query)
    return cur.fetchall()

def vulnerable_7():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    uid = request.args.get('id')
    query = f"UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id={uid}"
    cur.execute(query)

def vulnerable_8():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    order = request.args.get('sort')
    query = f"SELECT * FROM events ORDER BY {order}"
    cur.execute(query)
    return cur.fetchall()

def vulnerable_9():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    pid = request.args.get('pid')
    query = "DELETE FROM products WHERE id='%s'" % pid
    cur.execute(query)

def vulnerable_10():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    raw = request.args.get('raw')
    query = f"SELECT * FROM audit WHERE event = '{raw}'"
    cur.execute(query)
    return cur.fetchall()

def vulnerable_11():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    key = request.args.get('key')
    query = "SELECT value FROM config WHERE key = '" + key + "'"
    cur.execute(query)
    return cur.fetchall()

def vulnerable_12():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    arg = request.args.get('q')
    query = f"SELECT * FROM items WHERE desc LIKE '{arg}%'"
    cur.execute(query)
    return cur.fetchall()

def vulnerable_13():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    email = request.form.get('email')
    query = "SELECT * FROM users WHERE email = '%s'" % email
    cur.execute(query)
    return cur.fetchall()

def vulnerable_14():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    category = request.args.get('cat')
    query = "SELECT * FROM catalog WHERE category = '" + category + "'"
    cur.execute(query)
    return cur.fetchall()

def vulnerable_15():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    col = request.args.get('column')
    val = request.args.get('value')
    query = f"SELECT {col} FROM stats WHERE metric = '{val}'"
    cur.execute(query)
    return cur.fetchall()

def vulnerable_16():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    filt = request.args.get('f')
    query = "SELECT * FROM data WHERE " + filt
    cur.execute(query)
    return cur.fetchall()

def vulnerable_17():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    t = request.args.get('t')
    idd = request.args.get('id')
    query = "SELECT * FROM %s WHERE id = %s" % (t, idd)
    cur.execute(query)
    return cur.fetchall()

def vulnerable_18():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    where = request.args.get('where')
    query = f"SELECT * FROM payments WHERE {where}"
    cur.execute(query)
    return cur.fetchall()

def vulnerable_19():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    pattern = request.args.get('p')
    query = "SELECT * FROM accounts WHERE username LIKE '%s%%'" % pattern
    cur.execute(query)
    return cur.fetchall()

def vulnerable_20():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    username = request.form.get('user')
    passwd = request.form.get('pass')
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{passwd}'"
    cur.execute(query)
    return cur.fetchall()


##########################################
# 10 DECOY (BENIGN) FUNCTIONS
# — look dangerous, but actually safe
##########################################

def decoy_1():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    uid = request.args.get('id')
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return cur.fetchall()

def decoy_2():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    name = request.args.get('name')
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cur.fetchall()

def decoy_3():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    search = request.args.get('q')
    cur.execute("SELECT * FROM items WHERE description LIKE ?", (f"%{search}%",))
    return cur.fetchall()

def decoy_4():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    table = request.args.get('t')
    if table not in ["users", "items", "orders"]:
        return []
    cur.execute(f"SELECT count(*) FROM {table}")
    return cur.fetchall()

def decoy_5():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    email = request.form.get('email')
    cur.execute("SELECT * FROM newsletter WHERE email=?", (email,))
    return cur.fetchall()

def decoy_6():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    uid = request.args.get('id')
    cur.execute("UPDATE users SET active=1 WHERE id=?", (uid,))
    return "ok"

def decoy_7():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    metric = request.args.get('m')
    cur.execute("SELECT value FROM metrics WHERE name=?", (metric,))
    return cur.fetchall()

def decoy_8():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    col = request.args.get('column')
    if col not in ["views", "clicks", "sales"]:
        return []
    cur.execute(f"SELECT {col} FROM analytics")
    return cur.fetchall()

def decoy_9():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    user = request.form.get('user')
    cur.execute("SELECT * FROM profile WHERE username=?", (user,))
    return cur.fetchall()

def decoy_10():
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    tag = request.args.get('tag')
    cur.execute("SELECT * FROM tags WHERE tag LIKE ?", (f"%{tag}%",))
    return cur.fetchall()
