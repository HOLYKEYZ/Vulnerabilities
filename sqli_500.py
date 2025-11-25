# Auto-generated SQLi benchmark file
# 500 sample functions (80% vulnerable)
from flask import request
import sqlite3
try:
    from sqlalchemy import text
except Exception:
    pass
try:
    from django.contrib.auth.models import User
except Exception:
    pass

def sample_vuln_0223():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0349():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0010():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0369():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0391():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_safe_0420():
    """SAFE - orm_safe"""
    uid = request.args.get('id')
    # ORM-style safe usage (placeholder)
    # session.query(User).filter(User.id == uid).first()
    return None

def sample_vuln_0249():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0003():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0009():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0240():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_safe_0487():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_vuln_0336():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_safe_0418():
    """SAFE - orm_safe"""
    uid = request.args.get('id')
    # ORM-style safe usage (placeholder)
    # session.query(User).filter(User.id == uid).first()
    return None

def sample_vuln_0140():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0105():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_safe_0460():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None

def sample_safe_0473():
    """SAFE - orm_safe"""
    uid = request.args.get('id')
    # ORM-style safe usage (placeholder)
    # session.query(User).filter(User.id == uid).first()
    return None

def sample_vuln_0378():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0300():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_safe_0443():
    """SAFE - orm_safe"""
    uid = request.args.get('id')
    # ORM-style safe usage (placeholder)
    # session.query(User).filter(User.id == uid).first()
    return None

def sample_safe_0441():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_vuln_0154():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0374():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_safe_0457():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None

def sample_vuln_0112():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0371():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0174():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0237():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0211():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0364():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0141():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_safe_0411():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0161():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_safe_0417():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None

def sample_vuln_0113():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0191():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0015():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_vuln_0115():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0093():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0220():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0029():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0187():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0028():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0030():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_safe_0489():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_vuln_0005():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_safe_0464():
    """SAFE - orm_safe"""
    uid = request.args.get('id')
    # ORM-style safe usage (placeholder)
    # session.query(User).filter(User.id == uid).first()
    return None

def sample_safe_0434():
    """SAFE - orm_safe"""
    uid = request.args.get('id')
    # ORM-style safe usage (placeholder)
    # session.query(User).filter(User.id == uid).first()
    return None

def sample_vuln_0059():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0209():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0061():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0287():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0227():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0091():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0036():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0229():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0147():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0345():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0234():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_safe_0428():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_vuln_0157():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0171():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0086():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0398():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0136():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_safe_0438():
    """SAFE - orm_safe"""
    uid = request.args.get('id')
    # ORM-style safe usage (placeholder)
    # session.query(User).filter(User.id == uid).first()
    return None

def sample_vuln_0279():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_safe_0494():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_vuln_0181():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0285():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0394():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0204():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0241():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0148():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0292():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0079():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0250():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0042():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0313():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_safe_0495():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_safe_0410():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0304():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0268():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_safe_0423():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None

def sample_safe_0485():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0022():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0326():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_safe_0403():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_vuln_0017():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0263():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_vuln_0389():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_safe_0496():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_safe_0426():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_vuln_0107():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0146():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0388():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0366():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0380():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0169():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0168():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0196():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0205():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0188():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0289():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0359():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_safe_0476():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_vuln_0303():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0179():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_safe_0406():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_vuln_0299():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0035():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0117():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0386():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0330():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0043():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0377():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_safe_0456():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0155():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0284():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0320():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0195():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0085():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0053():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0094():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0332():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_safe_0422():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0167():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0060():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0098():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0044():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0275():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0243():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0356():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0244():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0069():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_safe_0486():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_vuln_0047():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0127():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_safe_0435():
    """SAFE - orm_safe"""
    uid = request.args.get('id')
    # ORM-style safe usage (placeholder)
    # session.query(User).filter(User.id == uid).first()
    return None

def sample_vuln_0273():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0323():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0358():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_safe_0493():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_safe_0439():
    """SAFE - orm_safe"""
    uid = request.args.get('id')
    # ORM-style safe usage (placeholder)
    # session.query(User).filter(User.id == uid).first()
    return None

def sample_vuln_0233():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0282():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0222():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0266():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_vuln_0123():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_safe_0402():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_safe_0449():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0399():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0177():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_safe_0499():
    """SAFE - orm_safe"""
    uid = request.args.get('id')
    # ORM-style safe usage (placeholder)
    # session.query(User).filter(User.id == uid).first()
    return None

def sample_safe_0429():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_vuln_0092():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0219():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0246():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_safe_0491():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0064():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0097():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0253():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0180():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0296():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0347():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_safe_0479():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_safe_0432():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_vuln_0040():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0099():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0325():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0018():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0114():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0351():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_safe_0458():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_vuln_0106():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_safe_0433():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0186():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0007():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0260():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0163():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0269():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0251():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0259():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0156():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0124():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_safe_0413():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_safe_0447():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_safe_0465():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_vuln_0342():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0067():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0016():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_safe_0448():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0198():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0215():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0224():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0165():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_safe_0444():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_vuln_0254():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0247():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0312():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0362():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0150():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0020():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0272():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_vuln_0381():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0370():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0280():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0045():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0090():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_safe_0424():
    """SAFE - orm_safe"""
    uid = request.args.get('id')
    # ORM-style safe usage (placeholder)
    # session.query(User).filter(User.id == uid).first()
    return None

def sample_vuln_0231():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0057():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0214():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0122():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0027():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0125():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0108():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0396():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0372():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0158():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0306():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_safe_0416():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None

def sample_vuln_0075():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0277():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_safe_0409():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_vuln_0100():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0384():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0055():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_safe_0488():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0202():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0367():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_safe_0478():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0203():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_vuln_0143():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0102():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0295():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0081():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_vuln_0172():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0031():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0383():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_safe_0452():
    """SAFE - orm_safe"""
    uid = request.args.get('id')
    # ORM-style safe usage (placeholder)
    # session.query(User).filter(User.id == uid).first()
    return None

def sample_vuln_0327():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_safe_0483():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_vuln_0110():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0026():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_safe_0401():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None

def sample_vuln_0046():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_safe_0469():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None

def sample_vuln_0236():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_vuln_0267():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0058():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0368():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0135():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0034():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0314():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0133():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0207():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_safe_0462():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_vuln_0230():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_vuln_0382():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0078():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_safe_0468():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0264():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0270():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0310():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0095():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0341():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0238():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0290():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0056():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0052():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0193():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0104():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_safe_0497():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_vuln_0400():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_safe_0471():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_vuln_0002():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0343():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0334():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0130():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0309():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0070():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0132():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0076():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0228():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0319():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0197():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0390():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0286():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0087():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0283():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0397():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0129():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0084():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_safe_0412():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_vuln_0307():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0208():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0170():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0278():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0337():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0151():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0365():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0176():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0185():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_safe_0407():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_safe_0427():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_vuln_0037():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0012():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0317():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0039():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_safe_0442():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0054():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_safe_0414():
    """SAFE - orm_safe"""
    uid = request.args.get('id')
    # ORM-style safe usage (placeholder)
    # session.query(User).filter(User.id == uid).first()
    return None

def sample_vuln_0324():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0265():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0262():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_safe_0445():
    """SAFE - orm_safe"""
    uid = request.args.get('id')
    # ORM-style safe usage (placeholder)
    # session.query(User).filter(User.id == uid).first()
    return None

def sample_vuln_0089():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0013():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0216():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0297():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0218():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0194():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_safe_0437():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_vuln_0019():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_safe_0404():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_vuln_0072():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0023():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0120():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_safe_0492():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_vuln_0041():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_safe_0500():
    """SAFE - orm_safe"""
    uid = request.args.get('id')
    # ORM-style safe usage (placeholder)
    # session.query(User).filter(User.id == uid).first()
    return None

def sample_vuln_0184():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0346():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0109():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0138():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0101():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0271():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0073():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0066():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0257():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0032():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0149():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0088():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_safe_0477():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_vuln_0131():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0121():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0357():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_safe_0454():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_safe_0490():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0225():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0302():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_safe_0466():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None

def sample_safe_0498():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0011():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_safe_0419():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None

def sample_safe_0430():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_safe_0421():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_vuln_0159():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_vuln_0294():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0315():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0142():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0395():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_safe_0484():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_vuln_0335():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0128():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0301():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0134():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0173():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0049():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0001():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0111():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_safe_0482():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_vuln_0103():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0033():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0190():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0065():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_safe_0480():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_safe_0453():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_vuln_0352():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_vuln_0363():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0024():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0274():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0096():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0077():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0050():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0164():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0213():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_safe_0450():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None

def sample_vuln_0305():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0152():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0252():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0175():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0261():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0316():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0116():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0242():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0210():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0119():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0189():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0387():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0239():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_vuln_0006():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0355():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0232():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0256():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_vuln_0068():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0281():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_safe_0408():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_vuln_0153():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0291():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_safe_0467():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None

def sample_vuln_0192():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0392():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0393():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0311():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0071():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0255():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_safe_0459():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_vuln_0344():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0178():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0014():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_safe_0446():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_safe_0440():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_vuln_0354():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0126():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0182():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0021():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_safe_0451():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_safe_0463():
    """SAFE - param_query"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return None

def sample_vuln_0308():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_vuln_0322():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0166():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0160():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0083():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0199():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0074():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0139():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0348():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_safe_0431():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None

def sample_safe_0475():
    """SAFE - whitelist_table"""
    t = request.args.get('t')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    if t in ['users','orders']:
        cursor.execute(f"SELECT * FROM {t}")
    return None

def sample_vuln_0183():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0008():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_vuln_0321():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0080():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0235():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0385():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0004():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0318():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0118():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0221():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0379():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_vuln_0063():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0329():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0353():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0200():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0048():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_safe_0481():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_vuln_0201():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0375():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0212():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_safe_0455():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None

def sample_vuln_0162():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0340():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0137():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0062():
    """VULNERABLE - header_injection"""
    ua = request.headers.get('User-Agent')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO analytics(user_agent) VALUES('{ua}')")
    return None

def sample_safe_0425():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_safe_0474():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_vuln_0376():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0051():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0361():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0025():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0217():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_safe_0461():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None

def sample_vuln_0082():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0333():
    """VULNERABLE - fstring_injection"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return None

def sample_safe_0470():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_vuln_0248():
    """VULNERABLE - format_method"""
    col = request.args.get('col')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT {} FROM users".format(col)
    cursor.execute(query)
    return None

def sample_vuln_0360():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_safe_0436():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None

def sample_vuln_0245():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_vuln_0338():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0038():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_vuln_0276():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0145():
    """VULNERABLE - percent_format"""
    table = request.args.get('table')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM %s" % table
    cursor.execute(query)
    return None

def sample_vuln_0258():
    """VULNERABLE - union_injection"""
    inp = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM logs WHERE action = '{inp}' UNION SELECT password FROM users")
    return None

def sample_vuln_0144():
    """VULNERABLE - join_list"""
    filters = []
    for key in ['min','max']:
        val = request.args.get(key)
        if val:
            filters.append(f"price > {val}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    q = "SELECT * FROM items WHERE " + " AND ".join(filters)
    cursor.execute(q)
    return None

def sample_vuln_0288():
    """VULNERABLE - concat_injection"""
    name = request.args.get('name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # SQLi
    cursor.execute(query)
    return None

def sample_vuln_0293():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_vuln_0226():
    """VULNERABLE - executescript"""
    user_sql = request.args.get('sql')
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(user_sql)  # CRITICAL SQLi
    return None

def sample_safe_0415():
    """SAFE - isdigit_check"""
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return None

def sample_vuln_0339():
    """VULNERABLE - subquery_injection"""
    sub = request.args.get('sub')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id IN ({sub})")
    return None

def sample_vuln_0373():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0328():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None

def sample_vuln_0331():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_safe_0405():
    """SAFE - format_constant"""
    table = 'users'
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM {}'.format(table))
    return None

def sample_vuln_0206():
    """VULNERABLE - order_by_injection"""
    order = request.args.get('sort')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products ORDER BY {order}")
    return None

def sample_vuln_0298():
    """VULNERABLE - django_raw"""
    user_input = request.GET.get('id')
    User.objects.raw(f"SELECT * FROM users WHERE id = {user_input}")  # Django raw() with tainted input
    return None

def sample_vuln_0350():
    """VULNERABLE - sqlalchemy_text"""
    user_input = request.args.get('search')
    query = text(f"SELECT * FROM users WHERE name = '{user_input}'")  # SQLAlchemy text() with tainted input
    return None

def sample_safe_0472():
    """SAFE - logging_only"""
    data = request.args.get('x')
    print(f"LOG: {data}")
    return data
    return None
