# Auto-generated complex SQLi challenge corpus
# Total functions: 1000
# Vulnerable: 601  (odd)
# Safe/decoys: 399  (odd)
# Reference uploaded scanner source: /mnt/data/scan6.py
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

def vuln_complex_0001():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0002():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0003():
    """VULNERABLE - eval_build"""
    s = request.args.get('q')
    q = eval('"SELECT * FROM users WHERE name = ' + repr(s) + '"')
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0004():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0005():
    """VULNERABLE - fstring_nested"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {int(uid or 0)}")
    return None

def vuln_complex_0006():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0007():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0008():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0009():
    """VULNERABLE - union_triple"""
    x = request.args.get('q')
    q = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0010():
    """VULNERABLE - eval_build"""
    s = request.args.get('q')
    q = eval('"SELECT * FROM users WHERE name = ' + repr(s) + '"')
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0011():
    """VULNERABLE - global_flow"""
    global G
    G = request.args.get('g')
    # later read
    val = G
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE v=' + val)
    return None

def vuln_complex_0012():
    """VULNERABLE - order_by_obfus"""
    sort = request.args.get('sort')
    cols = '-'.join([sort])
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM products ORDER BY ' + cols)
    return None

def vuln_complex_0013():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0014():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0015():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0016():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0017():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0018():
    """VULNERABLE - builder_class"""
    class B:
        def __init__(self): self.q='SELECT * FROM x WHERE '
        def add(self,c): self.q += c
    b=B()
    b.add('id=' + request.args.get('id'))
    sqlite3.connect('db.sqlite').cursor().execute(b.q)
    return None

def vuln_complex_0019():
    """VULNERABLE - builder_class"""
    class B:
        def __init__(self): self.q='SELECT * FROM x WHERE '
        def add(self,c): self.q += c
    b=B()
    b.add('id=' + request.args.get('id'))
    sqlite3.connect('db.sqlite').cursor().execute(b.q)
    return None

def vuln_complex_0020():
    """VULNERABLE - getattr_setattr"""
    obj = {}
    setattr(obj, 'v', request.args.get('v'))
    val = getattr(obj, 'v')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM a WHERE b='{val}'")
    return None

def vuln_complex_0021():
    """VULNERABLE - class_attr"""
    class Holder:
        pass
    h = Holder()
    h.v = request.args.get('v')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE x=' + h.v)
    return None

def vuln_complex_0022():
    """VULNERABLE - mogrify_like"""
    v = request.args.get('v')
    q = "SELECT * FROM t WHERE a = %s" % v
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0023():
    """VULNERABLE - format_tuple1"""
    a = request.args.get('a')
    q = 'SELECT %s' % (a,)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0024():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0025():
    """VULNERABLE - repr_obfus"""
    r = repr(request.args.get('x'))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)
    return None

def vuln_complex_0026():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0027():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0028():
    """VULNERABLE - subquery_positional"""
    sub = request.args.get('sub')
    q = "SELECT * FROM items WHERE id IN ({})".format(sub)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0029():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0030():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0031():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0032():
    """VULNERABLE - bytes_flow"""
    b = request.args.get('b').encode('utf-8').decode()
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE a=' + b)
    return None

def vuln_complex_0033():
    """VULNERABLE - builder_class"""
    class B:
        def __init__(self): self.q='SELECT * FROM x WHERE '
        def add(self,c): self.q += c
    b=B()
    b.add('id=' + request.args.get('id'))
    sqlite3.connect('db.sqlite').cursor().execute(b.q)
    return None

def vuln_complex_0034():
    """VULNERABLE - global_flow"""
    global G
    G = request.args.get('g')
    # later read
    val = G
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE v=' + val)
    return None

def vuln_complex_0035():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0036():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0037():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0038():
    """VULNERABLE - order_by_obfus"""
    sort = request.args.get('sort')
    cols = '-'.join([sort])
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM products ORDER BY ' + cols)
    return None

def vuln_complex_0039():
    """VULNERABLE - executemany_made"""
    pairs = [(request.args.get('a'),), (request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(%s)', pairs)
    return None

def vuln_complex_0040():
    """VULNERABLE - percent_tuple"""
    tbl = request.args.get('table')
    uid = request.args.get('id')
    q = "SELECT * FROM %s WHERE id = %s" % (tbl, uid)
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0041():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0042():
    """VULNERABLE - getattr_setattr"""
    obj = {}
    setattr(obj, 'v', request.args.get('v'))
    val = getattr(obj, 'v')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM a WHERE b='{val}'")
    return None

def vuln_complex_0043():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0044():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0045():
    """VULNERABLE - percent_tuple"""
    tbl = request.args.get('table')
    uid = request.args.get('id')
    q = "SELECT * FROM %s WHERE id = %s" % (tbl, uid)
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0046():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0047():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0048():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0049():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0050():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0051():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0052():
    """VULNERABLE - mogrify_like"""
    v = request.args.get('v')
    q = "SELECT * FROM t WHERE a = %s" % v
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0053():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0054():
    """VULNERABLE - percent_tuple"""
    tbl = request.args.get('table')
    uid = request.args.get('id')
    q = "SELECT * FROM %s WHERE id = %s" % (tbl, uid)
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0055():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0056():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0057():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0058():
    """VULNERABLE - union_triple"""
    x = request.args.get('q')
    q = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0059():
    """VULNERABLE - dict_attr"""
    d = {}
    d['k'] = request.args.get('k')
    val = d.get('k')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute(f"SELECT * FROM z WHERE a = '{val}'")
    return None

def vuln_complex_0060():
    """VULNERABLE - format_map"""
    fmt = 'SELECT {col} FROM users'
    col = request.args.get('col')
    q = fmt.format_map({'col': col})
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0061():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0062():
    """VULNERABLE - fstring_nested"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {int(uid or 0)}")
    return None

def vuln_complex_0063():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0064():
    """VULNERABLE - repr_obfus"""
    r = repr(request.args.get('x'))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)
    return None

def vuln_complex_0065():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0066():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0067():
    """VULNERABLE - eval_build"""
    s = request.args.get('q')
    q = eval('"SELECT * FROM users WHERE name = ' + repr(s) + '"')
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0068():
    """VULNERABLE - decorator_forward"""
    def deco(f):
        def wrapper(*a,**k): return f(*a,**k)
        return wrapper
    @deco
    def fn():
        x = request.args.get('q')
        sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE q=' + x)
    return None

def vuln_complex_0069():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0070():
    """VULNERABLE - django_raw_concat"""
    i = request.GET.get('id')
    qs = 'SELECT * FROM users WHERE id = ' + i
    User.objects.raw(qs)
    return None

def vuln_complex_0071():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0072():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0073():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0074():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0075():
    """VULNERABLE - join_map"""
    vals = [request.args.get('a'), request.args.get('b')]
    conds = list(map(lambda v: f"x='{v}'", vals))
    q = ' OR '.join(conds)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0076():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0077():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0078():
    """VULNERABLE - concat_fragments"""
    parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']
    uid = request.args.get('id')
    q = parts[0] + parts[1] + parts[2] + uid
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0079():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0080():
    """VULNERABLE - mogrify_like"""
    v = request.args.get('v')
    q = "SELECT * FROM t WHERE a = %s" % v
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0081():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0082():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0083():
    """VULNERABLE - global_flow"""
    global G
    G = request.args.get('g')
    # later read
    val = G
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE v=' + val)
    return None

def vuln_complex_0084():
    """VULNERABLE - fstring_funccall"""
    uid = request.args.get('id')
    def wrap(x):
        return x
    c = sqlite3.connect('db.sqlite').cursor()
    c.execute(f"SELECT * FROM items WHERE owner = '{wrap(uid)}'")
    return None

def vuln_complex_0085():
    """VULNERABLE - django_raw_concat"""
    i = request.GET.get('id')
    qs = 'SELECT * FROM users WHERE id = ' + i
    User.objects.raw(qs)
    return None

def vuln_complex_0086():
    """VULNERABLE - order_by_obfus"""
    sort = request.args.get('sort')
    cols = '-'.join([sort])
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM products ORDER BY ' + cols)
    return None

def vuln_complex_0087():
    """VULNERABLE - bytes_flow"""
    b = request.args.get('b').encode('utf-8').decode()
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE a=' + b)
    return None

def vuln_complex_0088():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0089():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0090():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0091():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0092():
    """VULNERABLE - percent_tuple"""
    tbl = request.args.get('table')
    uid = request.args.get('id')
    q = "SELECT * FROM %s WHERE id = %s" % (tbl, uid)
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0093():
    """VULNERABLE - fstring_funccall"""
    uid = request.args.get('id')
    def wrap(x):
        return x
    c = sqlite3.connect('db.sqlite').cursor()
    c.execute(f"SELECT * FROM items WHERE owner = '{wrap(uid)}'")
    return None

def vuln_complex_0094():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0095():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0096():
    """VULNERABLE - mogrify_like"""
    v = request.args.get('v')
    q = "SELECT * FROM t WHERE a = %s" % v
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0097():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0098():
    """VULNERABLE - django_raw_concat"""
    i = request.GET.get('id')
    qs = 'SELECT * FROM users WHERE id = ' + i
    User.objects.raw(qs)
    return None

def vuln_complex_0099():
    """VULNERABLE - fstring_nested"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {int(uid or 0)}")
    return None

def vuln_complex_0100():
    """VULNERABLE - fstring_funccall"""
    uid = request.args.get('id')
    def wrap(x):
        return x
    c = sqlite3.connect('db.sqlite').cursor()
    c.execute(f"SELECT * FROM items WHERE owner = '{wrap(uid)}'")
    return None

def vuln_complex_0101():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0102():
    """VULNERABLE - order_by_obfus"""
    sort = request.args.get('sort')
    cols = '-'.join([sort])
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM products ORDER BY ' + cols)
    return None

def vuln_complex_0103():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0104():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0105():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0106():
    """VULNERABLE - builder_class"""
    class B:
        def __init__(self): self.q='SELECT * FROM x WHERE '
        def add(self,c): self.q += c
    b=B()
    b.add('id=' + request.args.get('id'))
    sqlite3.connect('db.sqlite').cursor().execute(b.q)
    return None

def vuln_complex_0107():
    """VULNERABLE - global_flow"""
    global G
    G = request.args.get('g')
    # later read
    val = G
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE v=' + val)
    return None

def vuln_complex_0108():
    """VULNERABLE - eval_build"""
    s = request.args.get('q')
    q = eval('"SELECT * FROM users WHERE name = ' + repr(s) + '"')
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0109():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0110():
    """VULNERABLE - format_tuple1"""
    a = request.args.get('a')
    q = 'SELECT %s' % (a,)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0111():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0112():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0113():
    """VULNERABLE - join_map_str"""
    vals = map(lambda x: request.args.get(x), ['a','b'])
    q = ''.join(vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0114():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0115():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0116():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0117():
    """VULNERABLE - format_map"""
    fmt = 'SELECT {col} FROM users'
    col = request.args.get('col')
    q = fmt.format_map({'col': col})
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0118():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0119():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0120():
    """VULNERABLE - builder_class"""
    class B:
        def __init__(self): self.q='SELECT * FROM x WHERE '
        def add(self,c): self.q += c
    b=B()
    b.add('id=' + request.args.get('id'))
    sqlite3.connect('db.sqlite').cursor().execute(b.q)
    return None

def vuln_complex_0121():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0122():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0123():
    """VULNERABLE - path_param"""
    p = request.view_args.get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM t WHERE id={p}")
    return None

def vuln_complex_0124():
    """VULNERABLE - dict_attr"""
    d = {}
    d['k'] = request.args.get('k')
    val = d.get('k')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute(f"SELECT * FROM z WHERE a = '{val}'")
    return None

def vuln_complex_0125():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0126():
    """VULNERABLE - union_triple"""
    x = request.args.get('q')
    q = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0127():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0128():
    """VULNERABLE - decorator_forward"""
    def deco(f):
        def wrapper(*a,**k): return f(*a,**k)
        return wrapper
    @deco
    def fn():
        x = request.args.get('q')
        sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE q=' + x)
    return None

def vuln_complex_0129():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0130():
    """VULNERABLE - subquery_positional"""
    sub = request.args.get('sub')
    q = "SELECT * FROM items WHERE id IN ({})".format(sub)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0131():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0132():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0133():
    """VULNERABLE - eval_build"""
    s = request.args.get('q')
    q = eval('"SELECT * FROM users WHERE name = ' + repr(s) + '"')
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0134():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0135():
    """VULNERABLE - builder_class"""
    class B:
        def __init__(self): self.q='SELECT * FROM x WHERE '
        def add(self,c): self.q += c
    b=B()
    b.add('id=' + request.args.get('id'))
    sqlite3.connect('db.sqlite').cursor().execute(b.q)
    return None

def vuln_complex_0136():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0137():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0138():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0139():
    """VULNERABLE - order_by_obfus"""
    sort = request.args.get('sort')
    cols = '-'.join([sort])
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM products ORDER BY ' + cols)
    return None

def vuln_complex_0140():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0141():
    """VULNERABLE - percent_tuple"""
    tbl = request.args.get('table')
    uid = request.args.get('id')
    q = "SELECT * FROM %s WHERE id = %s" % (tbl, uid)
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0142():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0143():
    """VULNERABLE - path_param"""
    p = request.view_args.get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM t WHERE id={p}")
    return None

def vuln_complex_0144():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0145():
    """VULNERABLE - bytes_flow"""
    b = request.args.get('b').encode('utf-8').decode()
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE a=' + b)
    return None

def vuln_complex_0146():
    """VULNERABLE - subquery_positional"""
    sub = request.args.get('sub')
    q = "SELECT * FROM items WHERE id IN ({})".format(sub)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0147():
    """VULNERABLE - concat_fragments"""
    parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']
    uid = request.args.get('id')
    q = parts[0] + parts[1] + parts[2] + uid
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0148():
    """VULNERABLE - fstring_funccall"""
    uid = request.args.get('id')
    def wrap(x):
        return x
    c = sqlite3.connect('db.sqlite').cursor()
    c.execute(f"SELECT * FROM items WHERE owner = '{wrap(uid)}'")
    return None

def vuln_complex_0149():
    """VULNERABLE - format_tuple1"""
    a = request.args.get('a')
    q = 'SELECT %s' % (a,)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0150():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0151():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0152():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0153():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0154():
    """VULNERABLE - concat_fragments"""
    parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']
    uid = request.args.get('id')
    q = parts[0] + parts[1] + parts[2] + uid
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0155():
    """VULNERABLE - repr_obfus"""
    r = repr(request.args.get('x'))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)
    return None

def vuln_complex_0156():
    """VULNERABLE - fstring_nested"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {int(uid or 0)}")
    return None

def vuln_complex_0157():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0158():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0159():
    """VULNERABLE - concat_fragments"""
    parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']
    uid = request.args.get('id')
    q = parts[0] + parts[1] + parts[2] + uid
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0160():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0161():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0162():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0163():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0164():
    """VULNERABLE - django_raw_concat"""
    i = request.GET.get('id')
    qs = 'SELECT * FROM users WHERE id = ' + i
    User.objects.raw(qs)
    return None

def vuln_complex_0165():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0166():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0167():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0168():
    """VULNERABLE - executemany_made"""
    pairs = [(request.args.get('a'),), (request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(%s)', pairs)
    return None

def vuln_complex_0169():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0170():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0171():
    """VULNERABLE - bytes_flow"""
    b = request.args.get('b').encode('utf-8').decode()
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE a=' + b)
    return None

def vuln_complex_0172():
    """VULNERABLE - union_triple"""
    x = request.args.get('q')
    q = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0173():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0174():
    """VULNERABLE - union_triple"""
    x = request.args.get('q')
    q = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0175():
    """VULNERABLE - join_map"""
    vals = [request.args.get('a'), request.args.get('b')]
    conds = list(map(lambda v: f"x='{v}'", vals))
    q = ' OR '.join(conds)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0176():
    """VULNERABLE - join_map_str"""
    vals = map(lambda x: request.args.get(x), ['a','b'])
    q = ''.join(vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0177():
    """VULNERABLE - percent_tuple"""
    tbl = request.args.get('table')
    uid = request.args.get('id')
    q = "SELECT * FROM %s WHERE id = %s" % (tbl, uid)
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0178():
    """VULNERABLE - join_map_str"""
    vals = map(lambda x: request.args.get(x), ['a','b'])
    q = ''.join(vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0179():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0180():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0181():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0182():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0183():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0184():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0185():
    """VULNERABLE - path_param"""
    p = request.view_args.get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM t WHERE id={p}")
    return None

def vuln_complex_0186():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0187():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0188():
    """VULNERABLE - fstring_funccall"""
    uid = request.args.get('id')
    def wrap(x):
        return x
    c = sqlite3.connect('db.sqlite').cursor()
    c.execute(f"SELECT * FROM items WHERE owner = '{wrap(uid)}'")
    return None

def vuln_complex_0189():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0190():
    """VULNERABLE - percent_tuple"""
    tbl = request.args.get('table')
    uid = request.args.get('id')
    q = "SELECT * FROM %s WHERE id = %s" % (tbl, uid)
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0191():
    """VULNERABLE - dict_attr"""
    d = {}
    d['k'] = request.args.get('k')
    val = d.get('k')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute(f"SELECT * FROM z WHERE a = '{val}'")
    return None

def vuln_complex_0192():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0193():
    """VULNERABLE - order_by_obfus"""
    sort = request.args.get('sort')
    cols = '-'.join([sort])
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM products ORDER BY ' + cols)
    return None

def vuln_complex_0194():
    """VULNERABLE - format_map"""
    fmt = 'SELECT {col} FROM users'
    col = request.args.get('col')
    q = fmt.format_map({'col': col})
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0195():
    """VULNERABLE - decorator_forward"""
    def deco(f):
        def wrapper(*a,**k): return f(*a,**k)
        return wrapper
    @deco
    def fn():
        x = request.args.get('q')
        sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE q=' + x)
    return None

def vuln_complex_0196():
    """VULNERABLE - django_raw_concat"""
    i = request.GET.get('id')
    qs = 'SELECT * FROM users WHERE id = ' + i
    User.objects.raw(qs)
    return None

def vuln_complex_0197():
    """VULNERABLE - join_map_str"""
    vals = map(lambda x: request.args.get(x), ['a','b'])
    q = ''.join(vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0198():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0199():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0200():
    """VULNERABLE - executemany_made"""
    pairs = [(request.args.get('a'),), (request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(%s)', pairs)
    return None

def vuln_complex_0201():
    """VULNERABLE - concat_fragments"""
    parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']
    uid = request.args.get('id')
    q = parts[0] + parts[1] + parts[2] + uid
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0202():
    """VULNERABLE - path_param"""
    p = request.view_args.get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM t WHERE id={p}")
    return None

def vuln_complex_0203():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0204():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0205():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0206():
    """VULNERABLE - union_triple"""
    x = request.args.get('q')
    q = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0207():
    """VULNERABLE - class_attr"""
    class Holder:
        pass
    h = Holder()
    h.v = request.args.get('v')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE x=' + h.v)
    return None

def vuln_complex_0208():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0209():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0210():
    """VULNERABLE - fstring_funccall"""
    uid = request.args.get('id')
    def wrap(x):
        return x
    c = sqlite3.connect('db.sqlite').cursor()
    c.execute(f"SELECT * FROM items WHERE owner = '{wrap(uid)}'")
    return None

def vuln_complex_0211():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0212():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0213():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0214():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0215():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0216():
    """VULNERABLE - subquery_positional"""
    sub = request.args.get('sub')
    q = "SELECT * FROM items WHERE id IN ({})".format(sub)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0217():
    """VULNERABLE - getattr_setattr"""
    obj = {}
    setattr(obj, 'v', request.args.get('v'))
    val = getattr(obj, 'v')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM a WHERE b='{val}'")
    return None

def vuln_complex_0218():
    """VULNERABLE - join_map_str"""
    vals = map(lambda x: request.args.get(x), ['a','b'])
    q = ''.join(vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0219():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0220():
    """VULNERABLE - decorator_forward"""
    def deco(f):
        def wrapper(*a,**k): return f(*a,**k)
        return wrapper
    @deco
    def fn():
        x = request.args.get('q')
        sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE q=' + x)
    return None

def vuln_complex_0221():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0222():
    """VULNERABLE - concat_fragments"""
    parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']
    uid = request.args.get('id')
    q = parts[0] + parts[1] + parts[2] + uid
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0223():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0224():
    """VULNERABLE - bytes_flow"""
    b = request.args.get('b').encode('utf-8').decode()
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE a=' + b)
    return None

def vuln_complex_0225():
    """VULNERABLE - concat_fragments"""
    parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']
    uid = request.args.get('id')
    q = parts[0] + parts[1] + parts[2] + uid
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0226():
    """VULNERABLE - class_attr"""
    class Holder:
        pass
    h = Holder()
    h.v = request.args.get('v')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE x=' + h.v)
    return None

def vuln_complex_0227():
    """VULNERABLE - join_map_str"""
    vals = map(lambda x: request.args.get(x), ['a','b'])
    q = ''.join(vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0228():
    """VULNERABLE - join_map_str"""
    vals = map(lambda x: request.args.get(x), ['a','b'])
    q = ''.join(vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0229():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0230():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0231():
    """VULNERABLE - getattr_setattr"""
    obj = {}
    setattr(obj, 'v', request.args.get('v'))
    val = getattr(obj, 'v')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM a WHERE b='{val}'")
    return None

def vuln_complex_0232():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0233():
    """VULNERABLE - subquery_positional"""
    sub = request.args.get('sub')
    q = "SELECT * FROM items WHERE id IN ({})".format(sub)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0234():
    """VULNERABLE - repr_obfus"""
    r = repr(request.args.get('x'))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)
    return None

def vuln_complex_0235():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0236():
    """VULNERABLE - fstring_nested"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {int(uid or 0)}")
    return None

def vuln_complex_0237():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0238():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0239():
    """VULNERABLE - mogrify_like"""
    v = request.args.get('v')
    q = "SELECT * FROM t WHERE a = %s" % v
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0240():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0241():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0242():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0243():
    """VULNERABLE - getattr_setattr"""
    obj = {}
    setattr(obj, 'v', request.args.get('v'))
    val = getattr(obj, 'v')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM a WHERE b='{val}'")
    return None

def vuln_complex_0244():
    """VULNERABLE - class_attr"""
    class Holder:
        pass
    h = Holder()
    h.v = request.args.get('v')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE x=' + h.v)
    return None

def vuln_complex_0245():
    """VULNERABLE - concat_fragments"""
    parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']
    uid = request.args.get('id')
    q = parts[0] + parts[1] + parts[2] + uid
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0246():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0247():
    """VULNERABLE - builder_class"""
    class B:
        def __init__(self): self.q='SELECT * FROM x WHERE '
        def add(self,c): self.q += c
    b=B()
    b.add('id=' + request.args.get('id'))
    sqlite3.connect('db.sqlite').cursor().execute(b.q)
    return None

def vuln_complex_0248():
    """VULNERABLE - order_by_obfus"""
    sort = request.args.get('sort')
    cols = '-'.join([sort])
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM products ORDER BY ' + cols)
    return None

def vuln_complex_0249():
    """VULNERABLE - django_raw_concat"""
    i = request.GET.get('id')
    qs = 'SELECT * FROM users WHERE id = ' + i
    User.objects.raw(qs)
    return None

def vuln_complex_0250():
    """VULNERABLE - mogrify_like"""
    v = request.args.get('v')
    q = "SELECT * FROM t WHERE a = %s" % v
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0251():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0252():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0253():
    """VULNERABLE - repr_obfus"""
    r = repr(request.args.get('x'))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)
    return None

def vuln_complex_0254():
    """VULNERABLE - format_tuple1"""
    a = request.args.get('a')
    q = 'SELECT %s' % (a,)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0255():
    """VULNERABLE - subquery_positional"""
    sub = request.args.get('sub')
    q = "SELECT * FROM items WHERE id IN ({})".format(sub)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0256():
    """VULNERABLE - join_map_str"""
    vals = map(lambda x: request.args.get(x), ['a','b'])
    q = ''.join(vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0257():
    """VULNERABLE - subquery_positional"""
    sub = request.args.get('sub')
    q = "SELECT * FROM items WHERE id IN ({})".format(sub)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0258():
    """VULNERABLE - eval_build"""
    s = request.args.get('q')
    q = eval('"SELECT * FROM users WHERE name = ' + repr(s) + '"')
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0259():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0260():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0261():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0262():
    """VULNERABLE - django_raw_concat"""
    i = request.GET.get('id')
    qs = 'SELECT * FROM users WHERE id = ' + i
    User.objects.raw(qs)
    return None

def vuln_complex_0263():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0264():
    """VULNERABLE - concat_fragments"""
    parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']
    uid = request.args.get('id')
    q = parts[0] + parts[1] + parts[2] + uid
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0265():
    """VULNERABLE - mogrify_like"""
    v = request.args.get('v')
    q = "SELECT * FROM t WHERE a = %s" % v
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0266():
    """VULNERABLE - format_map"""
    fmt = 'SELECT {col} FROM users'
    col = request.args.get('col')
    q = fmt.format_map({'col': col})
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0267():
    """VULNERABLE - repr_obfus"""
    r = repr(request.args.get('x'))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)
    return None

def vuln_complex_0268():
    """VULNERABLE - global_flow"""
    global G
    G = request.args.get('g')
    # later read
    val = G
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE v=' + val)
    return None

def vuln_complex_0269():
    """VULNERABLE - union_triple"""
    x = request.args.get('q')
    q = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0270():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0271():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0272():
    """VULNERABLE - dict_attr"""
    d = {}
    d['k'] = request.args.get('k')
    val = d.get('k')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute(f"SELECT * FROM z WHERE a = '{val}'")
    return None

def vuln_complex_0273():
    """VULNERABLE - builder_class"""
    class B:
        def __init__(self): self.q='SELECT * FROM x WHERE '
        def add(self,c): self.q += c
    b=B()
    b.add('id=' + request.args.get('id'))
    sqlite3.connect('db.sqlite').cursor().execute(b.q)
    return None

def vuln_complex_0274():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0275():
    """VULNERABLE - order_by_obfus"""
    sort = request.args.get('sort')
    cols = '-'.join([sort])
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM products ORDER BY ' + cols)
    return None

def vuln_complex_0276():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0277():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0278():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0279():
    """VULNERABLE - eval_build"""
    s = request.args.get('q')
    q = eval('"SELECT * FROM users WHERE name = ' + repr(s) + '"')
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0280():
    """VULNERABLE - fstring_funccall"""
    uid = request.args.get('id')
    def wrap(x):
        return x
    c = sqlite3.connect('db.sqlite').cursor()
    c.execute(f"SELECT * FROM items WHERE owner = '{wrap(uid)}'")
    return None

def vuln_complex_0281():
    """VULNERABLE - builder_class"""
    class B:
        def __init__(self): self.q='SELECT * FROM x WHERE '
        def add(self,c): self.q += c
    b=B()
    b.add('id=' + request.args.get('id'))
    sqlite3.connect('db.sqlite').cursor().execute(b.q)
    return None

def vuln_complex_0282():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0283():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0284():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0285():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0286():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0287():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0288():
    """VULNERABLE - path_param"""
    p = request.view_args.get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM t WHERE id={p}")
    return None

def vuln_complex_0289():
    """VULNERABLE - union_triple"""
    x = request.args.get('q')
    q = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0290():
    """VULNERABLE - builder_class"""
    class B:
        def __init__(self): self.q='SELECT * FROM x WHERE '
        def add(self,c): self.q += c
    b=B()
    b.add('id=' + request.args.get('id'))
    sqlite3.connect('db.sqlite').cursor().execute(b.q)
    return None

def vuln_complex_0291():
    """VULNERABLE - fstring_nested"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {int(uid or 0)}")
    return None

def vuln_complex_0292():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0293():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0294():
    """VULNERABLE - mogrify_like"""
    v = request.args.get('v')
    q = "SELECT * FROM t WHERE a = %s" % v
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0295():
    """VULNERABLE - union_triple"""
    x = request.args.get('q')
    q = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0296():
    """VULNERABLE - union_triple"""
    x = request.args.get('q')
    q = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0297():
    """VULNERABLE - class_attr"""
    class Holder:
        pass
    h = Holder()
    h.v = request.args.get('v')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE x=' + h.v)
    return None

def vuln_complex_0298():
    """VULNERABLE - bytes_flow"""
    b = request.args.get('b').encode('utf-8').decode()
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE a=' + b)
    return None

def vuln_complex_0299():
    """VULNERABLE - getattr_setattr"""
    obj = {}
    setattr(obj, 'v', request.args.get('v'))
    val = getattr(obj, 'v')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM a WHERE b='{val}'")
    return None

def vuln_complex_0300():
    """VULNERABLE - global_flow"""
    global G
    G = request.args.get('g')
    # later read
    val = G
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE v=' + val)
    return None

def vuln_complex_0301():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0302():
    """VULNERABLE - repr_obfus"""
    r = repr(request.args.get('x'))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)
    return None

def vuln_complex_0303():
    """VULNERABLE - executemany_made"""
    pairs = [(request.args.get('a'),), (request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(%s)', pairs)
    return None

def vuln_complex_0304():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0305():
    """VULNERABLE - fstring_funccall"""
    uid = request.args.get('id')
    def wrap(x):
        return x
    c = sqlite3.connect('db.sqlite').cursor()
    c.execute(f"SELECT * FROM items WHERE owner = '{wrap(uid)}'")
    return None

def vuln_complex_0306():
    """VULNERABLE - concat_fragments"""
    parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']
    uid = request.args.get('id')
    q = parts[0] + parts[1] + parts[2] + uid
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0307():
    """VULNERABLE - class_attr"""
    class Holder:
        pass
    h = Holder()
    h.v = request.args.get('v')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE x=' + h.v)
    return None

def vuln_complex_0308():
    """VULNERABLE - format_tuple1"""
    a = request.args.get('a')
    q = 'SELECT %s' % (a,)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0309():
    """VULNERABLE - concat_fragments"""
    parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']
    uid = request.args.get('id')
    q = parts[0] + parts[1] + parts[2] + uid
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0310():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0311():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0312():
    """VULNERABLE - decorator_forward"""
    def deco(f):
        def wrapper(*a,**k): return f(*a,**k)
        return wrapper
    @deco
    def fn():
        x = request.args.get('q')
        sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE q=' + x)
    return None

def vuln_complex_0313():
    """VULNERABLE - getattr_setattr"""
    obj = {}
    setattr(obj, 'v', request.args.get('v'))
    val = getattr(obj, 'v')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM a WHERE b='{val}'")
    return None

def vuln_complex_0314():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0315():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0316():
    """VULNERABLE - builder_class"""
    class B:
        def __init__(self): self.q='SELECT * FROM x WHERE '
        def add(self,c): self.q += c
    b=B()
    b.add('id=' + request.args.get('id'))
    sqlite3.connect('db.sqlite').cursor().execute(b.q)
    return None

def vuln_complex_0317():
    """VULNERABLE - django_raw_concat"""
    i = request.GET.get('id')
    qs = 'SELECT * FROM users WHERE id = ' + i
    User.objects.raw(qs)
    return None

def vuln_complex_0318():
    """VULNERABLE - django_raw_concat"""
    i = request.GET.get('id')
    qs = 'SELECT * FROM users WHERE id = ' + i
    User.objects.raw(qs)
    return None

def vuln_complex_0319():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0320():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0321():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0322():
    """VULNERABLE - join_map_str"""
    vals = map(lambda x: request.args.get(x), ['a','b'])
    q = ''.join(vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0323():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0324():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0325():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0326():
    """VULNERABLE - fstring_funccall"""
    uid = request.args.get('id')
    def wrap(x):
        return x
    c = sqlite3.connect('db.sqlite').cursor()
    c.execute(f"SELECT * FROM items WHERE owner = '{wrap(uid)}'")
    return None

def vuln_complex_0327():
    """VULNERABLE - join_map"""
    vals = [request.args.get('a'), request.args.get('b')]
    conds = list(map(lambda v: f"x='{v}'", vals))
    q = ' OR '.join(conds)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0328():
    """VULNERABLE - concat_fragments"""
    parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']
    uid = request.args.get('id')
    q = parts[0] + parts[1] + parts[2] + uid
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0329():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0330():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0331():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0332():
    """VULNERABLE - repr_obfus"""
    r = repr(request.args.get('x'))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)
    return None

def vuln_complex_0333():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0334():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0335():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0336():
    """VULNERABLE - format_tuple1"""
    a = request.args.get('a')
    q = 'SELECT %s' % (a,)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0337():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0338():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0339():
    """VULNERABLE - mogrify_like"""
    v = request.args.get('v')
    q = "SELECT * FROM t WHERE a = %s" % v
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0340():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0341():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0342():
    """VULNERABLE - bytes_flow"""
    b = request.args.get('b').encode('utf-8').decode()
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE a=' + b)
    return None

def vuln_complex_0343():
    """VULNERABLE - concat_fragments"""
    parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']
    uid = request.args.get('id')
    q = parts[0] + parts[1] + parts[2] + uid
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0344():
    """VULNERABLE - bytes_flow"""
    b = request.args.get('b').encode('utf-8').decode()
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE a=' + b)
    return None

def vuln_complex_0345():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0346():
    """VULNERABLE - class_attr"""
    class Holder:
        pass
    h = Holder()
    h.v = request.args.get('v')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE x=' + h.v)
    return None

def vuln_complex_0347():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0348():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0349():
    """VULNERABLE - percent_tuple"""
    tbl = request.args.get('table')
    uid = request.args.get('id')
    q = "SELECT * FROM %s WHERE id = %s" % (tbl, uid)
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0350():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0351():
    """VULNERABLE - subquery_positional"""
    sub = request.args.get('sub')
    q = "SELECT * FROM items WHERE id IN ({})".format(sub)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0352():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0353():
    """VULNERABLE - getattr_setattr"""
    obj = {}
    setattr(obj, 'v', request.args.get('v'))
    val = getattr(obj, 'v')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM a WHERE b='{val}'")
    return None

def vuln_complex_0354():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0355():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0356():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0357():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0358():
    """VULNERABLE - path_param"""
    p = request.view_args.get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM t WHERE id={p}")
    return None

def vuln_complex_0359():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0360():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0361():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0362():
    """VULNERABLE - class_attr"""
    class Holder:
        pass
    h = Holder()
    h.v = request.args.get('v')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE x=' + h.v)
    return None

def vuln_complex_0363():
    """VULNERABLE - dict_attr"""
    d = {}
    d['k'] = request.args.get('k')
    val = d.get('k')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute(f"SELECT * FROM z WHERE a = '{val}'")
    return None

def vuln_complex_0364():
    """VULNERABLE - django_raw_concat"""
    i = request.GET.get('id')
    qs = 'SELECT * FROM users WHERE id = ' + i
    User.objects.raw(qs)
    return None

def vuln_complex_0365():
    """VULNERABLE - subquery_positional"""
    sub = request.args.get('sub')
    q = "SELECT * FROM items WHERE id IN ({})".format(sub)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0366():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0367():
    """VULNERABLE - executemany_made"""
    pairs = [(request.args.get('a'),), (request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(%s)', pairs)
    return None

def vuln_complex_0368():
    """VULNERABLE - format_tuple1"""
    a = request.args.get('a')
    q = 'SELECT %s' % (a,)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0369():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0370():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0371():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0372():
    """VULNERABLE - format_map"""
    fmt = 'SELECT {col} FROM users'
    col = request.args.get('col')
    q = fmt.format_map({'col': col})
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0373():
    """VULNERABLE - fstring_nested"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {int(uid or 0)}")
    return None

def vuln_complex_0374():
    """VULNERABLE - builder_class"""
    class B:
        def __init__(self): self.q='SELECT * FROM x WHERE '
        def add(self,c): self.q += c
    b=B()
    b.add('id=' + request.args.get('id'))
    sqlite3.connect('db.sqlite').cursor().execute(b.q)
    return None

def vuln_complex_0375():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0376():
    """VULNERABLE - global_flow"""
    global G
    G = request.args.get('g')
    # later read
    val = G
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE v=' + val)
    return None

def vuln_complex_0377():
    """VULNERABLE - fstring_nested"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {int(uid or 0)}")
    return None

def vuln_complex_0378():
    """VULNERABLE - django_raw_concat"""
    i = request.GET.get('id')
    qs = 'SELECT * FROM users WHERE id = ' + i
    User.objects.raw(qs)
    return None

def vuln_complex_0379():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0380():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0381():
    """VULNERABLE - format_map"""
    fmt = 'SELECT {col} FROM users'
    col = request.args.get('col')
    q = fmt.format_map({'col': col})
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0382():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0383():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0384():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0385():
    """VULNERABLE - path_param"""
    p = request.view_args.get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM t WHERE id={p}")
    return None

def vuln_complex_0386():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0387():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0388():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0389():
    """VULNERABLE - mogrify_like"""
    v = request.args.get('v')
    q = "SELECT * FROM t WHERE a = %s" % v
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0390():
    """VULNERABLE - subquery_positional"""
    sub = request.args.get('sub')
    q = "SELECT * FROM items WHERE id IN ({})".format(sub)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0391():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0392():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0393():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0394():
    """VULNERABLE - fstring_nested"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {int(uid or 0)}")
    return None

def vuln_complex_0395():
    """VULNERABLE - eval_build"""
    s = request.args.get('q')
    q = eval('"SELECT * FROM users WHERE name = ' + repr(s) + '"')
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0396():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0397():
    """VULNERABLE - repr_obfus"""
    r = repr(request.args.get('x'))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)
    return None

def vuln_complex_0398():
    """VULNERABLE - repr_obfus"""
    r = repr(request.args.get('x'))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)
    return None

def vuln_complex_0399():
    """VULNERABLE - path_param"""
    p = request.view_args.get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM t WHERE id={p}")
    return None

def vuln_complex_0400():
    """VULNERABLE - fstring_nested"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {int(uid or 0)}")
    return None

def vuln_complex_0401():
    """VULNERABLE - bytes_flow"""
    b = request.args.get('b').encode('utf-8').decode()
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE a=' + b)
    return None

def vuln_complex_0402():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0403():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0404():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0405():
    """VULNERABLE - format_tuple1"""
    a = request.args.get('a')
    q = 'SELECT %s' % (a,)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0406():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0407():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0408():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0409():
    """VULNERABLE - fstring_funccall"""
    uid = request.args.get('id')
    def wrap(x):
        return x
    c = sqlite3.connect('db.sqlite').cursor()
    c.execute(f"SELECT * FROM items WHERE owner = '{wrap(uid)}'")
    return None

def vuln_complex_0410():
    """VULNERABLE - percent_tuple"""
    tbl = request.args.get('table')
    uid = request.args.get('id')
    q = "SELECT * FROM %s WHERE id = %s" % (tbl, uid)
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0411():
    """VULNERABLE - dict_attr"""
    d = {}
    d['k'] = request.args.get('k')
    val = d.get('k')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute(f"SELECT * FROM z WHERE a = '{val}'")
    return None

def vuln_complex_0412():
    """VULNERABLE - executemany_made"""
    pairs = [(request.args.get('a'),), (request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(%s)', pairs)
    return None

def vuln_complex_0413():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0414():
    """VULNERABLE - decorator_forward"""
    def deco(f):
        def wrapper(*a,**k): return f(*a,**k)
        return wrapper
    @deco
    def fn():
        x = request.args.get('q')
        sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE q=' + x)
    return None

def vuln_complex_0415():
    """VULNERABLE - decorator_forward"""
    def deco(f):
        def wrapper(*a,**k): return f(*a,**k)
        return wrapper
    @deco
    def fn():
        x = request.args.get('q')
        sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE q=' + x)
    return None

def vuln_complex_0416():
    """VULNERABLE - bytes_flow"""
    b = request.args.get('b').encode('utf-8').decode()
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE a=' + b)
    return None

def vuln_complex_0417():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0418():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0419():
    """VULNERABLE - subquery_positional"""
    sub = request.args.get('sub')
    q = "SELECT * FROM items WHERE id IN ({})".format(sub)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0420():
    """VULNERABLE - fstring_nested"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {int(uid or 0)}")
    return None

def vuln_complex_0421():
    """VULNERABLE - executemany_made"""
    pairs = [(request.args.get('a'),), (request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(%s)', pairs)
    return None

def vuln_complex_0422():
    """VULNERABLE - dict_attr"""
    d = {}
    d['k'] = request.args.get('k')
    val = d.get('k')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute(f"SELECT * FROM z WHERE a = '{val}'")
    return None

def vuln_complex_0423():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0424():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0425():
    """VULNERABLE - fstring_nested"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {int(uid or 0)}")
    return None

def vuln_complex_0426():
    """VULNERABLE - format_map"""
    fmt = 'SELECT {col} FROM users'
    col = request.args.get('col')
    q = fmt.format_map({'col': col})
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0427():
    """VULNERABLE - fstring_nested"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {int(uid or 0)}")
    return None

def vuln_complex_0428():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0429():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0430():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0431():
    """VULNERABLE - fstring_funccall"""
    uid = request.args.get('id')
    def wrap(x):
        return x
    c = sqlite3.connect('db.sqlite').cursor()
    c.execute(f"SELECT * FROM items WHERE owner = '{wrap(uid)}'")
    return None

def vuln_complex_0432():
    """VULNERABLE - class_attr"""
    class Holder:
        pass
    h = Holder()
    h.v = request.args.get('v')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE x=' + h.v)
    return None

def vuln_complex_0433():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0434():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0435():
    """VULNERABLE - format_map"""
    fmt = 'SELECT {col} FROM users'
    col = request.args.get('col')
    q = fmt.format_map({'col': col})
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0436():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0437():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0438():
    """VULNERABLE - eval_build"""
    s = request.args.get('q')
    q = eval('"SELECT * FROM users WHERE name = ' + repr(s) + '"')
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0439():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0440():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0441():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0442():
    """VULNERABLE - executemany_made"""
    pairs = [(request.args.get('a'),), (request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(%s)', pairs)
    return None

def vuln_complex_0443():
    """VULNERABLE - dict_attr"""
    d = {}
    d['k'] = request.args.get('k')
    val = d.get('k')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute(f"SELECT * FROM z WHERE a = '{val}'")
    return None

def vuln_complex_0444():
    """VULNERABLE - path_param"""
    p = request.view_args.get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM t WHERE id={p}")
    return None

def vuln_complex_0445():
    """VULNERABLE - order_by_obfus"""
    sort = request.args.get('sort')
    cols = '-'.join([sort])
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM products ORDER BY ' + cols)
    return None

def vuln_complex_0446():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0447():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0448():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0449():
    """VULNERABLE - decorator_forward"""
    def deco(f):
        def wrapper(*a,**k): return f(*a,**k)
        return wrapper
    @deco
    def fn():
        x = request.args.get('q')
        sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE q=' + x)
    return None

def vuln_complex_0450():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0451():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0452():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0453():
    """VULNERABLE - join_map_str"""
    vals = map(lambda x: request.args.get(x), ['a','b'])
    q = ''.join(vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0454():
    """VULNERABLE - mogrify_like"""
    v = request.args.get('v')
    q = "SELECT * FROM t WHERE a = %s" % v
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0455():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0456():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0457():
    """VULNERABLE - repr_obfus"""
    r = repr(request.args.get('x'))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)
    return None

def vuln_complex_0458():
    """VULNERABLE - getattr_setattr"""
    obj = {}
    setattr(obj, 'v', request.args.get('v'))
    val = getattr(obj, 'v')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM a WHERE b='{val}'")
    return None

def vuln_complex_0459():
    """VULNERABLE - decorator_forward"""
    def deco(f):
        def wrapper(*a,**k): return f(*a,**k)
        return wrapper
    @deco
    def fn():
        x = request.args.get('q')
        sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE q=' + x)
    return None

def vuln_complex_0460():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0461():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0462():
    """VULNERABLE - percent_tuple"""
    tbl = request.args.get('table')
    uid = request.args.get('id')
    q = "SELECT * FROM %s WHERE id = %s" % (tbl, uid)
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0463():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0464():
    """VULNERABLE - format_map"""
    fmt = 'SELECT {col} FROM users'
    col = request.args.get('col')
    q = fmt.format_map({'col': col})
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0465():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0466():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0467():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0468():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0469():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0470():
    """VULNERABLE - percent_tuple"""
    tbl = request.args.get('table')
    uid = request.args.get('id')
    q = "SELECT * FROM %s WHERE id = %s" % (tbl, uid)
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0471():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0472():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0473():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0474():
    """VULNERABLE - percent_tuple"""
    tbl = request.args.get('table')
    uid = request.args.get('id')
    q = "SELECT * FROM %s WHERE id = %s" % (tbl, uid)
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0475():
    """VULNERABLE - fstring_nested"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {int(uid or 0)}")
    return None

def vuln_complex_0476():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0477():
    """VULNERABLE - dict_attr"""
    d = {}
    d['k'] = request.args.get('k')
    val = d.get('k')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute(f"SELECT * FROM z WHERE a = '{val}'")
    return None

def vuln_complex_0478():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0479():
    """VULNERABLE - join_map"""
    vals = [request.args.get('a'), request.args.get('b')]
    conds = list(map(lambda v: f"x='{v}'", vals))
    q = ' OR '.join(conds)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0480():
    """VULNERABLE - executemany_made"""
    pairs = [(request.args.get('a'),), (request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(%s)', pairs)
    return None

def vuln_complex_0481():
    """VULNERABLE - bytes_flow"""
    b = request.args.get('b').encode('utf-8').decode()
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE a=' + b)
    return None

def vuln_complex_0482():
    """VULNERABLE - class_attr"""
    class Holder:
        pass
    h = Holder()
    h.v = request.args.get('v')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE x=' + h.v)
    return None

def vuln_complex_0483():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0484():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0485():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0486():
    """VULNERABLE - path_param"""
    p = request.view_args.get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM t WHERE id={p}")
    return None

def vuln_complex_0487():
    """VULNERABLE - builder_class"""
    class B:
        def __init__(self): self.q='SELECT * FROM x WHERE '
        def add(self,c): self.q += c
    b=B()
    b.add('id=' + request.args.get('id'))
    sqlite3.connect('db.sqlite').cursor().execute(b.q)
    return None

def vuln_complex_0488():
    """VULNERABLE - format_map"""
    fmt = 'SELECT {col} FROM users'
    col = request.args.get('col')
    q = fmt.format_map({'col': col})
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0489():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0490():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0491():
    """VULNERABLE - order_by_obfus"""
    sort = request.args.get('sort')
    cols = '-'.join([sort])
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM products ORDER BY ' + cols)
    return None

def vuln_complex_0492():
    """VULNERABLE - union_triple"""
    x = request.args.get('q')
    q = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0493():
    """VULNERABLE - global_flow"""
    global G
    G = request.args.get('g')
    # later read
    val = G
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE v=' + val)
    return None

def vuln_complex_0494():
    """VULNERABLE - class_attr"""
    class Holder:
        pass
    h = Holder()
    h.v = request.args.get('v')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE x=' + h.v)
    return None

def vuln_complex_0495():
    """VULNERABLE - executemany_made"""
    pairs = [(request.args.get('a'),), (request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(%s)', pairs)
    return None

def vuln_complex_0496():
    """VULNERABLE - environ_taint"""
    ip = request.environ.get('REMOTE_ADDR')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)
    return None

def vuln_complex_0497():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0498():
    """VULNERABLE - fstring_funccall"""
    uid = request.args.get('id')
    def wrap(x):
        return x
    c = sqlite3.connect('db.sqlite').cursor()
    c.execute(f"SELECT * FROM items WHERE owner = '{wrap(uid)}'")
    return None

def vuln_complex_0499():
    """VULNERABLE - getattr_setattr"""
    obj = {}
    setattr(obj, 'v', request.args.get('v'))
    val = getattr(obj, 'v')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM a WHERE b='{val}'")
    return None

def vuln_complex_0500():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0501():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0502():
    """VULNERABLE - join_map_str"""
    vals = map(lambda x: request.args.get(x), ['a','b'])
    q = ''.join(vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0503():
    """VULNERABLE - dict_attr"""
    d = {}
    d['k'] = request.args.get('k')
    val = d.get('k')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute(f"SELECT * FROM z WHERE a = '{val}'")
    return None

def vuln_complex_0504():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0505():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0506():
    """VULNERABLE - fstring_funccall"""
    uid = request.args.get('id')
    def wrap(x):
        return x
    c = sqlite3.connect('db.sqlite').cursor()
    c.execute(f"SELECT * FROM items WHERE owner = '{wrap(uid)}'")
    return None

def vuln_complex_0507():
    """VULNERABLE - join_map"""
    vals = [request.args.get('a'), request.args.get('b')]
    conds = list(map(lambda v: f"x='{v}'", vals))
    q = ' OR '.join(conds)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0508():
    """VULNERABLE - getattr_setattr"""
    obj = {}
    setattr(obj, 'v', request.args.get('v'))
    val = getattr(obj, 'v')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM a WHERE b='{val}'")
    return None

def vuln_complex_0509():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0510():
    """VULNERABLE - mogrify_like"""
    v = request.args.get('v')
    q = "SELECT * FROM t WHERE a = %s" % v
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0511():
    """VULNERABLE - executemany_made"""
    pairs = [(request.args.get('a'),), (request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(%s)', pairs)
    return None

def vuln_complex_0512():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0513():
    """VULNERABLE - union_triple"""
    x = request.args.get('q')
    q = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0514():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0515():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0516():
    """VULNERABLE - subquery_positional"""
    sub = request.args.get('sub')
    q = "SELECT * FROM items WHERE id IN ({})".format(sub)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0517():
    """VULNERABLE - repr_obfus"""
    r = repr(request.args.get('x'))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)
    return None

def vuln_complex_0518():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0519():
    """VULNERABLE - percent_tuple"""
    tbl = request.args.get('table')
    uid = request.args.get('id')
    q = "SELECT * FROM %s WHERE id = %s" % (tbl, uid)
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0520():
    """VULNERABLE - join_map_str"""
    vals = map(lambda x: request.args.get(x), ['a','b'])
    q = ''.join(vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0521():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0522():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0523():
    """VULNERABLE - repr_obfus"""
    r = repr(request.args.get('x'))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)
    return None

def vuln_complex_0524():
    """VULNERABLE - loop_accumulate"""
    q='SELECT * FROM t WHERE '
    for k in ['a','b']:
        v = request.args.get(k)
        q += f"{k}='{v}' OR "
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0525():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0526():
    """VULNERABLE - join_map_str"""
    vals = map(lambda x: request.args.get(x), ['a','b'])
    q = ''.join(vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0527():
    """VULNERABLE - format_tuple1"""
    a = request.args.get('a')
    q = 'SELECT %s' % (a,)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0528():
    """VULNERABLE - fstring_funccall"""
    uid = request.args.get('id')
    def wrap(x):
        return x
    c = sqlite3.connect('db.sqlite').cursor()
    c.execute(f"SELECT * FROM items WHERE owner = '{wrap(uid)}'")
    return None

def vuln_complex_0529():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0530():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0531():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0532():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0533():
    """VULNERABLE - global_flow"""
    global G
    G = request.args.get('g')
    # later read
    val = G
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE v=' + val)
    return None

def vuln_complex_0534():
    """VULNERABLE - list_index"""
    arr = [request.args.get('i')]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])
    return None

def vuln_complex_0535():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0536():
    """VULNERABLE - concat_fragments"""
    parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']
    uid = request.args.get('id')
    q = parts[0] + parts[1] + parts[2] + uid
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0537():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0538():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0539():
    """VULNERABLE - mogrify_like"""
    v = request.args.get('v')
    q = "SELECT * FROM t WHERE a = %s" % v
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0540():
    """VULNERABLE - union_triple"""
    x = request.args.get('q')
    q = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0541():
    """VULNERABLE - concat_fragments"""
    parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']
    uid = request.args.get('id')
    q = parts[0] + parts[1] + parts[2] + uid
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0542():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0543():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0544():
    """VULNERABLE - decorator_forward"""
    def deco(f):
        def wrapper(*a,**k): return f(*a,**k)
        return wrapper
    @deco
    def fn():
        x = request.args.get('q')
        sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE q=' + x)
    return None

def vuln_complex_0545():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0546():
    """VULNERABLE - subquery_positional"""
    sub = request.args.get('sub')
    q = "SELECT * FROM items WHERE id IN ({})".format(sub)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0547():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0548():
    """VULNERABLE - eval_build"""
    s = request.args.get('q')
    q = eval('"SELECT * FROM users WHERE name = ' + repr(s) + '"')
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0549():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0550():
    """VULNERABLE - getattr_setattr"""
    obj = {}
    setattr(obj, 'v', request.args.get('v'))
    val = getattr(obj, 'v')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM a WHERE b='{val}'")
    return None

def vuln_complex_0551():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0552():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0553():
    """VULNERABLE - mogrify_like"""
    v = request.args.get('v')
    q = "SELECT * FROM t WHERE a = %s" % v
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0554():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0555():
    """VULNERABLE - header_join"""
    ua = request.headers.get('User-Agent')
    vals = ['a', ua]
    sqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\'' + vals[1] + "')")
    return None

def vuln_complex_0556():
    """VULNERABLE - subquery_positional"""
    sub = request.args.get('sub')
    q = "SELECT * FROM items WHERE id IN ({})".format(sub)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0557():
    """VULNERABLE - repr_obfus"""
    r = repr(request.args.get('x'))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)
    return None

def vuln_complex_0558():
    """VULNERABLE - union_triple"""
    x = request.args.get('q')
    q = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0559():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0560():
    """VULNERABLE - string_template"""
    from string import Template
    t = Template('SELECT * FROM users WHERE name = $name')
    q = t.substitute(name=request.args.get('name'))
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0561():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0562():
    """VULNERABLE - sqlalchemy_text_raw"""
    s = request.args.get('s')
    from sqlalchemy import text
    q = text(f"SELECT * FROM users WHERE name = '{s}'")
    engine = None
    # assume engine.execute(q) somewhere
    return None

def vuln_complex_0563():
    """VULNERABLE - class_attr"""
    class Holder:
        pass
    h = Holder()
    h.v = request.args.get('v')
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().execute('SELECT * FROM t WHERE x=' + h.v)
    return None

def vuln_complex_0564():
    """VULNERABLE - exec_fstring"""
    s = request.args.get('s')
    exec('q = f"SELECT * FROM u WHERE x={s}"')
    sqlite3.connect('db.sqlite').cursor().execute('q')
    return None

def vuln_complex_0565():
    """VULNERABLE - format_tuple1"""
    a = request.args.get('a')
    q = 'SELECT %s' % (a,)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0566():
    """VULNERABLE - executemany_made"""
    pairs = [(request.args.get('a'),), (request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(%s)', pairs)
    return None

def vuln_complex_0567():
    """VULNERABLE - executescript_body"""
    sql_scripts = request.get_data(as_text=True)
    conn = sqlite3.connect('db.sqlite')
    conn.executescript(sql_scripts)
    return None

def vuln_complex_0568():
    """VULNERABLE - bytes_flow"""
    b = request.args.get('b').encode('utf-8').decode()
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE a=' + b)
    return None

def vuln_complex_0569():
    """VULNERABLE - repr_obfus"""
    r = repr(request.args.get('x'))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)
    return None

def vuln_complex_0570():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0571():
    """VULNERABLE - percent_mapping"""
    m = {'t': request.args.get('t')}
    q = '%(t)s' % m
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)
    return None

def vuln_complex_0572():
    """VULNERABLE - subquery_positional"""
    sub = request.args.get('sub')
    q = "SELECT * FROM items WHERE id IN ({})".format(sub)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0573():
    """VULNERABLE - fstring_nested"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {int(uid or 0)}")
    return None

def vuln_complex_0574():
    """VULNERABLE - chained_calls"""
    def a(x): return x
    def b(y): return y
    def c(z): return z
    val = a(b(c(request.args.get('id'))))
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)
    return None

def vuln_complex_0575():
    """VULNERABLE - getattr_setattr"""
    obj = {}
    setattr(obj, 'v', request.args.get('v'))
    val = getattr(obj, 'v')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM a WHERE b='{val}'")
    return None

def vuln_complex_0576():
    """VULNERABLE - join_map"""
    vals = [request.args.get('a'), request.args.get('b')]
    conds = list(map(lambda v: f"x='{v}'", vals))
    q = ' OR '.join(conds)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0577():
    """VULNERABLE - order_by_obfus"""
    sort = request.args.get('sort')
    cols = '-'.join([sort])
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM products ORDER BY ' + cols)
    return None

def vuln_complex_0578():
    """VULNERABLE - format_map"""
    fmt = 'SELECT {col} FROM users'
    col = request.args.get('col')
    q = fmt.format_map({'col': col})
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0579():
    """VULNERABLE - mogrify_like"""
    v = request.args.get('v')
    q = "SELECT * FROM t WHERE a = %s" % v
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0580():
    """VULNERABLE - join_comp"""
    vals = [request.args.get(k) for k in ('a','b')]
    q = ' UNION '.join(f"(SELECT * FROM t WHERE c='{v}')" for v in vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0581():
    """VULNERABLE - json_nested"""
    j = request.json
    v = j.get('user',{}).get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM users WHERE id={v}")
    return None

def vuln_complex_0582():
    """VULNERABLE - format_map"""
    fmt = 'SELECT {col} FROM users'
    col = request.args.get('col')
    q = fmt.format_map({'col': col})
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0583():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0584():
    """VULNERABLE - join_map_str"""
    vals = map(lambda x: request.args.get(x), ['a','b'])
    q = ''.join(vals)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0585():
    """VULNERABLE - cookie_taint"""
    cval = request.cookies.get('x')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)
    return None

def vuln_complex_0586():
    """VULNERABLE - path_param"""
    p = request.view_args.get('id')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM t WHERE id={p}")
    return None

def vuln_complex_0587():
    """VULNERABLE - percent_tuple"""
    tbl = request.args.get('table')
    uid = request.args.get('id')
    q = "SELECT * FROM %s WHERE id = %s" % (tbl, uid)
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0588():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0589():
    """VULNERABLE - getattr_setattr"""
    obj = {}
    setattr(obj, 'v', request.args.get('v'))
    val = getattr(obj, 'v')
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT * FROM a WHERE b='{val}'")
    return None

def vuln_complex_0590():
    """VULNERABLE - bytes_flow"""
    b = request.args.get('b').encode('utf-8').decode()
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE a=' + b)
    return None

def vuln_complex_0591():
    """VULNERABLE - format_attr"""
    o = request
    col = o.args.get('c')
    q = 'SELECT %s FROM users' % col
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0592():
    """VULNERABLE - global_flow"""
    global G
    G = request.args.get('g')
    # later read
    val = G
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE v=' + val)
    return None

def vuln_complex_0593():
    """VULNERABLE - format_named"""
    params = {'col': request.args.get('c')}
    q = 'SELECT {col} FROM users'.format_map(params)
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0594():
    """VULNERABLE - decorator_forward"""
    def deco(f):
        def wrapper(*a,**k): return f(*a,**k)
        return wrapper
    @deco
    def fn():
        x = request.args.get('q')
        sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE q=' + x)
    return None

def vuln_complex_0595():
    """VULNERABLE - reduce_build"""
    from functools import reduce
    vals=[request.args.get('a'),request.args.get('b')]
    q = reduce(lambda acc,v: acc + ' OR ' + v, vals)
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)
    return None

def vuln_complex_0596():
    """VULNERABLE - second_order_store"""
    v = request.args.get('x')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('INSERT INTO store(val) VALUES(?)', (v,))
    row = c.execute('SELECT val FROM store').fetchone()[0]
    c.execute(f"SELECT * FROM users WHERE name = '{row}'")
    return None

def vuln_complex_0597():
    """VULNERABLE - union_triple"""
    x = request.args.get('q')
    q = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0598():
    """VULNERABLE - fstring_funccall"""
    uid = request.args.get('id')
    def wrap(x):
        return x
    c = sqlite3.connect('db.sqlite').cursor()
    c.execute(f"SELECT * FROM items WHERE owner = '{wrap(uid)}'")
    return None

def vuln_complex_0599():
    """VULNERABLE - format_map"""
    fmt = 'SELECT {col} FROM users'
    col = request.args.get('col')
    q = fmt.format_map({'col': col})
    conn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)
    return None

def vuln_complex_0600():
    """VULNERABLE - eval_build"""
    s = request.args.get('q')
    q = eval('"SELECT * FROM users WHERE name = ' + repr(s) + '"')
    sqlite3.connect('db.sqlite').cursor().execute(q)
    return None

def vuln_complex_0601():
    """VULNERABLE - order_by_obfus"""
    sort = request.args.get('sort')
    cols = '-'.join([sort])
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM products ORDER BY ' + cols)
    return None

def safe_complex_0602():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0603():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0604():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0605():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0606():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0607():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0608():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0609():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0610():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0611():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0612():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0613():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0614():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0615():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0616():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0617():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0618():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0619():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0620():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0621():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0622():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0623():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0624():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0625():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0626():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0627():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0628():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0629():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0630():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0631():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0632():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0633():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0634():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0635():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0636():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0637():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0638():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0639():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0640():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0641():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0642():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0643():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0644():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0645():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0646():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0647():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0648():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0649():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0650():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0651():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0652():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0653():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0654():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0655():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0656():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0657():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0658():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0659():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0660():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0661():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0662():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0663():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0664():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0665():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0666():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0667():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0668():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0669():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0670():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0671():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0672():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0673():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0674():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0675():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0676():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0677():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0678():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0679():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0680():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0681():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0682():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0683():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0684():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0685():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0686():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0687():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0688():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0689():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0690():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0691():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0692():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0693():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0694():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0695():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0696():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0697():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0698():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0699():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0700():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0701():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0702():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0703():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0704():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0705():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0706():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0707():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0708():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0709():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0710():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0711():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0712():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0713():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0714():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0715():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0716():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0717():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0718():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0719():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0720():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0721():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0722():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0723():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0724():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0725():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0726():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0727():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0728():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0729():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0730():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0731():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0732():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0733():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0734():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0735():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0736():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0737():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0738():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0739():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0740():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0741():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0742():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0743():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0744():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0745():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0746():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0747():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0748():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0749():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0750():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0751():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0752():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0753():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0754():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0755():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0756():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0757():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0758():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0759():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0760():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0761():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0762():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0763():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0764():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0765():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0766():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0767():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0768():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0769():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0770():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0771():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0772():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0773():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0774():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0775():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0776():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0777():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0778():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0779():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0780():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0781():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0782():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0783():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0784():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0785():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0786():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0787():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0788():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0789():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0790():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0791():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0792():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0793():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0794():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0795():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0796():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0797():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0798():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0799():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0800():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0801():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0802():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0803():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0804():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0805():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0806():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0807():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0808():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0809():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0810():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0811():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0812():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0813():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0814():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0815():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0816():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0817():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0818():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0819():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0820():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0821():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0822():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0823():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0824():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0825():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0826():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0827():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0828():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0829():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0830():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0831():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0832():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0833():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0834():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0835():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0836():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0837():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0838():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0839():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0840():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0841():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0842():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0843():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0844():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0845():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0846():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0847():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0848():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0849():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0850():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0851():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0852():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0853():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0854():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0855():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0856():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0857():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0858():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0859():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0860():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0861():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0862():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0863():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0864():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0865():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0866():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0867():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0868():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0869():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0870():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0871():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0872():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0873():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0874():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0875():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0876():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0877():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0878():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0879():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0880():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0881():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0882():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0883():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0884():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0885():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0886():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0887():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0888():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0889():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0890():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0891():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0892():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0893():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0894():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0895():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0896():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0897():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0898():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0899():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0900():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0901():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0902():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0903():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0904():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0905():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0906():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0907():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0908():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0909():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0910():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0911():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0912():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0913():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0914():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0915():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0916():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0917():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0918():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0919():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0920():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0921():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0922():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0923():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0924():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0925():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0926():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0927():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0928():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0929():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0930():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0931():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0932():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0933():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0934():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0935():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0936():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0937():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0938():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0939():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0940():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0941():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0942():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0943():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0944():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0945():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0946():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0947():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0948():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0949():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0950():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0951():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0952():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0953():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0954():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0955():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0956():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0957():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0958():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0959():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0960():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0961():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0962():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0963():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0964():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0965():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0966():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0967():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0968():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0969():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0970():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0971():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0972():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0973():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0974():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0975():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_0976():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0977():
    """SAFE - safe_builder"""
    allowed = {'id','name'}
    col = request.args.get('c')
    if col in allowed:
        sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0978():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0979():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0980():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0981():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0982():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0983():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0984():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0985():
    """SAFE - int_cast"""
    uid = request.args.get('id')
    try:
        uid_i = int(uid)
    except Exception:
        uid_i = 0
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))
    return None

def safe_complex_0986():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0987():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0988():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0989():
    """SAFE - whitelist_col"""
    col = request.args.get('c')
    if col not in ('id','name'):
        col = 'id'
    sqlite3.connect('db.sqlite').cursor().execute(f"SELECT {col} FROM users")
    return None

def safe_complex_0990():
    """SAFE - log_only"""
    x = request.args.get('x')
    print('LOG:', x)
    return x
    return None

def safe_complex_0991():
    """SAFE - param_safe"""
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))
    return None

def safe_complex_0992():
    """SAFE - django_orm_filter"""
    uid = request.GET.get('id')
    # User.objects.filter(id=uid)  # safe ORM usage
    return None

def safe_complex_0993():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0994():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0995():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0996():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

def safe_complex_0997():
    """SAFE - sqlalchemy_bind"""
    from sqlalchemy import text
    s = request.args.get('s')
    q = text('SELECT * FROM users WHERE name = :name')
    # q = q.bindparams(name=s)  # assume bind used later
    return None

def safe_complex_0998():
    """SAFE - regex_fullmatch"""
    import re
    d = request.args.get('d')
    if not re.fullmatch(r'\d+', d):
        raise ValueError('bad')
    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))
    return None

def safe_complex_0999():
    """SAFE - mixed_but_safe"""
    s = request.args.get('s')
    q = 'SELECT * FROM users WHERE name = ?'
    sqlite3.connect('db.sqlite').cursor().execute(q, (s,))
    return None

def safe_complex_1000():
    """SAFE - executemany_safe"""
    rows = [(request.args.get('a'),),(request.args.get('b'),)]
    conn = sqlite3.connect('db.sqlite')
    conn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)
    return None

