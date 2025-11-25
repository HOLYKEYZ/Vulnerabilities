# Retry generating the complex file with 1000 functions.
OUT_PATH = "C:\Users\Ren-pc\Desktop\certion versions\certion - security scan\sqli\vulnerabilities.py"

import random, textwrap, os

TOTAL = 1000
VULN_COUNT = 601
SAFE_COUNT = TOTAL - VULN_COUNT

random.seed(20251120)

vuln_templates = [
    ("fstring_nested", "uid = request.args.get('id')\nconn = sqlite3.connect('db.sqlite')\nc = conn.cursor()\nc.execute(f\"SELECT * FROM users WHERE id = {int(uid or 0)}\")"),
    ("fstring_funccall", "uid = request.args.get('id')\ndef wrap(x):\n    return x\nc = sqlite3.connect('db.sqlite').cursor()\nc.execute(f\"SELECT * FROM items WHERE owner = '{wrap(uid)}'\")"),
    ("concat_fragments", "parts = ['SELECT *', ' FROM orders WHERE ', 'user_id = ']\nuid = request.args.get('id')\nq = parts[0] + parts[1] + parts[2] + uid\nsqlite3.connect('db.sqlite').cursor().execute(q)"),
    ("percent_tuple", "tbl = request.args.get('table')\nuid = request.args.get('id')\nq = \"SELECT * FROM %s WHERE id = %s\" % (tbl, uid)\nconn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)"),
    ("format_map", "fmt = 'SELECT {col} FROM users'\ncol = request.args.get('col')\nq = fmt.format_map({'col': col})\nconn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)"),
    ("join_map", "vals = [request.args.get('a'), request.args.get('b')]\nconds = list(map(lambda v: f\"x='{v}'\", vals))\nq = ' OR '.join(conds)\nsqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)"),
    ("executescript_body", "sql_scripts = request.get_data(as_text=True)\nconn = sqlite3.connect('db.sqlite')\nconn.executescript(sql_scripts)"),
    ("sqlalchemy_text_raw", "s = request.args.get('s')\nfrom sqlalchemy import text\nq = text(f\"SELECT * FROM users WHERE name = '{s}'\")\nengine = None\n# assume engine.execute(q) somewhere"),
    ("django_raw_concat", "i = request.GET.get('id')\nqs = 'SELECT * FROM users WHERE id = ' + i\nUser.objects.raw(qs)"),
    ("order_by_obfus", "sort = request.args.get('sort')\ncols = '-'.join([sort])\nsqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM products ORDER BY ' + cols)"),
    ("union_triple", "x = request.args.get('q')\nq = '''SELECT id FROM logs WHERE msg = '%s' UNION SELECT secret FROM secrets''' % x\nsqlite3.connect('db.sqlite').cursor().execute(q)"),
    ("subquery_positional", "sub = request.args.get('sub')\nq = \"SELECT * FROM items WHERE id IN ({})\".format(sub)\nsqlite3.connect('db.sqlite').cursor().execute(q)"),
    ("header_join", "ua = request.headers.get('User-Agent')\nvals = ['a', ua]\nsqlite3.connect('db.sqlite').cursor().execute('INSERT INTO analytics(v) VALUES(\\'' + vals[1] + \"')\")"),
    ("second_order_store", "v = request.args.get('x')\nconn = sqlite3.connect('db.sqlite')\nc = conn.cursor()\nc.execute('INSERT INTO store(val) VALUES(?)', (v,))\nrow = c.execute('SELECT val FROM store').fetchone()[0]\nc.execute(f\"SELECT * FROM users WHERE name = '{row}'\")"),
    ("dict_attr", "d = {}\nd['k'] = request.args.get('k')\nval = d.get('k')\nconn = sqlite3.connect('db.sqlite')\nconn.cursor().execute(f\"SELECT * FROM z WHERE a = '{val}'\")"),
    ("class_attr", "class Holder:\n    pass\nh = Holder()\nh.v = request.args.get('v')\nconn = sqlite3.connect('db.sqlite')\nconn.cursor().execute('SELECT * FROM t WHERE x=' + h.v)"),
    ("list_index", "arr = [request.args.get('i')]\nconn = sqlite3.connect('db.sqlite')\nconn.cursor().execute('SELECT * FROM t WHERE id=' + arr[0])"),
    ("getattr_setattr", "obj = {}\nsetattr(obj, 'v', request.args.get('v'))\nval = getattr(obj, 'v')\nsqlite3.connect('db.sqlite').cursor().execute(f\"SELECT * FROM a WHERE b='{val}'\")"),
    ("eval_build", "s = request.args.get('q')\nq = eval('\"SELECT * FROM users WHERE name = ' + repr(s) + '\"')\nsqlite3.connect('db.sqlite').cursor().execute(q)"),
    ("string_template", "from string import Template\nt = Template('SELECT * FROM users WHERE name = $name')\nq = t.substitute(name=request.args.get('name'))\nsqlite3.connect('db.sqlite').cursor().execute(q)"),
    ("percent_mapping", "m = {'t': request.args.get('t')}\nq = '%(t)s' % m\nsqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM ' + q)"),
    ("format_attr", "o = request\ncol = o.args.get('c')\nq = 'SELECT %s FROM users' % col\nsqlite3.connect('db.sqlite').cursor().execute(q)"),
    ("join_comp", "vals = [request.args.get(k) for k in ('a','b')]\nq = ' UNION '.join(f\"(SELECT * FROM t WHERE c='{v}')\" for v in vals)\nsqlite3.connect('db.sqlite').cursor().execute(q)"),
    ("builder_class", "class B:\n    def __init__(self): self.q='SELECT * FROM x WHERE '\n    def add(self,c): self.q += c\nb=B()\nb.add('id=' + request.args.get('id'))\nsqlite3.connect('db.sqlite').cursor().execute(b.q)"),
    ("executemany_made", "pairs = [(request.args.get('a'),), (request.args.get('b'),)]\nconn = sqlite3.connect('db.sqlite')\nconn.cursor().executemany('INSERT INTO t(val) VALUES(%s)', pairs)"),
    ("mogrify_like", "v = request.args.get('v')\nq = \"SELECT * FROM t WHERE a = %s\" % v\nconn = sqlite3.connect('db.sqlite'); conn.cursor().execute(q)"),
    ("format_named", "params = {'col': request.args.get('c')}\nq = 'SELECT {col} FROM users'.format_map(params)\nsqlite3.connect('db.sqlite').cursor().execute(q)"),
    ("chained_calls", "def a(x): return x\ndef b(y): return y\ndef c(z): return z\nval = a(b(c(request.args.get('id'))))\nsqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM u WHERE id=' + val)"),
    ("json_nested", "j = request.json\nv = j.get('user',{}).get('id')\nsqlite3.connect('db.sqlite').cursor().execute(f\"SELECT * FROM users WHERE id={v}\")"),
    ("cookie_taint", "cval = request.cookies.get('x')\nsqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE v=' + cval)"),
    ("environ_taint", "ip = request.environ.get('REMOTE_ADDR')\nsqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM s WHERE ip=' + ip)"),
    ("path_param", "p = request.view_args.get('id')\nsqlite3.connect('db.sqlite').cursor().execute(f\"SELECT * FROM t WHERE id={p}\")"),
    ("join_map_str", "vals = map(lambda x: request.args.get(x), ['a','b'])\nq = ''.join(vals)\nsqlite3.connect('db.sqlite').cursor().execute(q)"),
    ("repr_obfus", "r = repr(request.args.get('x'))\nsqlite3.connect('db.sqlite').cursor().execute('SELECT ' + r)"),
    ("format_tuple1", "a = request.args.get('a')\nq = 'SELECT %s' % (a,)\nsqlite3.connect('db.sqlite').cursor().execute(q)"),
    ("global_flow", "global G\nG = request.args.get('g')\n# later read\nval = G\nsqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE v=' + val)"),
    ("decorator_forward", "def deco(f):\n    def wrapper(*a,**k): return f(*a,**k)\n    return wrapper\n@deco\ndef fn():\n    x = request.args.get('q')\n    sqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE q=' + x)"),
    ("exec_fstring", "s = request.args.get('s')\nexec('q = f\"SELECT * FROM u WHERE x={s}\"')\nsqlite3.connect('db.sqlite').cursor().execute('q')"),
    ("reduce_build", "from functools import reduce\nvals=[request.args.get('a'),request.args.get('b')]\nq = reduce(lambda acc,v: acc + ' OR ' + v, vals)\nsqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE ' + q)"),
    ("bytes_flow", "b = request.args.get('b').encode('utf-8').decode()\nsqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE a=' + b)"),
    ("loop_accumulate", "q='SELECT * FROM t WHERE '\nfor k in ['a','b']:\n    v = request.args.get(k)\n    q += f\"{k}='{v}' OR \"\nsqlite3.connect('db.sqlite').cursor().execute(q)"),
]

safe_templates = [
    ("param_safe", "uid = request.args.get('id')\nconn = sqlite3.connect('db.sqlite')\nc = conn.cursor()\nc.execute('SELECT * FROM users WHERE id = ?', (int(uid) if uid and uid.isdigit() else None,))"),
    ("int_cast", "uid = request.args.get('id')\ntry:\n    uid_i = int(uid)\nexcept Exception:\n    uid_i = 0\nsqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM users WHERE id = ?', (uid_i,))"),
    ("whitelist_col", "col = request.args.get('c')\nif col not in ('id','name'):\n    col = 'id'\nsqlite3.connect('db.sqlite').cursor().execute(f\"SELECT {col} FROM users\")"),
    ("sqlalchemy_bind", "from sqlalchemy import text\ns = request.args.get('s')\nq = text('SELECT * FROM users WHERE name = :name')\n# q = q.bindparams(name=s)  # assume bind used later"),
    ("django_orm_filter", "uid = request.GET.get('id')\n# User.objects.filter(id=uid)  # safe ORM usage"),
    ("regex_fullmatch", "import re\nd = request.args.get('d')\nif not re.fullmatch(r'\\d+', d):\n    raise ValueError('bad')\nsqlite3.connect('db.sqlite').cursor().execute('SELECT * FROM t WHERE id = ?', (int(d),))"),
    ("executemany_safe", "rows = [(request.args.get('a'),),(request.args.get('b'),)]\nconn = sqlite3.connect('db.sqlite')\nconn.cursor().executemany('INSERT INTO t(val) VALUES(?)', rows)"),
    ("safe_builder", "allowed = {'id','name'}\ncol = request.args.get('c')\nif col in allowed:\n    sqlite3.connect('db.sqlite').cursor().execute(f\"SELECT {col} FROM users\")"),
    ("log_only", "x = request.args.get('x')\nprint('LOG:', x)\nreturn x"),
    ("mixed_but_safe", "s = request.args.get('s')\nq = 'SELECT * FROM users WHERE name = ?'\nsqlite3.connect('db.sqlite').cursor().execute(q, (s,))"),
]

UPLOADED_FILE_PATH = "/mnt/data/scan6.py"

# write the file
with open(OUT_PATH, "w", encoding="utf-8") as f:
    f.write("# Auto-generated complex SQLi challenge corpus\n")
    f.write("# Total functions: {}\n".format(TOTAL))
    f.write("# Vulnerable: {}  (odd)\n".format(VULN_COUNT))
    f.write("# Safe/decoys: {}  (odd)\n".format(SAFE_COUNT))
    f.write("# Reference uploaded scanner source: {}\n".format(UPLOADED_FILE_PATH))
    f.write("from flask import request\nimport sqlite3\n\ntry:\n    from sqlalchemy import text\nexcept Exception:\n    pass\n\ntry:\n    from django.contrib.auth.models import User\nexcept Exception:\n    pass\n\n")

# append functions
func_index = 1
with open(OUT_PATH, "a", encoding="utf-8") as f:
    for i in range(VULN_COUNT):
        tpl_name, tpl_code = random.choice(vuln_templates)
        name = f"vuln_complex_{func_index:04d}"
        f.write(f"def {name}():\n    \"\"\"VULNERABLE - {tpl_name}\"\"\"\n")
        f.write(textwrap.indent(tpl_code, "    ") + "\n    return None\n\n")
        func_index += 1

    for i in range(SAFE_COUNT):
        tpl_name, tpl_code = random.choice(safe_templates)
        name = f"safe_complex_{func_index:04d}"
        f.write(f"def {name}():\n    \"\"\"SAFE - {tpl_name}\"\"\"\n")
        f.write(textwrap.indent(tpl_code, "    ") + "\n    return None\n\n")
        func_index += 1

OUT_PATH

