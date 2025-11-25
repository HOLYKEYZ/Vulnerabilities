from flask import request
import sqlite3

# -------------------------------------------------------------------------
# THE 29 MISSING "SECOND-ORDER" VULNERABILITIES
# -------------------------------------------------------------------------

def sample_vuln_0223():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    # 1. Poisoning (Scanner sees this as SAFE because it is parameterized)
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    # 2. Retrieval (Scanner sees this as SAFE because it comes from DB)
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    # 3. Injection (Scanner ignores this because it thinks 'row' is safe)
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
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

def sample_vuln_0161():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
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

def sample_vuln_0157():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
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

def sample_vuln_0107():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
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

def sample_vuln_0165():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
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

def sample_vuln_0351():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
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

def sample_vuln_0399():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
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

def sample_vuln_0210():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
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

def sample_vuln_0274():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
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

def sample_vuln_0130():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
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

def sample_vuln_0208():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
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

def sample_vuln_0217():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
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

def sample_vuln_0291():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
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

def sample_vuln_0328():
    """VULNERABLE - second_order"""
    tainted = request.args.get('data')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    cur.execute('INSERT INTO temp_store(val) VALUES(?)', (tainted,))
    row = cur.execute('SELECT val FROM temp_store').fetchone()[0]
    cur.execute(f"SELECT * FROM users WHERE name = '{row}'")  # second-order SQLi
    return None
