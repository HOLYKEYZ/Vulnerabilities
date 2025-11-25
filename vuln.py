from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import sqlite3
import secrets
import hashlib
import os
import subprocess

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

def init_db():
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS posts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  title TEXT NOT NULL, 
                  content TEXT NOT NULL,
                  author TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL)''')
    
    admin_hash = hashlib.sha256('admin123'.encode()).hexdigest()
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
              ('admin', admin_hash))
    
    c.execute("INSERT OR IGNORE INTO posts (title, content, author) VALUES (?, ?, ?)",
              ('Welcome', 'Welcome to our blog platform!', 'admin'))
    c.execute("INSERT OR IGNORE INTO posts (title, content, author) VALUES (?, ?, ?)",
              ('Getting Started', 'Here are some tips to get started...', 'admin'))
    
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    c.execute("SELECT id, title, author, created_at FROM posts ORDER BY created_at DESC")
    posts = c.fetchall()
    conn.close()
    return render_template('blog_home.html', posts=posts, username=session.get('username'))

@app.route('/post/<int:post_id>')
def view_post(post_id):
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    c.execute("SELECT title, content, author, created_at FROM posts WHERE id = ?", (post_id,))
    post = c.fetchone()
    conn.close()
    if post:
        return render_template('blog_post.html', post=post, username=session.get('username'))
    return "Post not found", 404

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            return render_template('blog_login.html', error="Username and password required")
        
        conn = sqlite3.connect('blog.db')
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE username = ? AND password = ?",
                  (username, hashlib.sha256(password.encode()).hexdigest()))
        user = c.fetchone()
        conn.close()
        
        if user:
            session['username'] = user[0]
            return redirect(url_for('home'))
        else:
            return render_template('blog_login.html', error="Invalid credentials")
    
    return render_template('blog_login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/admin/backup')
def backup():
    if 'username' not in session or session['username'] != 'admin':
        return "Unauthorized", 403
    
    backup_type = request.args.get('type', 'database')
    
    if backup_type == 'database':
        result = subprocess.run(['ls', '-la', 'blog.db'], capture_output=True, text=True)
    elif backup_type == 'full':
        result = subprocess.run(['du', '-sh', '.'], capture_output=True, text=True)
    else:
        filename = request.args.get('file', 'blog.db')
        result = subprocess.run(['file', filename], capture_output=True, text=True)
    
    return f"<pre>{result.stdout}</pre>"

@app.route('/create', methods=['GET', 'POST'])
def create_post():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        
        if not title or not content:
            return render_template('blog_create.html', error="Title and content required")
        
        conn = sqlite3.connect('blog.db')
        c = conn.cursor()
        c.execute("INSERT INTO posts (title, content, author) VALUES (?, ?, ?)",
                  (title, content, session['username']))
        conn.commit()
        conn.close()
        
        return redirect(url_for('home'))
    
    return render_template('blog_create.html')

def create_templates():
    os.makedirs('templates', exist_ok=True)
    
    with open('templates/blog_home.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html><head><title>Blog Platform</title>
<style>body{font-family:Arial;max-width:900px;margin:50px auto;padding:20px}
.post{background:#f9f9f9;padding:20px;margin:15px 0;border-radius:5px}
.btn{background:#007bff;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;display:inline-block;margin:5px}
.header{display:flex;justify-content:space-between;align-items:center}</style></head>
<body><div class="header"><h1>📝 Blog Platform</h1><div>
{% if username %}<span>Welcome, {{username}}!</span> <a href="/create" class="btn">New Post</a>
{% if username == 'admin' %}<a href="/admin/backup?type=database" class="btn">Backup</a>{% endif %}
<a href="/logout" class="btn">Logout</a>
{% else %}<a href="/login" class="btn">Login</a>{% endif %}</div></div>
<h2>Recent Posts</h2>{% for post in posts %}<div class="post">
<h3><a href="/post/{{post[0]}}">{{post[1]}}</a></h3>
<small>By {{post[2]}} on {{post[3]}}</small></div>{% endfor %}</body></html>''')
    
    with open('templates/blog_post.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html><head><title>{{post[0]}}</title>
<style>body{font-family:Arial;max-width:900px;margin:50px auto;padding:20px}
.content{background:#f9f9f9;padding:30px;border-radius:5px;margin:20px 0}</style></head>
<body><h1>{{post[0]}}</h1><small>By {{post[2]}} on {{post[3]}}</small>
<div class="content">{{post[1]}}</div><p><a href="/">← Back to Home</a></p></body></html>''')
    
    with open('templates/blog_login.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html><head><title>Login</title>
<style>body{font-family:Arial;max-width:400px;margin:100px auto}
input{width:100%;padding:8px;margin:10px 0;border:1px solid #ddd;border-radius:4px}
.btn{background:#007bff;color:white;padding:10px;border:none;border-radius:4px;width:100%;cursor:pointer}
.error{color:red;background:#ffe6e6;padding:10px;border-radius:4px;margin:10px 0}</style></head>
<body><h2>Login</h2>{% if error %}<div class="error">{{error}}</div>{% endif %}
<form method="POST"><input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit" class="btn">Login</button></form>
<p>Test: admin / admin123</p><p><a href="/">Back</a></p></body></html>''')
    
    with open('templates/blog_create.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html><head><title>Create Post</title>
<style>body{font-family:Arial;max-width:800px;margin:50px auto;padding:20px}
input,textarea{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:4px}
textarea{height:200px}.btn{background:#007bff;color:white;padding:10px 20px;border:none;border-radius:4px;cursor:pointer}
.error{color:red;background:#ffe6e6;padding:10px;border-radius:4px;margin:10px 0}</style></head>
<body><h2>Create New Post</h2>{% if error %}<div class="error">{{error}}</div>{% endif %}
<form method="POST"><input type="text" name="title" placeholder="Post Title" required>
<textarea name="content" placeholder="Post content..." required></textarea>
<button type="submit" class="btn">Publish</button></form><p><a href="/">Cancel</a></p></body></html>''')

create_templates()

if __name__ == '__main__':
    print("Blog Platform Server")
    print("Running on http://localhost:5000")
    print("Login: admin / admin123")
    app.run(debug=False, host='127.0.0.1', port=5000)
