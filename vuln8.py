from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/test')
def test():
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return "OK"
