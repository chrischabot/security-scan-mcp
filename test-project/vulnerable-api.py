# Vulnerable Python application for testing the scanner

import os
import pickle
import yaml
import subprocess
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

# Database connection
conn = sqlite3.connect('app.db')
cursor = conn.cursor()

# CWE-89: SQL Injection via f-string
@app.route('/user/<user_id>')
def get_user(user_id):
    # VULNERABLE: SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return jsonify(cursor.fetchall())

# CWE-89: SQL Injection via format
@app.route('/search')
def search():
    term = request.args.get('q')
    # VULNERABLE: SQL injection
    query = "SELECT * FROM products WHERE name LIKE '%{}%'".format(term)
    cursor.execute(query)
    return jsonify(cursor.fetchall())

# CWE-78: Command Injection via os.system
@app.route('/ping')
def ping():
    host = request.args.get('host')
    # VULNERABLE: Command injection
    os.system(f"ping -c 1 {host}")
    return "Ping sent"

# CWE-78: Command Injection via subprocess with shell=True
@app.route('/exec')
def run_command():
    cmd = request.args.get('cmd')
    # VULNERABLE: Command injection
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout

# CWE-502: Unsafe pickle deserialization
@app.route('/load', methods=['POST'])
def load_data():
    data = request.get_data()
    # VULNERABLE: Arbitrary code execution via pickle
    obj = pickle.loads(data)
    return jsonify({"loaded": str(obj)})

# CWE-502: Unsafe YAML loading
@app.route('/config', methods=['POST'])
def load_config():
    yaml_data = request.get_data().decode()
    # VULNERABLE: Arbitrary code execution via yaml.load
    config = yaml.load(yaml_data)
    return jsonify(config)

# CWE-22: Path Traversal
@app.route('/file')
def read_file():
    filename = request.args.get('name')
    # VULNERABLE: Path traversal
    with open(f"/uploads/{filename}", 'r') as f:
        return f.read()

# CWE-94: Code Injection via eval
@app.route('/calc')
def calculate():
    expr = request.args.get('expr')
    # VULNERABLE: Code injection
    result = eval(expr)
    return jsonify({"result": result})

# CWE-94: Code Injection via exec
@app.route('/run', methods=['POST'])
def run_code():
    code = request.form.get('code')
    # VULNERABLE: Code injection
    exec(code)
    return "Executed"

# CWE-798: Hardcoded credentials
DB_PASSWORD = "MySuperSecretDBPassword123"
API_KEY = "sk-live-abc123xyz789secret"

# CWE-918: SSRF
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    # VULNERABLE: SSRF
    import requests
    response = requests.get(url)
    return response.text

if __name__ == '__main__':
    app.run(debug=True)
