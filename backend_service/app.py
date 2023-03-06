"""
JWT: JSON Web Tokens

This python code implements an authentication wrapper using JWT

Questions: 
1. Identify potential security issues in JWT and database interactions.
2. Describe all attack scenarios in as much detail as possible using the security issues reported.
3. Provide fixes for all the identified issues.

How: 
Research on common SQL and JWT issues and bypasses.
"""

from flask import Flask, request, make_response
import jwt
import pickle
import hashlib
import bcrypt
import secrets
import os
import base64
import datetime
import sqlite3
import logging
from utils.db_utils import DatabaseUtils
from utils.file_storage import FileStorage

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# limit login requests to SQLite to prevent password guessing attacks
limiter = Limiter(app)

# use a random hard to guess secret key
SECRET_KEY = base64.urlsafe_b64encode(os.urandom(64)).decode('utf-8')

logging.basicConfig(level=logging.INFO)
db = DatabaseUtils()
fs = FileStorage()

# Generate salt for hashing passwords using higher number of rounds
# This will increase the password hashing time, thus slowing down a potential attacker
salt = bcrypt.gensalt(rounds=14)

def _init_app():

    # strictly using parameterized queries
    db.update_data("DROP TABLE IF EXISTS users;", [])
    db.update_data('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            password TEXT NOT NULL,
                            privilege INTEGER
                        );''', [])

    # Use salt along with hashed passwords to prevent some password attacks
    non_admin_password = bcrypt.hashpw(('password1'.encode()), salt).decode()
    admin_password = bcrypt.hashpw('adminpassword1'.encode(), salt).decode()


    db.update_data("INSERT INTO users (username, password, privilege) VALUES (?, ?, ?)", ["user1", non_admin_password, 0])
    db.update_data("INSERT INTO users (username, password, privilege) VALUES (?, ?, ?)", ["admin1", admin_password, 1])


def _check_login():
    auth_token = request.cookies.get('token', None)
    if not auth_token:
        raise "Missing token cookie"
    try:
        # Decode JWT token
        token = auth_token[len(auth_token)//2:] + auth_token[:len(auth_token)//2]
        data = jwt.decode(pickle.loads(bytes.fromhex(token)), SECRET_KEY, algorithms=["HS256"])
    except jwt.DecodeError:
        raise "Token is invalid"
    return data


@app.route("/login", methods=["POST"])
# limit login requests to SQLite to prevent password guessing attacks
@limiter.limit("10 per minute")
def login():

    # Sanitize username and password inputs to prevent SQL injection attacks
    # SQLite3::escapeString - Returns a string that has been properly escaped for safe inclusion in an SQL statement
    # ref: https://www.php.net/manual/en/sqlite3.escapestring.php
    username = sqlite3.escape_string(request.json.get("username"))
    password = sqlite3.escape_string(request.json.get("password"))

    # Hash passwords of the user to using random salts to prevent some password attacks
    password = bcrypt.hashpw(password.encode(), salt)

    rows = db.fetch_data("SELECT * FROM users WHERE username = ? AND password = ?", [username, password])

    if len(rows) != 1:
        return "Invalid credentials"

    admin = 'true' if rows[0][-1] == 1 else 'false'
    token = jwt.encode({"username": username, "is_admin": admin}, SECRET_KEY, algorithm="HS256")

    # JWT token should expire after a finite time, ideally 20 mins
    jwt_expiration_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=20)

    token = jwt.encode({ "username": username, "exp": jwt_expiration_time }, SECRET_KEY, algorithm="HS256")
    obfuscate1 = pickle.dumps(token.encode())
    obfuscate2 = obfuscate1.hex()
    obfuscate3 = obfuscate2[len(obfuscate2)//2:] + obfuscate2[:len(obfuscate2)//2]
    # Everyone knows how to read JWT tokens these days. The team decided to obfuscate it as a pickle and
    # some fancy tricks so nobody can tell we're using JWT and can't exploit us using common JWT exploits :D
    # Devs knowing some security sure is useful! :P

    res = make_response()

    # ref: set_cookie docs
    # param secure=True will make sure that the cookie will only be available via HTTPS
    # param httponly=True: Disallow JavaScript access to the cookie.
    # param samesite: Limit the scope of the cookie to only be attached to requests that are "same-site".
    res.set_cookie("token", value=obfuscate3, httponly=True, secure=True, samesite="strict")

    return res


@app.route("/file", methods=["GET", "POST", "DELETE"])
def store_file():
    """
    Only admins can upload/delete files.
    All users can read files.
    """
    try:
        data = _check_login()
    except:
        return "Not logged in"

    # is_admin = True if request.cookies.get('admin', 'false')=='true' else False
    is_admin = data['is_admin'] == "true"
    username = (data['username'])
    conn = sqlite3.connect('common_db.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    rows = cursor.execute(query, (username,)).fetchall()
    cursor = conn.cursor()
    if len(rows) == 0:
        return "Username not found"

    if request.method == 'GET':
        filename = request.args.get('filename')
        return fs.get(filename)
    elif request.method == 'POST':
        if not is_admin: return "Need admin access"
        uploaded_files = request.files
        logging.error(uploaded_files)
        for f in uploaded_files:
            fs.store(uploaded_files[f].name, uploaded_files[f].read())
            logging.info(f'Uploaded filename: {uploaded_files[f].name}')
        return "Files uploaded successfully"
    elif request.method == 'DELETE':
        if not is_admin: return "Need admin access"
        filename = request.args.get('filename')
        fs.delete(filename)
        return f"{filename} deleted successfully"
    else:
        return "Method not implemented"


if __name__ == "__main__":
    _init_app()
    app.run(host='0.0.0.0', debug=True, port=9090)
