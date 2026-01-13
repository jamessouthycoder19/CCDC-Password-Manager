from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask import Flask, request, render_template, redirect, url_for, flash, session, g
from urllib.parse import urlparse, unquote_plus

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from argon2 import PasswordHasher
from hashlib import pbkdf2_hmac

from datetime import timedelta, datetime
import numpy as np
import secrets
import os
import sqlite3
import hashlib
import threading
import time
import json

######################### Setup important local Variables #########################

SESSION_STATE_LENGTH = 30

ENCRYPTION_KEY = ""
ENCRYPTION_KEY_LOCK = threading.Lock()

LOGGED_IN_USER_STATES_EXPIRATION = []
LOGGED_IN_USER_STATES_EXPIRATION_LOCK = threading.Lock()

password_hasher = PasswordHasher()


######################### Variables for Random Password Generation #########################

# The Random Word List comes from https://github.com/nsacyber/RandPassGenerator/blob/master/RandPassGenerator/data/wordlist.txt
RANDOM_WORD_LIST = np.load("wordlist.npy", mmap_mode="r", allow_pickle=True)
NUMBER_RANDOM_WORDS = len(RANDOM_WORD_LIST)

RANDOM_INTEGER_LIST = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']
NUMBER_RANDOM_INTEGERS = len(RANDOM_INTEGER_LIST)

RANDOM_SPECIAL_CHAR_LIST = ['!', '@', '#', '$', '%', '^', '*', '(', ')', '-', '_', '=', '+']
NUMBER_RANDOM_SPECIAL_CHARS = len(RANDOM_SPECIAL_CHAR_LIST)

######################### Setup Flask Config #########################
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.urandom(32), # Randomize the key used to sign cookies on every startup
    SESSION_COOKIE_SECURE=True, # HTTPS Only
    SESSION_COOKIE_HTTPONLY=True, # Prevents JavaScript from accessing the session cookie
    SESSION_COOKIE_SAMESITE="Strict", # CSRF prevention
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_STATE_LENGTH), # Cookie only lasts 30 minutes
    SESSION_REFRESH_EACH_REQUEST=False # Don't refresh the cookie afer every request (force the cookie to only last 30 minutes)
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

######################### Thread used to manage state of Encryption key #########################

def validate_encryption_key_state():
    # This zeros out the encryption key if there are no currently logged in users.
    global ENCRYPTION_KEY
    global ENCRYPTION_KEY_LOCK
    global LOGGED_IN_USER_STATES_EXPIRATION
    global LOGGED_IN_USER_STATES_EXPIRATION_LOCK

    while True:
        with LOGGED_IN_USER_STATES_EXPIRATION_LOCK:
            while len(LOGGED_IN_USER_STATES_EXPIRATION) > 0:
                if LOGGED_IN_USER_STATES_EXPIRATION[0] < datetime.now():
                    LOGGED_IN_USER_STATES_EXPIRATION.pop(0)
                    if len(LOGGED_IN_USER_STATES_EXPIRATION) == 0:
                        break
                else:
                    break

        if len(LOGGED_IN_USER_STATES_EXPIRATION) == 0:
            with ENCRYPTION_KEY_LOCK:
                ENCRYPTION_KEY = ""

        time.sleep(10)

####################### Helper functions #########################

def generate_random_password():
    new_password = ""
    while len(new_password) < 13:
        word = RANDOM_WORD_LIST[secrets.randbelow(NUMBER_RANDOM_WORDS)]
        new_password += word.capitalize()
    new_password += RANDOM_INTEGER_LIST[secrets.randbelow(NUMBER_RANDOM_INTEGERS)]
    new_password += RANDOM_SPECIAL_CHAR_LIST[secrets.randbelow(NUMBER_RANDOM_SPECIAL_CHARS)]
    return new_password

def encrypt_data(plaintext):
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.ECB(), backend=default_backend())
    padder = padding.PKCS7(256).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def decrypt_data(ciphertext, old_enc_key=None):
    if old_enc_key is not None:
        cipher = Cipher(algorithms.AES(old_enc_key), modes.ECB(), backend=default_backend())
    else:
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(256).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode('utf-8')

def get_encryption_key():
    global ENCRYPTION_KEY
    global ENCRYPTION_KEY_LOCK
    with ENCRYPTION_KEY_LOCK:
        return ENCRYPTION_KEY

def set_encryption_key(username, password):
    global ENCRYPTION_KEY
    global ENCRYPTION_KEY_LOCK

    db = get_db()
    row = db.execute(
        "SELECT encryption_key_salt FROM app_credentials WHERE username = ?",
        (username,)
    ).fetchone()
    salt = row[0]
    iterations = 100000
    hash_algorithm = 'sha256'

    key = hashlib.pbkdf2_hmac(
        hash_algorithm,
        password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations
    )

    with ENCRYPTION_KEY_LOCK:
        ENCRYPTION_KEY = key

def get_db():
    if "db" not in g:
        # check_same_thread=False lets this connection be used within the same request thread context
        g.db = sqlite3.connect(
            "password_manager.db",
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False
        )
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS app_credentials (
        username             TEXT PRIMARY KEY,
        password             TEXT NOT NULL,
        encryption_key_salt  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS passwords (
        ip_address  TEXT NOT NULL,
        username    TEXT NOT NULL,
        password    TEXT,
        claimed     INTEGER DEFAULT 1,
        confirmed   INTEGER DEFAULT 3,
        error       TEXT,
        PRIMARY KEY (ip_address, username)
    );
                     
    CREATE TABLE IF NOT EXISTS client_tokens (
        ip_address  TEXT PRIMARY KEY,
        hostname    TEXT,
        token       TEXT
    );
    """)

    row = db.execute("SELECT COUNT(*) FROM app_credentials").fetchone()
    if row[0] == 0:
        starting_admin_password = os.urandom(16).hex()
        # starting_admin_password = "admin"

        with open("default_credentials.txt", "w") as f:
            f.write(f"admin:{starting_admin_password}\n")

        encryption_key_salt = os.urandom(16).hex()
        print("Starting Username: admin")
        print(f"Starting Password: {starting_admin_password}")
        add_app_user("admin", starting_admin_password, encryption_key_salt)

    db.commit()

def clear_db():
    db = get_db()
    db.execute("DROP TABLE IF EXISTS app_credentials")
    db.execute("DROP TABLE IF EXISTS passwords")
    db.execute("DROP TABLE IF EXISTS client_tokens")
    db.commit()

def add_app_user(username, password, encryption_key_salt):
    password_hash = password_hasher.hash(password)
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO app_credentials (username, password, encryption_key_salt) VALUES (?, ?, ?)",
        (username, password_hash, encryption_key_salt)
    )
    db.commit()

def add_new_client(ip_address):
    db = get_db()
    row = db.execute(
        "SELECT ip_address FROM client_tokens WHERE ip_address = ?",
        (ip_address,)
    ).fetchone()
    if row:
        return "Client already exists", 400
    db.execute(
        "INSERT OR REPLACE INTO client_tokens (ip_address, hostname, token) VALUES (?, ?, ?)",
        (ip_address, None, None)
    )
    db.commit()

def load_starting_clients():
    db = get_db()
    db.execute(
        "INSERT INTO client_tokens (ip_address, hostname, token) VALUES (?, ?, ?)",
        ("MISC", None, secrets.token_hex(16))
    )
    clients = db.execute("SELECT ip_address FROM client_tokens").fetchall()
    with open("starting_clients.txt", "r") as f:
        lines = f.readlines()
        for line in lines:
            ip_address = line.strip()
            if ip_address != "[clients]":
                if ip_address not in [client['ip_address'] for client in clients]:
                    add_new_client(ip_address)
    db.commit()

def validate_app_user(username, password):
    db = get_db()
    row = db.execute(
        "SELECT password FROM app_credentials WHERE username = ?",
        (username,)
    ).fetchone()
    if row:
        try:
            password_hasher.verify(row[0], password)
            return True
        except:
            return False
    return False

def add_stored_password(ip_address, username, password_value):
    db = get_db()
    claimed = 0
    confirmed = 2
    if password_value is None:
        claimed = 1
        confirmed = 3
    if ip_address == "MISC":
        claimed = 1
        confirmed = 0
    db.execute(
        "INSERT OR REPLACE INTO passwords (ip_address, username, password, claimed, confirmed, error) VALUES (?, ?, ?, ?, ?, ?)",
        (ip_address, username, password_value, claimed, confirmed, None)
    )
    db.commit()

# Thanks for this method andrew
def is_safe_path(next_url: str) -> bool:
    if not next_url:
        return False
    # percent-decoded already by Flask for request.args/form, but be safe:
    next_url = unquote_plus(next_url)
    parsed = urlparse(next_url)
    # allow only relative paths (no scheme/netloc)
    return (parsed.scheme == "" and parsed.netloc == "" and next_url.startswith("/"))

class User(UserMixin):
    def __init__(self, id, role):
        self.id = id
        self.role = role

###################### UI Login Handlers #########################

@login_manager.user_loader
def load_user(id):
    db = get_db()
    user = db.execute(
        "SELECT username FROM app_credentials WHERE username = ?",
        (id,)
    ).fetchone()
    if user:
        return User(id, 'admin')
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    global LOGGED_IN_USER_STATES_EXPIRATION
    global LOGGED_IN_USER_STATES_EXPIRATION_LOCK

    # For GET render pass the next param to template so the form includes it
    if request.method == 'GET':
        next_param = request.args.get('next', '')
        return render_template('login.html', next=next_param)

    # Get number of rows in app_credentials, if 0 then have user create admin account
    db = get_db()
    row = db.execute("SELECT COUNT(*) FROM app_credentials").fetchone()

    next_param = request.form.get('next') or request.args.get('next') or ''

    username = request.form.get('username')
    password = request.form.get('password')

    if validate_app_user(username, password):
        user = User(username, 'admin')
        login_user(user)
        set_encryption_key(username, password)
        session.permanent = True

        with LOGGED_IN_USER_STATES_EXPIRATION_LOCK:
            LOGGED_IN_USER_STATES_EXPIRATION.append(datetime.now() + timedelta(minutes=SESSION_STATE_LENGTH))

        # Validate next and redirect safely
        if is_safe_path(next_param):
            return redirect(unquote_plus(next_param))
        return redirect(url_for('dashboard'))

    flash('Invalid username or password', 'danger')
    return render_template('login.html', next=next_param)

@app.route('/logout')
@login_required
def logout():
    global LOGGED_IN_USER_STATES_EXPIRATION
    global LOGGED_IN_USER_STATES_EXPIRATION_LOCK
    with LOGGED_IN_USER_STATES_EXPIRATION_LOCK:
        LOGGED_IN_USER_STATES_EXPIRATION.pop(0)
    logout_user()
    return redirect(url_for('login'))


####################### UI Static Pages #########################

@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@login_required
@app.route('/agent')
def agent_page():
    return render_template('agent.html')

####################### UI APIs #########################

@login_required
@app.route("/add_client", methods=["POST"])
def add_client():
    ip_address = request.form.get("ip_address")
    if not ip_address:
        return "Missing ip_address", 400
    
    add_new_client(ip_address)

    return "OK", 200

@login_required
@app.route("/get_clients", methods=["GET"])
def get_clients():
    db = get_db()
    rows = db.execute("SELECT ip_address, hostname, token FROM client_tokens").fetchall()
    clients = []
    for row in rows:
        status = "Connected" if row['token'] else "Unregistered"
        users = db.execute(
            "SELECT COUNT(*) as user_count FROM passwords WHERE ip_address = ?",
            (row['ip_address'],)
        ).fetchone()
        users_with_passwords = db.execute(
            "SELECT COUNT(*) as user_count FROM passwords WHERE ip_address = ? AND password IS NOT NULL",
            (row['ip_address'],)
        ).fetchone()
        clients.append({
            'ip_address': row['ip_address'],
            'hostname': row['hostname'],
            'status': status,
            'total_users': users['user_count'],
            'users_with_passwords': users_with_passwords['user_count'],
        })
    return {'clients': clients}, 200

@login_required
@app.route("/reset_client_token", methods=["POST"])
def reset_client_token():
    ip_address = request.form.get("ip_address")
    if not ip_address:
        return "Missing ip_address", 400
    db = get_db()
    db.execute(
        "UPDATE client_tokens SET token = ? WHERE ip_address = ?",
        (None, ip_address)
    )
    db.commit()

    return "OK", 200

@login_required
@app.route("/add_misc_user", methods=["POST"])
def add_misc_user():
    username = request.form.get("username")
    if not username:
        return "Missing username", 400

    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO passwords (ip_address, username, password, claimed, confirmed, error) VALUES (?, ?, ?, ?, ?, ?)",
        ("MISC", username, None, 1, 2, None)
    )
    db.commit()
    return "OK", 200

@login_required
@app.route("/remove_client", methods=["POST"])
def remove_client():
    ip_address = request.form.get("ip_address")
    if not ip_address:
        return "Missing ip_address", 400
    db = get_db()
    db.execute(
        "DELETE FROM client_tokens WHERE ip_address = ?",
        (ip_address,)
    )
    db.commit()

    return "OK", 200

@login_required
@app.route("/get_users", methods=["GET"])
def get_users():
    ip_address = request.args.get("ip_address")
    if not ip_address:
        return "Missing ip_address", 400
    db = get_db()
    rows = db.execute(
        "SELECT username, password, confirmed, error FROM passwords WHERE ip_address = ?",
        (ip_address,)
    ).fetchall()
    
    users = []
    # Note: password_claimed: 0 = unsuccessful password change, 1 = successful password change, 2 = haven't heard back yet
    for row in rows:
        users.append({
            'username': row['username'],
            'password_exists': row['password'] is not None,
            'password_claimed': row['confirmed'],
            'error': row['error'],
        })
    # db.commit()
    return {'users': users}, 200

@login_required
@app.route("/set_user_password", methods=["POST"])
def set_user_password():
    ip_address = request.form.get("ip_address")
    username = request.form.get("username")
    password_value = request.form.get("password_value")
    if not ip_address or not username or not password_value:
        return "Missing ip_address, username, or password_value", 400

    for bad_symbol in [';', '--', '"', "'", "&", "|"]:
        if bad_symbol in password_value:
            return "Invalid characters in password_value", 400
    
    if password_value == "RANDOM":
        password_value = generate_random_password()

    add_stored_password(ip_address, username, encrypt_data(password_value))
    return "OK", 200

@login_required
@app.route("/set_master_password", methods=["POST"])
def set_master_password():
    new_password = request.form.get("new_password")
    
    current_encryption_key = get_encryption_key()
    set_encryption_key("admin", new_password)

    db = get_db()

    row = db.execute(
        "SELECT encryption_key_salt FROM app_credentials WHERE username = ?",
        ("admin",)
    ).fetchone()
    salt = row[0]

    add_app_user("admin", new_password, salt)
    
    rows = db.execute(
        "SELECT * FROM passwords"
    ).fetchall()
    for row in rows:
        if row[2] is not None:
            ip_address = row[0]
            username = row[1]
            password = decrypt_data(row[2], current_encryption_key)
            encrypted_password = encrypt_data(password)
            add_stored_password(ip_address, username, encrypted_password)
    
    return "OK", 200
    
@login_required
@app.route("/get_user_password", methods=["GET"])
def get_user_password():
    ip_address = request.args.get("ip_address")
    username = request.args.get("username")
    if not ip_address or not username:
        return "Missing ip_address or username", 400
    db = get_db()
    row = db.execute(
        "SELECT password FROM passwords WHERE ip_address = ? AND username = ?",
        (ip_address, username)
    ).fetchone()
    if row and row['password']:
        decrypted_password = decrypt_data(row['password'])
        return {'password': decrypted_password}, 200
    return "Password not set", 404

##################### Client APIs #########################

@app.route("/get_passwords_to_claim", methods=["POST"])
def get_passwords_to_claim():
    ip_address = request.form.get("ip_address")
    token = request.form.get("authoriztion_token")
    # Check auth
    if not token:
        return "Missing authorization token", 400
    db = get_db()
    row = db.execute(
        "SELECT token FROM client_tokens WHERE ip_address = ?",
        (ip_address,)
    ).fetchone()
    if not row or row['token'] != token:
        return "Unauthorized", 401
    if not ip_address:
        return "Missing ip_address", 400
    rows = db.execute(
        "SELECT username, password FROM passwords WHERE ip_address = ? AND claimed = 0",
        (ip_address,)
    ).fetchall()
    users = []
    for row in rows:
        users.append({
            'username': row['username'],
            'password': decrypt_data(row['password']),
        })
        db.execute(
            "UPDATE passwords SET claimed = 1 WHERE ip_address = ? AND username = ?",
            (ip_address, row['username'])
        )
    db.commit()
    return {'users': users}, 200

@app.route("/update_password_change_status", methods=["POST"])
def update_password_change_status():
    ip_address = request.form.get("ip_address")
    user_status = request.form.get("user_status")
    token = request.form.get("authoriztion_token")
    # Check auth
    if not token:
        return "Missing authorization token", 400
    db = get_db()
    row = db.execute(
        "SELECT token FROM client_tokens WHERE ip_address = ?",
        (ip_address,)
    ).fetchone()
    if not row or row['token'] != token:
        return "Unauthorized", 401
    if not ip_address or not user_status:
        return "Missing ip_address or user_status", 400
    user_status_json = json.loads(user_status)
    db = get_db()
    for item in user_status_json:
        user = item["username"]
        status = item["status"]
        if status == "Success":
            db.execute(
                "UPDATE passwords SET confirmed = 0, error = ? WHERE ip_address = ? AND username = ?",
                (None, ip_address, user)
            )
        else:
            db.execute(
                "UPDATE passwords SET confirmed = 1, error = ? WHERE ip_address = ? AND username = ?",
                (status, ip_address, user)
            )
    db.commit()
    return "Ok", 200

@app.route("/update_local_users", methods=["POST"])
def update_local_users():
    ip_address = request.form.get("ip_address")
    local_users = request.form.getlist("local_users")
    token = request.form.get("authoriztion_token")
    # Check auth
    if not token:
        return "Missing authorization token", 400
    db = get_db()
    row = db.execute(
        "SELECT token FROM client_tokens WHERE ip_address = ?",
        (ip_address,)
    ).fetchone()
    if not row or row['token'] != token:
        return "Unauthorized", 401
    if not ip_address or not local_users:
        return "Missing ip_address or local_users", 400
    local_users = local_users[0].split(',')
    # Update local users
    existing_users = db.execute(
        "SELECT username FROM passwords WHERE ip_address = ?",
        (ip_address,)
    ).fetchall()
    existing_usernames = {row['username'] for row in existing_users}
    for user in local_users:
        if user not in existing_usernames:
            add_stored_password(ip_address, user, None)
    db.commit()
    return "Local users updated", 200

@app.route("/register_client", methods=["POST"])
def register_client():
    # Client will send its IP
    ip_address = request.form.get("ip_address")
    if not ip_address:
        return "Missing IP Address", 400
    db = get_db()
    row = db.execute(
        "SELECT ip_address, token FROM client_tokens WHERE ip_address = ?",
        (ip_address,)
    ).fetchone()
    if row:
        if row['token']:
            return "Client already registered", 400
        else:
            # Generate token
            token = os.urandom(16).hex()
            hostname = request.form.get("hostname")
            db.execute(
                "UPDATE client_tokens SET token = ?, hostname = ? WHERE ip_address = ?",
                (token, hostname, ip_address)
            )
            db.commit()
            return token, 200
    db.commit()

    return "Client not available for registration", 400

if __name__ == '__main__':
    with app.app_context():
        clear_db()
        init_db()
        load_starting_clients()

    key_management_thread = threading.Thread(
        target=validate_encryption_key_state,
        daemon=True
    )
    key_management_thread.start()
    
    app.run(host="0.0.0.0", port=443, debug=False, ssl_context='adhoc')