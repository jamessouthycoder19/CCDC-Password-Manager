from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask import Flask, request, render_template, redirect, url_for, flash, session, g
from datetime import timedelta
import os
from urllib.parse import urlparse, unquote_plus
import sqlite3
from argon2 import PasswordHasher
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


# ============= Set Flask Config ========================
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.urandom(32), # Randomize the key every startup to avoid cookie reuse
    #SESSION_COOKIE_SECURE=True, # Forces the session cookie to be sent only over HTTPS. TODO
    SESSION_COOKIE_HTTPONLY=True, # Prevents JavaScript from accessing the session cookie
    SESSION_COOKIE_SAMESITE="Strict", # "Strict": the cookie is only sent for requests from the same site (no subdomains)
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=1),
    SESSION_REFRESH_EACH_REQUEST=True # Automatic refreshes mean that lifetime is effectively infinite! This means that users actively on the site won't get signed out, but people who close the site but not the browser and keep it closed for 1 min will have to sign in again
)

######################### Setup important local Variables #########################

ENCRYPTION_KEY = ""

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


password_hasher = PasswordHasher()

####################### Helper functions #########################

def encrypt_data(plaintext):
    global ENCRYPTION_KEY
    key = ENCRYPTION_KEY.encode('utf-8')[:32]
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    padder = padding.PKCS7(256).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def decrypt_data(ciphertext):
    global ENCRYPTION_KEY
    key = ENCRYPTION_KEY.encode('utf-8')[:32]
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(256).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode('utf-8')

def get_encryption_key():
    global ENCRYPTION_KEY
    return ENCRYPTION_KEY

def set_encryption_key(key):
    global ENCRYPTION_KEY
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
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS passwords (
        ip_address TEXT NOT NULL,
        username   TEXT NOT NULL,
        password   TEXT,
        claimed    INTEGER DEFAULT 1,
        PRIMARY KEY (ip_address, username)
    );
                     
    CREATE TABLE IF NOT EXISTS client_tokens (
        ip_address TEXT PRIMARY KEY,
        token      TEXT
    );
    """)
    db.commit()

def clear_db():
    db = get_db()
    db.execute("DROP TABLE IF EXISTS app_credentials")
    db.execute("DROP TABLE IF EXISTS passwords")
    db.execute("DROP TABLE IF EXISTS client_tokens")
    db.commit()

def get_sha256_hash(data):
    sha256 = hashlib.sha256()
    sha256.update(data.encode('utf-8'))
    return sha256.hexdigest()

def add_app_user(username, password):
    password_hash = password_hasher.hash(password)
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO app_credentials (username, password) VALUES (?, ?)",
        (username, password_hash)
    )
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
    db.execute(
        "INSERT OR REPLACE INTO passwords (ip_address, username, password, claimed) VALUES (?, ?, ?, ?)",
        (ip_address, username, password_value, 0)
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
    # For GET render pass the next param to template so the form includes it
    if request.method == 'GET':
        next_param = request.args.get('next', '')
        return render_template('login.html', next=next_param)

    # POST
    # Get number of rows in app_credentials, if 0 then have user create admin account
    db = get_db()
    row = db.execute("SELECT COUNT(*) FROM app_credentials").fetchone()

    next_param = request.form.get('next') or request.args.get('next') or ''

    if row[0] == 0:
        username = request.form.get('username')
        password = request.form.get('password')
        add_app_user(username, password)
        user = User(username, 'admin')
        login_user(user)
        set_encryption_key(get_sha256_hash(username + password))
        session.permanent = True

        # Validate next and redirect safely
        if is_safe_path(next_param):
            return redirect(unquote_plus(next_param))
        return redirect(url_for('page_dashboard'))

    else:
        username = request.form.get('username')
        password = request.form.get('password')

        if validate_app_user(username, password):
            user = User(username, 'admin')
            login_user(user)
            set_encryption_key(get_sha256_hash(username + password))
            session.permanent = True

            # Validate next and redirect safely
            if is_safe_path(next_param):
                return redirect(unquote_plus(next_param))
            return redirect(url_for('page_dashboard'))

        flash('Invalid username or password', 'danger')
    return render_template('login.html', next=next_param)

@app.route('/logout')
@login_required
def logout():
    set_encryption_key("")
    logout_user()
    return redirect(url_for('login'))


####################### UI Static Pages #########################

@app.route("/")
@app.route("/dashboard")
@login_required
def page_dashboard():
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
    db = get_db()
    row = db.execute(
        "SELECT ip_address FROM client_tokens WHERE ip_address = ?",
        (ip_address,)
    ).fetchone()
    if row:
        return "Client already exists", 400
    db.execute(
        "INSERT OR REPLACE INTO client_tokens (ip_address, token) VALUES (?, ?)",
        (ip_address, None)
    )
    db.commit()

    return "OK", 200

@login_required
@app.route("/get_clients", methods=["GET"])
def get_clients():
    db = get_db()
    rows = db.execute("SELECT ip_address, token FROM client_tokens").fetchall()
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
        "SELECT username, password FROM passwords WHERE ip_address = ?",
        (ip_address,)
    ).fetchall()
    users = []
    for row in rows:
        users.append({
            'username': row['username'],
            'password_exists': row['password'] is not None,
        })
    return {'users': users}, 200

@login_required
@app.route("/set_user_password", methods=["POST"])
def set_user_password():
    ip_address = request.form.get("ip_address")
    username = request.form.get("username")
    password_value = request.form.get("password_value")
    if not ip_address or not username or not password_value:
        return "Missing ip_address, username, or password_value", 400
    encrypted_password = encrypt_data(password_value)
    add_stored_password(ip_address, username, encrypted_password)
    return "OK", 200\
    
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
            db.execute(
                "INSERT INTO passwords (ip_address, username, password) VALUES (?, ?, ?)",
                (ip_address, user, None)
            )
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
            db.execute(
                "UPDATE client_tokens SET token = ? WHERE ip_address = ?",
                (token, ip_address)
            )
            db.commit()
            return token, 200
    db.commit()

    return "Client not available for registration", 400

if __name__ == '__main__':
    with app.app_context():
        clear_db()
        init_db()
    app.run(host="0.0.0.0", port=443, debug=True, ssl_context='adhoc')