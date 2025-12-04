from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask import Flask, request, render_template, redirect, url_for, flash, session, g
from datetime import timedelta
import os
from urllib.parse import urlparse, unquote_plus
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import sqlite3
from argon2 import PasswordHasher
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature


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

# ============= Setup SQLite Database ========================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_KEY = None
ENCRYPTION_KEY = ""

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
        password   TEXT NOT NULL,
        PRIMARY KEY (ip_address, username)
    );
                     
    CREATE TABLE IF NOT EXISTS client_pub_keys (
        ip_address TEXT PRIMARY KEY,
        pub_key    TEXT NOT NULL
    );
    """)
    db.commit()

def init_server_pub_priv_keys():
    # Check if keys already exist
    if os.path.exists("server_private_key.pem") and os.path.exists("server_public_key.pem"):
        # Load existing keys
        with open("server_private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        with open("server_public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read()
            )
        
        global SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY
        SERVER_PRIVATE_KEY = private_key
        SERVER_PUBLIC_KEY = public_key
        return
    # Generate new RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    # Save private key
    with open("server_private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    # Save public key
    with open("server_public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    
    global SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY
    SERVER_PRIVATE_KEY = private_key
    SERVER_PUBLIC_KEY = public_key

def encrypt_message_pub_key(public_key, message: str) -> bytes:
    if not isinstance(message, str):
        raise TypeError("Message must be a string.")
    try:
        ciphertext = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    except Exception as e:
        raise RuntimeError(f"Encryption failed: {e}")

def decrypt_message_pub_key(public_key, ciphertext: bytes) -> str:
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes.")
    try:
        # Note: Public keys cannot decrypt; this is just for demonstration
        plaintext = public_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')
    except Exception as e:
        raise RuntimeError(f"Decryption failed: {e}")

def encrypt_message_privaet_key(private_key, ciphertext: bytes) -> str:
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes.")
    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')
    except Exception as e:
        raise RuntimeError(f"Decryption failed: {e}")

# ============= Setup Password Hasher ========================
password_hasher = PasswordHasher()

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
        "INSERT OR REPLACE INTO passwords (ip_address, username, password) VALUES (?, ?, ?)",
        (ip_address, username, password_value)
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

@app.route("/")
@app.route("/dashboard")
@login_required
def page_dashboard():
    return render_template("dashboard.html")

@app.route("/register_client", methods=["POST"])
def register_client():
    # Client will send its IP and public key in POST data
    ip_address = request.form.get("ip_address")
    pub_key = request.form.get("pub_key")
    if not ip_address or not pub_key:
        return "Missing ip_address or pub_key", 400
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO client_pub_keys (ip_address, pub_key) VALUES (?, ?)",
        (ip_address, pub_key)
    )
    db.commit()

if __name__ == '__main__':
    init_server_pub_priv_keys()
    app.run(host="127.0.0.1", port=6767, debug=True)
    with app.app_context():
        init_db()