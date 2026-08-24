from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import hmac
import os
import secrets
from datetime import datetime
import sys
import threading
import time
import socket
from sqlalchemy.engine import URL
from werkzeug.security import check_password_hash
from waitress import serve

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv is optional at import time; production values must still be set.
    pass


def required_env(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable: {name}. "
            "Copy .env.example to .env and configure it before starting."
        )
    return value

app = Flask(__name__)

# =========================
# EXPIRATION DATE
# =========================

expiry_date = datetime(
    2026,
    12,
    31
)

today = datetime.now()

if today > expiry_date:

    print("\n")
    print("=" * 60)
    print("   SYSTEM EXPIRED")
    print("=" * 60)
    print("\n")

    print(" Please contact:")
    print(" Engr. Crispolo L. Bernardino, Jr.")
    print("\n")

    print(" This Queue Management System")
    print(" license has already expired.")
    print("\n")

    input(" Press ENTER to exit...")

    sys.exit()

# =========================
# EXE OR NORMAL MODE
# =========================

if getattr(sys, 'frozen', False):

    basedir = os.path.dirname(
        sys.executable
    )

else:

    basedir = os.path.abspath(
        os.path.dirname(__file__)
    )

# =========================
# DATE ROLLBACK DETECTION
# =========================

last_run_file = os.path.join(
    basedir,
    "system.lock"
)

# FIRST RUN
if not os.path.exists(last_run_file):

    with open(
        last_run_file,
        "w"
    ) as f:

        f.write(
            today.strftime("%Y-%m-%d")
        )

    # This local runtime file is excluded by .gitignore; do not invoke a shell
    # command just to hide it.

else:

    with open(
        last_run_file,
        "r"
    ) as f:

        saved_date = f.read().strip()

    last_run_date = datetime.strptime(
        saved_date,
        "%Y-%m-%d"
    )

    # DATE ROLLBACK DETECTED
    if today < last_run_date:

        print("\n")
        print("=" * 60)
        print("   SYSTEM SECURITY WARNING")
        print("=" * 60)
        print("\n")

        print(" System date rollback detected.")
        print(" Please contact the developer.")
        print("\n")

        input(" Press ENTER to exit...")

        sys.exit()

    # UPDATE LAST RUN DATE
    with open(
        last_run_file,
        "w"
    ) as f:

        f.write(
            today.strftime("%Y-%m-%d")
        )

app.config.update(
    SECRET_KEY=required_env('SECRET_KEY'),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true',
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=16 * 1024,
)

ADMIN_USERNAME = required_env('ADMIN_USERNAME')
ADMIN_PASSWORD_HASH = required_env('ADMIN_PASSWORD_HASH')

_login_failures = {}
_login_lock = threading.Lock()
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300

# EXE OR NORMAL MODE
if getattr(sys, 'frozen', False):

    basedir = os.path.dirname(
        sys.executable
    )

else:

    basedir = os.path.abspath(
        os.path.dirname(__file__)
    )

db_path = os.path.abspath(os.getenv('QUEUE_DB_PATH', os.path.join(basedir, 'queue.db')))
database_url = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or URL.create(
    drivername='sqlite',
    database=db_path,
)

db = SQLAlchemy(app)

reannounce_counter = 0


def csrf_token():
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
    return token


@app.context_processor
def inject_security_helpers():
    return {'csrf_token': csrf_token}


def csrf_protect(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method == 'POST':
            supplied = request.form.get('csrf_token', '')
            expected = session.get('csrf_token', '')
            if not expected or not hmac.compare_digest(supplied, expected):
                abort(400, description='Invalid CSRF token')
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('login'))
        return view(*args, **kwargs)

    return wrapped


def login_is_locked(client_ip):
    now = time.monotonic()
    with _login_lock:
        details = _login_failures.get(client_ip)
        if not details:
            return False
        if details['locked_until'] > now:
            return True
        if details['locked_until']:
            _login_failures.pop(client_ip, None)
    return False


def record_failed_login(client_ip):
    now = time.monotonic()
    with _login_lock:
        details = _login_failures.setdefault(
            client_ip,
            {'attempts': 0, 'locked_until': 0},
        )
        details['attempts'] += 1
        if details['attempts'] >= LOGIN_MAX_ATTEMPTS:
            details['locked_until'] = now + LOGIN_LOCKOUT_SECONDS
            details['attempts'] = 0


def clear_failed_logins(client_ip):
    with _login_lock:
        _login_failures.pop(client_ip, None)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault('Cache-Control', 'no-store')
    if app.config['SESSION_COOKIE_SECURE']:
        response.headers.setdefault(
            'Strict-Transport-Security',
            'max-age=31536000; includeSubDomains',
        )
    return response

# =========================
# DATABASE
# =========================

class Queue(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    number = db.Column(
        db.String(20)
    )

    counter = db.Column(
        db.String(20)
    )

    priority = db.Column(
        db.Boolean,
        default=False
    )

    recalled = db.Column(
        db.Boolean,
        default=False
    )

    status = db.Column(
        db.String(20),
        default='waiting'
    )


# FORCE CREATE TABLES
with app.app_context():

    db.create_all()

    print("QUEUE TABLE CREATED")


# =========================
# HOME
# =========================

@app.route('/')
def home():

    queues = Queue.query.order_by(
        Queue.id.desc()
    ).all()

    return render_template(
        'index.html',
        queues=queues
    )


# =========================
# GET NORMAL NUMBER
# =========================

@app.route('/get_number', methods=['POST'])
@csrf_protect
def get_number():

    last = Queue.query.order_by(Queue.id.desc()).first()

    if last:
        next_num = int(last.number.split('-')[1]) + 1
    else:
        next_num = 1

    queue_number = f"A-{next_num}"

    new_queue = Queue(
        number=queue_number,
        priority=False
    )

    db.session.add(new_queue)
    db.session.commit()

    return redirect('/')


# =========================
# GET PRIORITY NUMBER
# =========================

@app.route('/priority', methods=['POST'])
@csrf_protect
def priority():

    last = Queue.query.order_by(Queue.id.desc()).first()

    if last:
        next_num = int(last.number.split('-')[1]) + 1
    else:
        next_num = 1

    queue_number = f"P-{next_num}"

    new_queue = Queue(
        number=queue_number,
        priority=True
    )

    db.session.add(new_queue)
    db.session.commit()

    return redirect('/')


# =========================
# ADMIN LOGIN
# =========================

@app.route('/login', methods=['GET', 'POST'])
@csrf_protect
def login():

    if request.method == 'POST':

        client_ip = request.remote_addr or 'unknown'
        if login_is_locked(client_ip):
            return render_template('login.html', error='Too many failed attempts. Try again later.'), 429

        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if hmac.compare_digest(username, ADMIN_USERNAME) and check_password_hash(
            ADMIN_PASSWORD_HASH,
            password,
        ):
            clear_failed_logins(client_ip)
            session.clear()
            session['admin'] = True
            session['csrf_token'] = secrets.token_urlsafe(32)
            session.permanent = True

            return redirect(url_for('admin'))

        record_failed_login(client_ip)

    error = 'Invalid username or password.' if request.method == 'POST' else None
    return render_template('login.html', error=error)


# =========================
# ADMIN PANEL
# =========================

@app.route('/admin')
@admin_required
def admin():

    queues = Queue.query.order_by(
        Queue.id.desc()
    ).all()

    serving = Queue.query.filter_by(
        status='serving'
    ).all()

    return render_template(
        'admin.html',
        queues=queues,
        serving=serving
    )


# =========================
# COUNTER NEXT QUEUE
# =========================

@app.route('/next/<counter>', methods=['POST'])
@admin_required
@csrf_protect
def next_queue(counter):

    # CURRENT SERVING
    current = Queue.query.filter_by(
        counter=counter,
        status='serving'
    ).first()

    if current:

        # COMPLETE TRANSACTION
        current.status = 'done'

        # RESET RECALL FLAG
        current.recalled = False

    # PRIORITY FIRST
    priority_queue = Queue.query.filter_by(
        status='waiting',
        priority=True
    ).first()

    if priority_queue:

        priority_queue.status = 'serving'

        priority_queue.counter = counter

    else:

        # NORMAL QUEUE
        queue = Queue.query.filter_by(
            status='waiting'
        ).first()

        if queue:

            queue.status = 'serving'

            queue.counter = counter

    db.session.commit()

    return redirect('/admin')


# =========================
# DISPLAY SCREEN
# =========================

@app.route('/display')
def display():

    serving = Queue.query.filter_by(
        status='serving'
    ).all()

    next_queues = Queue.query.filter_by(
        status='waiting'
    ).limit(10).all()

    return render_template(
        'display.html',
        serving=serving,
        next_queues=next_queues
    )
   
# =========================
# QUE DATA
# =========================   
   
@app.route('/queue_data')
def queue_data():

    global reannounce_counter

    current = "---"
    recalled = False

    serving = Queue.query.filter_by(
        status='serving'
    ).first()

    if serving:

        current = serving.number

        recalled = serving.recalled

    # NEXT LIST
    next_queues = Queue.query.filter_by(
        status='waiting'
    ).limit(30).all()

    next_list = []

    for q in next_queues:

        next_list.append(q.number)

    return jsonify({
        "current": current,
        "next": next_list,
        "recalled": recalled,
        "reannounce": reannounce_counter
    })

# =========================
# RECALL
# ========================= 

@app.route('/recall/<int:id>', methods=['POST'])
@admin_required
@csrf_protect
def recall(id):

    # CURRENT SERVING
    current = Queue.query.filter_by(
        status='serving'
    ).first()

    if current:

        current.status = 'done'

    # SPECIFIC SKIPPED NUMBER
    skipped = db.session.get(
        Queue,
        id
    )

    if skipped and skipped.status == 'skipped':

        skipped.status = 'serving'

        skipped.counter = 'Counter 1'

        skipped.recalled = True

    db.session.commit()

    return redirect('/admin')

# =========================
# SKIP
# ========================= 
   
@app.route('/skip', methods=['POST'])
@admin_required
@csrf_protect
def skip():

    current = Queue.query.filter_by(
        status='serving'
    ).first()

    if current:

        current.status = 'skipped'

    # NEXT PRIORITY
    priority_queue = Queue.query.filter_by(
        status='waiting',
        priority=True
    ).first()

    if priority_queue:

        priority_queue.status = 'serving'
        priority_queue.counter = 'Counter 1'

    else:

        # NEXT NORMAL
        next_queue = Queue.query.filter_by(
            status='waiting'
        ).first()

        if next_queue:

            next_queue.status = 'serving'
            next_queue.counter = 'Counter 1'

    db.session.commit()

    return redirect('/admin')
    
# =========================
# RESET QUEUE
# =========================    
    
@app.route('/reset', methods=['POST'])
@admin_required
@csrf_protect
def reset():

    Queue.query.delete()

    db.session.commit()

    return redirect('/admin')
    
# =========================
# RE-ANNOUNCE
# =========================

@app.route('/reannounce', methods=['POST'])
@admin_required
@csrf_protect
def reannounce():

    global reannounce_counter

    reannounce_counter += 1

    return redirect('/admin')


@app.route('/logout', methods=['POST'])
@admin_required
@csrf_protect
def logout():
    session.clear()
    return redirect(url_for('login'))
    
  
# =========================
# RUN SERVER
# =========================

if __name__ == '__main__':

    server_host = os.getenv('SERVER_HOST', '127.0.0.1')
    server_port = int(os.getenv('SERVER_PORT', '5000'))

    # GET LOCAL IP
    hostname = socket.gethostname()

    local_ip = socket.gethostbyname(
        hostname
    )

    print("\n")
    print("=" * 100)
    print("   COMELEC QUEUE MANAGEMENT SYSTEM")
    print("=" * 100)
    print("\n")

    print(" Server Status : RUNNING")
    print(f" Local Access  : http://127.0.0.1:5000")
    if server_host == '0.0.0.0':
        print(f" Network Access: http://{local_ip}:{server_port}")
    else:
        print(" Network Access: disabled (SERVER_HOST is localhost)")
    print("\n")

    print(" IMPORTANT:")
    print(" Do NOT close this window.")
    print(" Closing this window will stop")
    print(" the Queue Management System.")
    print("\n")

    print(" Thanks to Engr. Crispolo L. Bernardino, Jr.")
    print(" for Developing this COMELEC Queuing System at no cost to the Commission.")
    print("\n")

    print("=" * 100)
    print("\n")

    serve(
        app,
        host=server_host,
        port=server_port,
        threads=8
    )
