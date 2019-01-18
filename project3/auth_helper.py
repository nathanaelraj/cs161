import random, sys
from functools import wraps
from hashlib import sha256
import database
from flask import *

def generate_session_id():
    return '{:090x}'.format(random.randrange(16**90))

def check_login(username, password):
    hashed_password = sha256(password.encode()).hexdigest()
    correct_hash = database.fetchone("SELECT hash FROM users WHERE username='{}';".format(username))
    return correct_hash and correct_hash[0] == hashed_password

def is_valid_username(username):
    return bool(database.fetchone("SELECT 1 FROM users WHERE username='{}';".format(username)))

def get_username_from_session():
    session = request.cookies.get('SESSION_ID', '')
    found_session = database.fetchone("SELECT username FROM sessions WHERE id='{}';".format(session))
    username = found_session[0] if found_session else None
    return username

def get_username(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = get_username_from_session()
        return f(username, *args, **kwargs)
    return decorated_function

# Assume for the actual site, this is replaced by the actual URL.
SERVER_NAME = 'http://127.0.0.1:5000/'

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        referer = request.headers.get('Referer')
        if referer and SERVER_NAME not in referer:
            print('Potential CSRF blocked', file=sys.stderr)
            return 'Potential CSRF blocked', 403
        return f(*args, **kwargs)
    return decorated_function
