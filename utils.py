
from functools import wraps

from flask import redirect, url_for, session

def login_required(login_path):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if 'user' in session:
                return view(*args, **kwargs)
            else:
                return redirect(url_for(login_path))
        return wrapped
    return decorator

def login(user):
    session['user'] = user
    return user

def logout():
    if 'user' in session:
        del session['user']

def current_user():
    return session.get('user', None)
