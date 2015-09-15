
from functools import wraps

from flask import redirect, url_for, session

from storage import users

_SESSION_USER_KEY = 'user_id'

def login_required(login_path):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if _SESSION_USER_KEY in session:
                return view(*args, **kwargs)
            else:
                return redirect(url_for(login_path))
        return wrapped
    return decorator

def login(user):
    session[_SESSION_USER_KEY] = user.username

def logout():
    if _SESSION_USER_KEY in session:
        del session[_SESSION_USER_KEY]

def current_user():
    user_id = session.get('user_id', None)
    if user_id is None:
        raise Exception("No user currently logged in.")
    else:
        return [u for u in users if u.username == user_id][0]

def log_at(level):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            level("Calling function {}".format(f))
            level("The args are: {}".format(repr(args)))
            level("The kwargs are: {}".format(repr(kwargs)))
            ret = f(*args, **kwargs)
            level("The return value is: {}".format(ret))
            return ret
        return wrapped
    return decorator

def block_after_return(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        ret = f(*args, **kwargs)
        import code
        code.interact(local=vars())
        return ret
    return decorator
