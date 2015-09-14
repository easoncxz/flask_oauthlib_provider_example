
import os
import logging

from flask import (Flask, session, request, redirect, url_for, jsonify,
        render_template)
from flask_oauthlib.provider import OAuth1Provider
from jinja2 import escape

from models import Client, User, RequestToken
from utils import (current_user, login_required,
        login as do_login, logout as do_logout,
        log_at, block_after_return)
from storage import users, clients, request_tokens, access_tokens, nonces
from hooks import (load_client,
        load_request_token, save_request_token,
        load_access_token, save_access_token,
        load_verifier, save_verifier,
        load_nonce, save_nonce)

"""
An OAuth Service Provider implementation, using Flask-OAuthlib,
as per Lepture's example.
"""

log = logging.getLogger(__name__)

app = Flask(__name__)
app.debug = True
app.secret_key = 'lol'
app.config.update({
    'OAUTH1_PROVIDER_ENFORCE_SSL': False,
    'OAUTH1_PROVIDER_KEY_LENGTH': (10, 100),
    'OAUTH1_PROVIDER_REALMS': ['email']})
# Not present in Flask-OAuthlib tests:
#os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app.trc = app.test_request_context

provider = OAuth1Provider(app)
provider.clientgetter(load_client)
provider.grantgetter(load_request_token)
provider.grantsetter(save_request_token)
provider.verifiergetter(load_verifier)
provider.verifiersetter(save_verifier)
provider.tokengetter(load_access_token)
provider.tokensetter(save_access_token)
provider.noncegetter(load_nonce)
provider.noncesetter(save_nonce)

@app.route('/')
@login_required('login')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return render_template('login.html',
                login_url=url_for('login'))
    else:
        u = request.form['username']
        p = request.form['password']
        if u == 'admin' and p == 'pass':
            user = do_login(u)
            return redirect(request.args.get('next', url_for('index')))
        else:
            return 'Invalid credentials.'

@app.route('/logout')
def logout():
    do_logout()
    return redirect(url_for('index'))

@app.route('/client')
@login_required('login')
def client():
    c = Client(
        current_user(),
        [
            'http://localhost:8000/authorized',
            'http://localhost/authorized',
        ],
        ['email'])
    assert c.default_realms == ['email'], repr(c.default_realms)
    assert c.realms == ['email'], c.realms
    clients.append(c)
    return jsonify(
            client_key=c.client_key,
            client_secret=c.client_secret)

@app.route('/client-list')
@login_required('login')
def client_list():
    return jsonify(clients=[{
            'client_key': c.client_key,
            'client_secret': c.client_secret}
        for c in clients])

@app.route('/nonce-list')
def nonce_list():
    return jsonify(nonces=[{
            'client_key': n.client_key,
            'timestamp': n.timestamp,
            'nonce': n.nonce,
            'request_token': n.request_token,
            'access_token': n.access_token}
        for n in nonces])

@app.route('/oauth/request_token')
@log_at(log.debug)
@provider.request_token_handler
def request_token():
    return {}

@app.route('/oauth/authorize', methods=['GET', 'POST'])
@login_required('login')
@log_at(log.debug)  # Log again so we see oauth.authorize_handler's return value.
@provider.authorize_handler
@log_at(log.debug)  # Log once.
def authorize(*args, **kwargs):
    if request.method == 'GET':
        rt = kwargs['resource_owner_key']   # This is somehow a request token.
        t = [t for t in request_tokens
                if t.token == rt][0]
        c = t.client
        return render_template('authorize.html',
                url=url_for('authorize'),
                client=repr(c))
    else:
        assert request.method == 'POST', request.method
        return request.form['authorize'] == 'yes'

@app.route('/oauth/access_token')
@provider.access_token_handler
def access_token():
    return {}

@app.route('/test')
def test():
    import code
    v = {}
    v.update(locals())
    v.update(globals())
    code.interact(local=v)
    return 'Done.'

@app.route('/api/me')
@provider.require_oauth()
def me():
    #import code
    #v = {}
    #v.update(locals())
    #v.update(globals())
    #v.update(vars())
    #code.interact(local=v)
    # ...
    user = request.oauth.user
    assert isinstance(user, User)
    return jsonify(username=user.username)

@app.route('/api/email')
@provider.require_oauth('email')
def email():
    user = current_user()
    return jsonify(
            username=user.username,
            email='same-as-everyone-else@gmail.com')

def add_hard_coded_client():
    ck = 'dev'
    cs = 'dev'
    user = User(username='admin', password='pass')
    log.debug("Created user: {}".format(user))
    client = Client(
            user,
            [
                'http://localhost:8000/authorized',
                'http://localhost/authorized',
            ],
            ['email'],
            'dev',
            'dev')
    log.debug("Created client: {}".format(client))
    users.append(user)
    clients.append(client)

def main():
    logging.basicConfig(level=logging.DEBUG)
    add_hard_coded_client()
    log.debug('Hello, DEBUG.')
    app.run('127.0.0.1', 5000)

if __name__ == '__main__':
    main()
