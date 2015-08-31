
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

app = Flask(__name__)
app.debug = True
app.secret_key = 'lol'
app.config['OAUTH1_PROVIDER_ENFORCE_SSL'] = False
app.config['OAUTH1_PROVIDER_KEY_LENGTH'] = (10, 100)
app.config['OAUTH1_PROVIDER_REALMS'] = ['r']
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
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
    return '''
        Index page of user: {user}
        <br />
        visit <a href="/client-list">/client-list</a> to get consumer key/secrets.
        '''.format(user=session['user'])


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return '''
            <p>The username is "user" and the password is "pass".</p>
            <br />
            <form method="post" action="{}">
                Username
                <input type="text" name="username" />
                <br />
                Password
                <input type="password" name="password" />
                <input type="submit" />
            </form>
            '''.format(url_for('login'))
    else:
        u = request.form['username']
        p = request.form['password']
        if u == 'user' and p == 'pass':
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
    c = Client(current_user(), ['http://localhost:8000/oauth-callback'])
    assert c.default_realms == ['r'], repr(c.default_realms)
    clients.append(c)
    return jsonify(
            client_key=c.client_key,
            client_secret=c.client_secret)

@app.route('/client-list')
@login_required('login')
def client_list():
    add_hard_coded_client()
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
@provider.request_token_handler
def request_token():
    return {}

@app.route('/oauth/authorize', methods=['GET', 'POST'])
@login_required('login')
@log_at(logging.info)
#@block_after_return
@provider.authorize_handler
def authorize(*args, **kwargs):
    if request.method == 'GET':
        rt = kwargs['resource_owner_key']   # This is somehow a request token.
        t = [t for t in request_tokens
                if t.token == rt][0]
        assert isinstance(t, RequestToken)
        c = t.client
        assert isinstance(c, Client)
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

def add_hard_coded_client():
    ck = '38zgEsThKKD26hRcpJr3353Fd3rEQW'
    cs = '87b6cbQrT2PPTiwI4M72NDQDVV0s6vJzFeXHNz7c'
    user = current_user()
    if user is not None:
        if len([c for c in clients
                if c.client_key == ck]) == 0:
            c = Client(
                    user,
                    redirect_uris=['http://localhost:8000/oauth-callback'])
            assert c.default_realms == ['r'], repr(c.default_realms)
            c.client_key = ck
            c.client_secret = cs
            clients.append(c)

def main():
    logging.basicConfig(level=logging.DEBUG)
    app.run('127.0.0.1', 5000)

if __name__ == '__main__':
    main()
