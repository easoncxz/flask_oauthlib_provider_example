
import code
import random

from flask import Flask, request, session, url_for, redirect

from lepture_flask_oauthlib import make_lepture

app = Flask(__name__)
app.debug = True
app.secret_key = 'lol-key'
lepture = make_lepture(
    app,
    '38zgEsThKKD26hRcpJr3353Fd3rEQW',
    '87b6cbQrT2PPTiwI4M72NDQDVV0s6vJzFeXHNz7c')

@app.route('/')
def index():
    ta = session.get('token_credentials')
    if ta is None:
        return '''<a href="{url}">login here.</a>'''.format(
                url=url_for('login'))
    else:
        resp = lepture.get('me')
        return resp.text

@app.route('/login')
def login():
    return lepture.authorize(callback=url_for('callback'))

@app.route('/logout')
def logout():
    if 'token_credentials' in session:
        del session['token_credentials']
    return redirect(url_for('index'))

@app.route('/oauth-callback')
def callback():
    authorized_response = lepture.authorized_response()
    if authorized_response is None:
        return '''You denied us access.'''
    else:
        at = authorized_response['oauth_token']
        ats = authorized_response['oauth_token_secret']
        set_access_token(at, ats)
        return redirect(url_for('index'))

@lepture.tokengetter
def get_access_token(token=None):
    return session.get('token_credentials')

def set_access_token(token, secret):
    session['token_credentials'] = token, secret

def main():
    app.run(host='localhost', port=8000)

if __name__ == '__main__':
    main()
