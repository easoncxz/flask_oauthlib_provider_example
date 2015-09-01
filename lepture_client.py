import code
import random
import logging

from flask import Flask, request, session, url_for, redirect

from lepture_flask_oauthlib import make_lepture

app = Flask(__name__)
app.debug = True
app.secret_key = 'lol-key'
lepture = make_lepture(app, 'dev_consumer_key', 'dev_consumer_secret')

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
    return lepture.authorize(callback=url_for('callback', _external=True))

@app.route('/logout')
def logout():
    del_access_token()
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
def get_access_token():
    return session.get('token_credentials')

def set_access_token(token, secret):
    session['token_credentials'] = token, secret

def del_access_token():
    session.pop('token_credentials', None)

def main():
    logging.basicConfig(level=logging.DEBUG)
    app.run(host='localhost', port=8000)

if __name__ == '__main__':
    main()
