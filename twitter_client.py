
import code
import random

from flask import Flask, request, session, url_for, redirect

from twitter_flask_oauthlib import make_twitter

app = Flask(__name__)
app.debug = True
app.secret_key = 'lol-key'
twitter = make_twitter(app)

@app.route('/')
def index():
    ta = session.get('twitter_access')
    if ta is None:
        return '''<a href="{url}">login here.</a>'''.format(
                url=url_for('login'))
    else:
        resp = twitter.get('account/verify_credentials.json')
        screen_name = resp.data['screen_name']
        return '''Hello, {name}!
            <br>
            Your count is: {count}'''.format(
                name=screen_name,
                count=request.args.get('count', '???'))

@app.route('/login')
def login():
    count = random.randrange(0, 100)
    return twitter.authorize(
            callback=url_for('callback', count=count, _external=True))

@app.route('/logout')
def logout():
    session.pop('twitter_access', None)
    return redirect(url_for('index'))

@app.route('/oauth-callback')
def callback():
    authorized_response = twitter.authorized_response()
    if authorized_response is None:
        return '''You denied us access.'''
    else:
        #code.interact(local=vars())
        at = authorized_response['oauth_token']
        ats = authorized_response['oauth_token_secret']
        set_twitter_access_token(at, ats)
        count = request.args.get('count', '?')
        return redirect(url_for('index', count=count))

@twitter.tokengetter
def get_twitter_access_token(token=None):
    return session.get('twitter_access')

def set_twitter_access_token(token, secret):
    session['twitter_access'] = token, secret

def main():
    app.run(host='localhost', port=8000)

if __name__ == '__main__':
    main()
