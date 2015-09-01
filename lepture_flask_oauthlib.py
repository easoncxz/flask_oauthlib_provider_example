
from flask_oauthlib.client import OAuth

"""
Flask-OAuthlib bindings for Lepture's OAuth SP example.
"""

def make_lepture(app, ck, cs):
    oauth = OAuth(app)
    return oauth.remote_app('lepture',
            consumer_key=ck,
            consumer_secret=cs,
            request_token_params={
                'realm': 'r'},
            base_url='http://127.0.0.1:5000/api/',
            request_token_url='http://127.0.0.1:5000/oauth/request_token',
            access_token_method='GET',
            access_token_url='http://127.0.0.1:5000/oauth/access_token',
            authorize_url='http://127.0.0.1:5000/oauth/authorize')
