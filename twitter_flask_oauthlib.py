
import os

from flask_oauthlib.client import OAuth

"""
A Flask-OAuthlib binding for Twitter.
"""

__all__ = ['make_twitter']

def make_twitter(flask_app):
    oauth = OAuth(flask_app)
    return oauth.remote_app('twitter',
            base_url='https://api.twitter.com/1.1/',
            request_token_url='https://api.twitter.com/oauth/request_token',
            access_token_url='https://api.twitter.com/oauth/access_token',
            authorize_url='https://api.twitter.com/oauth/authenticate',
            consumer_key=os.getenv('TWITTER_CONSUMER_KEY'),
            consumer_secret=os.getenv('TWITTER_CONSUMER_SECRET'))
