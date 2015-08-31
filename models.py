
from werkzeug.security import gen_salt

class User:

    def __init__(self, username, password):
        self.username = username
        self.password = password

class Client:

    def __init__(self, user, redirect_uris):
        self.user = user
        self.redirect_uris = redirect_uris
        self.client_key = gen_salt(30)
        self.client_secret = gen_salt(40)
        self.default_realms = ['r']

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

class RequestToken:

    def __init__(self, client, user, token, secret, redirect_uri):
        self.client = client
        self.user = user
        self.redirect_uri = redirect_uri
        self.realms = ['r']
        self.token = token
        self.secret = secret
        self.verifier = gen_salt(40)

class Nonce:

    def __init__(
            self,
            client_key,
            timestamp,
            nonce,
            request_token,
            access_token):
        self.client_key = client_key
        self.timestamp = timestamp
        self.nonce = nonce
        self.request_token = request_token
        self.access_token = access_token

class AccessToken:

    def __init__(self, client, user):
        self.client = client
        self.user = user
        self.realms = ['r']
        self.token = gen_salt(30)
        self.secret = gen_salt(40)
