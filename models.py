
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

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_realms(self):
        return ['r']

class RequestToken:

    def __init__(self, client, user, redirect_uri):
        self.client = client
        self.user = user
        self.redirect_uri = redirect_uri
        self.realms = []
        self.token = gen_salt(30)
        self.secret = gen_salt(40)
        self.verifier = gen_salt(40)

class Nonce:

    def __init__(self):
        self.client_key = None
        self.timestamp = None
        self.nonce = None
        self.request_token = None
        self.access_token = None

class AccessToken:

    def __init__(self, client, user):
        self.client = client
        self.user = user
        self.realms = []
        self.token = gen_salt(30)
        self.secret = gen_salt(40)
