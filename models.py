
from werkzeug.security import gen_salt

class User:

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __repr__(self):
        return "<User(username={}, password={})>".format(
                self.username, self.password)

class Client:

    def __init__(self, user, redirect_uris):
        self.user = user
        self.redirect_uris = redirect_uris
        self.client_key = gen_salt(30)
        self.client_secret = gen_salt(40)
        self.default_realms = ['r']

    def __repr__(self):
        return ("<Client(user={}, redirect_uris={}, "
                "client_key={}, client_secret={}, "
                "default_realms={})>").format(
                    self.user, self.redirect_uris,
                    self.client_key, self.client_secret, self.default_realms)

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

    def __repr__(self):
        return ("<RequestToken(client={}, user={}, "
                "redirect_uri={}, realms={}, "
                "token={}, secret={}, verifier={})>").format(
                    self.client, self.user, self.redirect_uri, self.realms,
                    self.token, self.secret, self.verifier)

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

    def __repr__(self):
        return ("<Nonce(client_key={}, timestamp={}, nonce={}, "
                "request_token={}, access_token={})>").format(
                    self.client_key, self.timestamp, self.nonce,
                    self.request_token, self.access_token)

class AccessToken:

    def __init__(self, client, user):
        self.client = client
        self.user = user
        self.realms = ['r']
        self.token = gen_salt(30)
        self.secret = gen_salt(40)

    def __repr__(self):
        return ("<AccessToken(client={}, user={}, realms={}, "
                "token={}, secret={})>").format(
                    self.client, self.user, self.realms,
                    self.token, self.secret)
