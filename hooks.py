
import logging

import oauthlib

from models import User, Client, RequestToken, AccessToken, Nonce
from utils import current_user, log_at
from storage import clients, request_tokens, access_tokens, nonces, users

@log_at(logging.debug)
def load_client(client_key):
    try:
        return [c for c in clients if c.client_key == client_key][0]
    except IndexError:
        return None

@log_at(logging.debug)
def load_request_token(token):
    try:
        return [t for t in request_tokens if t.token == token][0]
    except IndexError:
        return None

@log_at(logging.debug)
def save_request_token(token, req):
    assert isinstance(req, oauthlib.common.Request)
    rt = token['oauth_token']
    rts = token['oauth_token_secret']
    client = req.client
    assert type(client) is Client, type(client)
    assert isinstance(req.redirect_uri, str)    # py3
    t = RequestToken(
            client=req.client,
            token=rt,
            secret=rts,
            redirect_uri=req.redirect_uri,
            realms=client.default_realms)  # ??
    request_tokens.append(t)

@log_at(logging.debug)
def load_verifier(verifier, token):
    try:
        return [t for t in request_tokens if (
                t.token == token and t.verifier == verifier)][0]
    except IndexError:
        return None

@log_at(logging.debug)
def save_verifier(token, verifier, *args, **kwargs):
    t = [t for t in request_tokens if t.token == token][0]
    t.verifier = verifier
    t.user = current_user()
    return t

@log_at(logging.debug)
def load_access_token(client_key, token, *args, **kwargs):
    try:
        return [t for t in access_tokens if t.client_key == client_key][0]
    except IndexError:
        return None

@log_at(logging.debug)
def save_access_token(token, req):
    assert type(req) is oauthlib.common.Request, type(req)
    client = req.client
    assert type(client) is Client, type(client)
    user = req.user
    assert type(user) is User, type(user)
    at = token['oauth_token']
    ats = token['oauth_token_secret']
    realms = token['oauth_authorized_realms']
    t = AccessToken(client, user, realms, token=at, secret=ats)
    access_tokens.append(t)

@log_at(logging.debug)
def load_nonce(client_key, timestamp, nonce, request_token, access_token):
    try:
        return [n for n in nonces if (
                n.client_key == client_key and
                n.timestamp == timestamp and
                n.nonce == nonce and
                n.request_token == request_token and
                n.access_token == access_token)][0]
    except IndexError:
        return None

@log_at(logging.debug)
def save_nonce(client_key, timestamp, nonce, request_token, access_token):
    n = Nonce(
        client_key=client_key,
        timestamp=timestamp,
        nonce=nonce,
        request_token=request_token,
        access_token=access_token)
    nonces.append(n)
    return n

