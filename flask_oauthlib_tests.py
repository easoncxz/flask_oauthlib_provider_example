#!/usr/bin/env python

import unittest
import logging

from models import User, RequestToken, Client, AccessToken, Nonce
from flask_oauthlib_api_spec import FlaskOAuthlibSpecs

CONSUMER_KEY = '123456789012345678901234567890'
CONSUMER_SECRET = '1234567890123456789012345678901234567890'
REQUEST_TOKEN = '123456789012345678901234567890'
REQUEST_TOKEN_SECRET = '1234567890123456789012345678901234567890'
ACCESS_TOKEN = '123456789012345678901234567890'
ACCESS_TOKEN_SECRET = '1234567890123456789012345678901234567890'
TIMESTAMP = 1442305580
NONCE = '1234567890123456789012345678901234567890'
REDIRECT_URI = 'http://localhost:8000/callback'

log = logging.getLogger(__name__)

class ModelsTest(unittest.TestCase, FlaskOAuthlibSpecs):

    def setUp(self):
        self.user = User(username='admin', password='pass')
        self.client = Client(
            user=self.user,
            redirect_uris=[REDIRECT_URI],
            realms=['read'],
            client_key=CONSUMER_KEY,
            client_secret=CONSUMER_SECRET)
        self.request_token = RequestToken(
            client=self.client,
            token=REQUEST_TOKEN,
            secret=REQUEST_TOKEN_SECRET,
            redirect_uri=REDIRECT_URI,
            realms=['read'],
            user=self.user)
        self.access_token = AccessToken(
            client=self.client,
            user=self.user,
            realms=[REDIRECT_URI],
            token=ACCESS_TOKEN,
            secret=ACCESS_TOKEN_SECRET)
        self.nonce = Nonce(
            client_key=self.client.client_key,
            timestamp=TIMESTAMP,
            nonce=NONCE,
            request_token=REQUEST_TOKEN,
            access_token=ACCESS_TOKEN)

    def test_types(self):
        self.test_client(self.client)
        self.test_request_token(self.request_token, User, Client)
        self.test_nonce(self.nonce)
        self.test_access_token(self.access_token, User, Client)

if __name__ == '__main__':
    unittest.main()
