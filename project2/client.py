"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError


class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)

    def upload(self, name, value):
        # Replace with your implementation
        # Change to represent the share functions
        # We first generate the respective nodes.
        # we need a functon that generates keys.
        # we need a function that automatically decrypts the string and siphons
        # it out into its respectiv parts.
        #we need to figure out which parts of the nodes require mac and which require
        #RSA signatures
        # need to figure out how to do a resolve
        # 
        raise NotImplementedError

    def download(self, name):
        # Replace with your implementation
        raise NotImplementedError

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)

        raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError
