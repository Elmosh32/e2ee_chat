# client.py

import socket

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from chat_console import get_client_data
from protocol.protocol import *
from constants import *


class Client:
    def __init__(self):
        self.phone_number = None
        self.password = None
        self.name = None
        self.client_public_key = None
        self.private_key = None
        self.socket = None
        self.messages_status_socket = None
        self.recv_messages_socket = None
        self.client_code = None
        self.message_buffer = {}

    def send_request_code(self, request):
        request_code = encode_client_request_code(request)
        self.socket.send(request_code)

    def get_public_key(self):
        pem_encoded_public_key = self.client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_encoded_public_key

    def init_listening_sockets(self):
        self.messages_status_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.messages_status_socket.bind((HOST, 0))
        self.messages_status_socket.listen()

        self.recv_messages_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.recv_messages_socket.bind((HOST, 0))
        self.recv_messages_socket.listen()

    def init_main_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((HOST, PORT))

    def create_client(self, status=None):
        phone, password, name = get_client_data(status)
        self.phone_number = phone
        self.password = password
        self.name = name
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE
        )
        self.client_public_key = self.private_key.public_key()
        self.init_main_socket()
        self.init_listening_sockets()
