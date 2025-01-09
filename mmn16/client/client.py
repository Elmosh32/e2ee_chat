# client.py

from cryptography.hazmat.primitives import serialization, hashes
import re
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64
import json
from protocol.protocol import decode_server_response, encode_client_request_code
import socket
# import struct
from chat_console import *

HOST = "127.0.0.1"
PORT = 12345


class Client:
    def __init__(self):
        self.phone_number = None
        self.password = None
        self.name = None
        self.client_public_key = None
        self.client_private_key = None
        self.socket = None
        self.messages_status_socket = None
        self.recv_messages_socket = None
        #        self.recv_messages_socket = None
        self.client_code = None
        self.message_buffer = {}

    def encrypt_message(self, public_key, request, chunk_size=190):
        request = request.encode("utf-8")
        chunks = [request[i:i + chunk_size] for i in range(0, len(request), chunk_size)]
        encrypted_chunks = [
            base64.b64encode(public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )).decode("utf-8") for chunk in chunks
        ]

        return encrypted_chunks

    def decrypt_message(self, received_data):
        data_str = received_data.decode("utf-8")
        msg_json = json.loads(data_str)
        encrypted_chunks_base64 = msg_json["chunks"]
        encrypted_chunks = [base64.b64decode(chunk) for chunk in encrypted_chunks_base64]
        decrypted_chunks = [
            self.client_private_key.decrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ) for chunk in encrypted_chunks
        ]
        final_message = b"".join(decrypted_chunks)
        return decode_server_response(final_message.decode("utf-8"))

    def decrypt_inner_message(self, encrypted_message_base64):
        encrypted_message = base64.b64decode(encrypted_message_base64)
        decrypted_message = self.client_private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode("utf-8")

    def send_request_code(self, request):
        request_code = encode_client_request_code(request)
        print("Request code size : ", len(request_code))
        self.socket.send(request_code)

    def get_my_public_key(self):
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
        self.client_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.client_public_key = self.client_private_key.public_key()
        self.init_main_socket()
        self.init_listening_sockets()


def get_user_phone():
    while True:
        phone_number = input("Enter phone number (10 digits): ")
        if phone_number.isdigit() and len(phone_number) == 10:
            break
        else:
            print("Invalid phone number. Try again.")
            continue

    return phone_number


def get_user_password():
    while True:
        password = input(
            "Enter password (at least 8 characters, including uppercase, lowercase, number, and special character): ")
        if is_valid_password(password):
            break
        else:
            print("Invalid password. Try again.")
            continue

    return password


def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!?@#$%^&*(),.]", password):
        return False
    return True
