# server.py
import base64
import json
import random
import socket
import string
import struct
from threading import Thread

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from protocol.protocol import encode_server_response_code, encode_server_response, decode_client_request, \
    decode_client_request_code, ServerResponseCodes, ClientRequestCodes
from user import *
from db import *

# Server configuration
HOST = "127.0.0.1"
PORT = 12345
MAX_CLIENTS = 10

DEFAULT_PRINT = '\033[0m'
FAILURE_PRINT = '\033[31m'
SUCCESS_PRINT = '\033[32m'


# server_socket.bind(('0.0.0.0', 12345))

class Server:
    SERVER_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoUibKE1c+9HkG8mSdAJ8
fRBhRsQtJIGtXrSFANN/bGcaLZbQIld3XfnSuD6AfaTTQMYo7cjJz+QbTBBWud3C
xsyr2XMOD4qZ5F6LdK8ydysMPNstGukA+xep3dMUHQiEl4xb6nL/yQ/E6Y16fQ+k
xZCGHTg15CGu6zly9A2DjQLMpB3PF4UYOg3mhtQyPIxiX4XtVQpxGXbqN75+KqUP
HlE/kbkvrMjzc0rS5k1FFvoGYv8DJMXPlFUYUtQv8uS6EMV6C24rjXMJlYh/R3YZ
5s+sGzHFIi7qE/tyXrLZn8o01cGmzP1FNJfWOOKBKePD/14kLJnvOEuzpv3goPvj
EwIDAQAB
-----END PUBLIC KEY-----"""

    SERVER_PRIVATE_KEY = b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQChSJsoTVz70eQb
yZJ0Anx9EGFGxC0kga1etIUA039sZxotltAiV3dd+dK4PoB9pNNAxijtyMnP5BtM
EFa53cLGzKvZcw4PipnkXot0rzJ3Kww82y0a6QD7F6nd0xQdCISXjFvqcv/JD8Tp
jXp9D6TFkIYdODXkIa7rOXL0DYONAsykHc8XhRg6DeaG1DI8jGJfhe1VCnEZduo3
vn4qpQ8eUT+RuS+syPNzStLmTUUW+gZi/wMkxc+UVRhS1C/y5LoQxXoLbiuNcwmV
iH9Hdhnmz6wbMcUiLuoT+3JestmfyjTVwabM/UU0l9Y44oEp48P/XiQsme84S7Om
/eCg++MTAgMBAAECggEAF1FK9Vmx/spKo2XSIamWW/J5TeTg7e09pnqM3CC3xHFn
jH3IW56vqEuNFowawY+J50x+8FneK4s8ExQtpbOVDG7czZRfzQlp1GWC3fzSW/5C
R64caE6VkLfMHED/IG9x1AM76rpzlpsMCgQlWF1hohqR+Tl+ORxRkLp+jyBBC6rI
J4IbcWweHOaBoj7DkQUcpfCznxWXShmt+Alk0j5pi7Hig4lwVWE4b5bdEhbO5+N8
X+EAV1X/wIjtrtmL6aaCyaDd6XQRuWXDASsiC3JIr6aAcQrYwNk/4GAhVPzxr8RQ
4W18BBJWwP6pD/hZW5XT/cNKWu6bKavL21G+U1fHQQKBgQDSK04HCjcFcKu2G6GW
w/NsLq4RHvUINWUkgoVn1u6A77jFXd9mlHiBjL0PScZyvA3OE0SMVwHfiC4MFejW
4b+G1bSOSGCJnBfBZBXEsUPvOSx3K1uib4eYJQwnyk3RpmD8MK/azOFYUsalwjjq
fAJye3XqLWm7Dqfptqh9qxtAcwKBgQDEdEP2Uf9vZ82ZoqfmSoM/b7uVbbxmmkhm
2o1/KyADoN9Clk6rwgCVU7NGYdGb5OU9+bfrG/KYoNgDTQQhWX1EvCSFkcWmjOOG
eP1GGCxF6idg72xkCWjqMUq6z6psYfjxKS4SvyySyyMwVqJrenxqduBqPu0IhTTd
Hmksdj1K4QKBgQCSMFEcEHzpKdAm4d1qU26051toyVHDnfB2jttguV45DYZGst88
KTYRVuYDBlwlXq1zlG9v9u10oPL2sR6+qVRh47Ct76ZG0e6sNIP3xx3r/qbxVZVt
zYpRyCNGYi/zDnoTsYIA/dYZa6qFji2s3QmOvFXuyBvtY2pk5QsaLrTMBQKBgC1d
o+wX12LEl8fotdkKT/CwPqMtKhqPejS2N4KsVMJBvgzEZPpo3HWfVIDmSd80JnP/
XKdgVs9EJV3txQxme/UJdW2a0ge59Tiya9pp7p9eiSVrZJ5dRer+4wDsv7Azl6cp
GUie+Q4U9tVMzEkBigWT2hLu4RHcoO6G/UaVL2ZBAoGAJ92fwJsp3sKCnpjGJ0ZT
Awl9V/GluevKFHJrJsC7UDlvp0NpLmyBb2HDUglAUQN4sDQ3xgMagFXa/nLh1j/O
JWBZB0B16wtG4NDrxSy0XrGD0xdOcWVQ1/b/DxczAcBQwkf35rHV4a+95HXb4us9
VUQE0ySXS3OhzOpjn5VZOqQ=
-----END PRIVATE KEY-----"""

    def __init__(self, host, port, max_clients):
        self.shared_key = None
        self.private_key = serialization.load_pem_private_key(Server.SERVER_PRIVATE_KEY, password=None,
                                                              backend=default_backend())
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((host, port))
        self.socket.listen(max_clients)
        self.db = DB()

    @staticmethod
    def send_by_secure_channel(client_socket):
        registration_code = random.randint(100000, 999999)
        payload = {
            "registration_code": registration_code,
        }

        response_code = encode_server_response_code(ServerResponseCodes.SendRegistrationCode)
        response = encode_server_response(payload)
        try:
            client_socket.send(response_code)
            client_socket.send(response)
            print(SUCCESS_PRINT + "[SUCCESS] Registration code sent succesfuly" + DEFAULT_PRINT)
            return registration_code
        except Exception as e:
            print(FAILURE_PRINT + f"[FAILURE] Failed to send registration code: {e}" + DEFAULT_PRINT)
            return False

    def start_server(self, client_socket, address):
        while True:
            request_code = client_socket.recv(22)
            if not request_code:
                print(f"Connection from {address} closed")
                break
            code = decode_client_request_code(request_code)
            match code:
                case ClientRequestCodes.RegisterRequest.value:
                    self.handle_registerion_request(client_socket)
                case ClientRequestCodes.VerifyCodeRequest.value:
                    self.handle_verify_request(client_socket)
                case ClientRequestCodes.LoginRequest.value:
                    self.handle_client_login_request(client_socket)
                case ClientRequestCodes.GetUserPublicKey.value:
                    self.handle_sending_user_pkey(client_socket)
                case ClientRequestCodes.SendMsgToUser.value:
                    self.handle_save_income_messages(client_socket)
                case ClientRequestCodes.GetAllMessages.value:
                    self.handle_send_msg_to_user(client_socket, all_messages=True)
                case ClientRequestCodes.GetMessagesFromUser.value:
                    self.handle_send_msg_to_user(client_socket)
                case ClientRequestCodes.DisconnectRequest.value:
                    self.handle_client_disconected(client_socket)

    def handle_registerion_request(self, client_socket):
        encrypted_payload = client_socket.recv(2048)
        payload = self.decrypt_message(encrypted_payload)

        if not self.db.user_exists(payload.get("phone")):
            # self.send_response_code(client_socket, ServerResponseCodes.ValidUserData)
            registration_code = self.send_by_secure_channel(client_socket)
            if registration_code:
                self.db.add_pending_registration(registration_code, payload)
        else:
            self.send_response_code(client_socket, ServerResponseCodes.UserAlreadyRegistered)
            print(FAILURE_PRINT + "[FAILURE] Registerion Failed: user already registered" + DEFAULT_PRINT)
            return

    def handle_verify_request(self, client_socket):
        encrypted_payload = client_socket.recv(2048)
        payload = self.decrypt_message(encrypted_payload)
        registration_code = payload["verification_code"]
        user_info = self.db.get_user_info_from_pending_list(registration_code)

        if user_info is not None:
            public_key_str = payload.get("client_public_key")
            client_public_key = serialization.load_pem_public_key(public_key_str.encode("utf-8"))
            phone_number = user_info[registration_code]["phone"]
            name = user_info[registration_code]["name"]
            password = user_info[registration_code]["password"]
            pending_message_socket = user_info[registration_code]["pending_message_socket"]
            recv_msgs_socket = user_info[registration_code]["recv_messages_socket"]

            self.send_response_code(client_socket, ServerResponseCodes.RegistrationSuccess)

            pending_messages_socket_new_address = eval(pending_message_socket)
            messages_status_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            messages_status_socket.connect(pending_messages_socket_new_address)

            recv_messages_socket_new_address = eval(recv_msgs_socket)
            recv_messages_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            recv_messages_socket.connect(recv_messages_socket_new_address)

            user = User(phone_number, client_public_key, client_socket, messages_status_socket, recv_messages_socket,
                        registration_code,
                        password, name)
            self.db.add_registered_user(phone_number, user)
            print(SUCCESS_PRINT + f"[SUCCESS] Registration code {registration_code} verified." + DEFAULT_PRINT)
        else:
            self.send_response_code(client_socket, ServerResponseCodes.RegistrationFailed)
            print(FAILURE_PRINT + "[FAILURE] Registerion Failed: registration code mismatch" + DEFAULT_PRINT)

    def handle_client_login_request(self, client_socket):
        encrypted_payload = client_socket.recv(2048)
        payload = self.decrypt_message(encrypted_payload)
        phone_number = payload.get("phone")
        password = payload.get("password")
        code = payload.get("verification_code")
        pending_message_socket = payload["pending_message_socket"]
        recv_msgs_socket = payload["recv_messages_socket"]

        if self.db.user_exists(phone_number):
            user = self.db.get_user(phone_number)
            user_saved_password = user.password
            user_code = user.registration_code

            if user_saved_password == password and user_code == code:
                login_code = ''.join(random.choices(string.printable, k=20))
                payload = {
                    "login_code": login_code
                }
                payload = encode_server_response(payload)
                encrypted_msg_from_client = self.encrypt_message(client_socket, user.public_key, payload)
                json_payload = json.dumps({"chunks": encrypted_msg_from_client})
                self.send_response_code(client_socket, ServerResponseCodes.SendLoginCode)
                client_socket.sendall(json_payload.encode("utf-8"))
                encrypted_payload = client_socket.recv(2048)
                payload = self.decrypt_message(encrypted_payload)
                if payload["code"] == login_code:
                    user.connected = True
                    user.user_socket = client_socket
                    pending_messages_socket_new_address = eval(pending_message_socket)
                    messages_status_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    messages_status_socket.connect(pending_messages_socket_new_address)

                    recv_messages_socket_new_address = eval(recv_msgs_socket)
                    recv_messages_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    recv_messages_socket.connect(recv_messages_socket_new_address)

                    user.messages_status_socket = messages_status_socket
                    user.recv_messages_socket = recv_messages_socket
                    self.send_response_code(client_socket, ServerResponseCodes.LoginSuccess)
                    if user.messages:
                        for sending_message_number in user.messages.keys():
                            self.send_response_code(messages_status_socket, ServerResponseCodes.UpdatePendingMessages)
                            payload = {
                                "new_msg_from": sending_message_number,
                                "num_of_messages": len(user.messages[sending_message_number])
                            }
                            payload = encode_server_response(payload)
                            encrypted_msg_from_client = self.encrypt_message(messages_status_socket, user.public_key,
                                                                             payload)
                            json_payload = json.dumps({"chunks": encrypted_msg_from_client}).encode("utf-8")
                            length = len(json_payload)
                            length_prefix = struct.pack("!I", length)
                            messages_status_socket.sendall(length_prefix + json_payload)

                    if user.user_read_receipt:
                        for read_receipt_from in user.user_read_receipt.keys():
                            self.send_response_code(messages_status_socket, ServerResponseCodes.ReadReceipt)
                            payload = {
                                "read_receipt_from": read_receipt_from,
                            }
                            payload = encode_server_response(payload)
                            encrypted_msg_from_client = self.encrypt_message(messages_status_socket, user.public_key,
                                                                             payload)
                            json_payload = json.dumps({"chunks": encrypted_msg_from_client}).encode("utf-8")
                            length = len(json_payload)
                            length_prefix = struct.pack("!I", length)
                            messages_status_socket.sendall(length_prefix + json_payload)
                        user.user_read_receipt = {}
                    print(SUCCESS_PRINT + f"[SUCCESS] User Login Success" + DEFAULT_PRINT)
                else:
                    self.send_response_code(client_socket, ServerResponseCodes.LoginFailed)
                    print(FAILURE_PRINT + "[FAILURE] Login Failed: login code mismatch" + DEFAULT_PRINT)
            else:
                self.send_response_code(client_socket, ServerResponseCodes.WrongUserData)
                print(FAILURE_PRINT + "[FAILURE] Login Failed: verification code error" + DEFAULT_PRINT)
        else:
            self.send_response_code(client_socket, ServerResponseCodes.UserNotExist)
            print(FAILURE_PRINT + "[FAILURE] Login Failed: user doesn't exist" + DEFAULT_PRINT)

    def handle_sending_user_pkey(self, client_socket):
        encrypted_payload = client_socket.recv(2048)
        payload = self.decrypt_message(encrypted_payload)

        my_phone_number = payload["my_phone"]
        my_code = payload["my_code"]
        if self.db.verify_regisered_user(my_phone_number, my_code):
            send_msg_to = payload["send_msg_to"]
            if self.db.verify_regisered_user(my_phone_number, my_code) is False:
                self.send_response_code(client_socket, ServerResponseCodes.VerificationFailed)

            user = self.db.get_user(my_phone_number)
            public_key_str = user.public_key
            if self.db.user_exists(send_msg_to):
                contact = self.db.get_user(send_msg_to)
                public_key = contact.public_key

                pem_encoded_public_key = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                req_public_key_str = pem_encoded_public_key.decode("utf-8")
                verify_payload = {
                    "client_public_key": req_public_key_str
                }
                payload = encode_server_response(verify_payload)
                encrypted_msg_from_client = self.encrypt_message(client_socket, public_key_str, payload)
                json_payload = json.dumps({"chunks": encrypted_msg_from_client})

                self.send_response_code(client_socket, ServerResponseCodes.RegistrationSuccess)
                client_socket.sendall(json_payload.encode("utf-8"))
                print(SUCCESS_PRINT + "[SUCCESS] Sending user public key" + DEFAULT_PRINT)
            else:
                self.send_response_code(client_socket, ServerResponseCodes.UserNotFound)
                print(FAILURE_PRINT + "[FAILURE] Sending User Public Key Failed: user doesn't exist" + DEFAULT_PRINT)
        else:
            self.send_response_code(client_socket, ServerResponseCodes.VerificationFailed)
            print(FAILURE_PRINT + "[FAILURE] Sending User Public Key Failed: user not verified" + DEFAULT_PRINT)

    def handle_save_income_messages(self, client_socket):
        encrypted_request = client_socket.recv(2048)
        verify_payload = self.decrypt_message(encrypted_request)
        msg_to_phone = verify_payload["message_to"]
        msg_from_phone = verify_payload["message_from"]

        contact = self.db.get_user(msg_to_phone)
        contact_public_key = contact.public_key
        messages_status_socket = contact.messages_status_socket
        user_recv_msgs_socket = contact.recv_messages_socket
        payload = encode_server_response(verify_payload)
        encrypted_msg = self.encrypt_message(user_recv_msgs_socket, contact_public_key, payload)
        json_payload = json.dumps({"chunks": encrypted_msg})

        contact.messages.setdefault(msg_from_phone, [])
        contact.messages[msg_from_phone].append(json_payload)

        if contact.connected:
            self.send_response_code(messages_status_socket, ServerResponseCodes.UpdatePendingMessages)

            payload = {
                "new_msg_from": msg_from_phone,
                "num_of_messages": 1
            }

            payload = encode_server_response(payload)

            encrypted_msg_from_client = self.encrypt_message(messages_status_socket, contact.public_key, payload)
            json_payload = json.dumps({"chunks": encrypted_msg_from_client}).encode("utf-8")
            length = len(json_payload)
            length_prefix = struct.pack("!I", length)
            messages_status_socket.sendall(length_prefix + json_payload)

            self.send_response_code(client_socket, ServerResponseCodes.SendingMessageToUser)
            print(SUCCESS_PRINT + "[SUCCESS] Sending message to user" + DEFAULT_PRINT)
        else:
            self.send_response_code(client_socket, ServerResponseCodes.UserOffline)
            print(
                FAILURE_PRINT + "[FAILURE] User Disconnected: message will be sent to user when he will connect" + DEFAULT_PRINT)

    def handle_send_msg_to_user(self, client_socket, all_messages=False):
        encrypted_request = client_socket.recv(2048)
        verify_payload = self.decrypt_message(encrypted_request)
        phone = verify_payload["phone_number"]
        contact = self.db.get_user(phone)
        user_recv_msgs_socket = contact.recv_messages_socket
        if all_messages:
            while contact.messages:
                keys_to_remove = []
                for key, message_list in contact.messages.items():
                    while message_list:
                        current_message = message_list.pop(0)
                        message_bytes = current_message.encode("utf-8")
                        length = len(message_bytes)
                        length_prefix = struct.pack("!I", length)
                        user_recv_msgs_socket.sendall(length_prefix + message_bytes)

                    if not message_list:
                        keys_to_remove.append(key)

                for key in keys_to_remove:
                    # todo: sent confirmation for the sender that the contact read his messages
                    send_receipt_to = self.db.get_user(key)
                    payload = {
                        "read_receipt_from": phone,
                    }
                    payload = encode_server_response(payload)
                    encrypted_msg_from_client = self.encrypt_message(send_receipt_to.messages_status_socket,
                                                                     send_receipt_to.public_key,
                                                                     payload)
                    json_payload = json.dumps({"chunks": encrypted_msg_from_client}).encode("utf-8")
                    length = len(json_payload)
                    length_prefix = struct.pack("!I", length)

                    if send_receipt_to.connected:
                        self.send_response_code(send_receipt_to.messages_status_socket, ServerResponseCodes.ReadReceipt)
                        send_receipt_to.messages_status_socket.sendall(length_prefix + json_payload)
                    else:
                        send_receipt_to.user_read_receipt.setdefault(phone, [])
                        send_receipt_to.user_read_receipt[phone].append(json_payload)

                        # contact.messages[key].append(json_payload)

                    del contact.messages[key]

                if not contact.messages:
                    print(
                        SUCCESS_PRINT + f"[SUCCESS] all the pedding messages for: {phone} sends succesfully" + DEFAULT_PRINT)
        else:
            msg_from = verify_payload["messages_from"]
            message_list = contact.messages[msg_from]
            while message_list:
                current_message = message_list.pop(0)
                message_bytes = current_message.encode("utf-8")
                length = len(message_bytes)
                length_prefix = struct.pack("!I", length)
                user_recv_msgs_socket.sendall(length_prefix + message_bytes)
                print(SUCCESS_PRINT + f"[SUCCESS] sending all messages from: {msg_from} to: {phone}" + DEFAULT_PRINT)

            if not message_list:
                del contact.messages[msg_from]
                print(f"All messages from user {msg_from} have been sent and removed from the dictionary.")

    def handle_client_disconected(self, client_socket):
        encrypted_request = client_socket.recv(2048)
        verify_payload = self.decrypt_message(encrypted_request)
        user_phone = verify_payload["phone_number"]
        self.db.remove_user(user_phone)
        print(SUCCESS_PRINT + f"[SUCCESS] {user_phone} disconnected succesfuly" + DEFAULT_PRINT)

    def send_response_code(self, client_socket, response):
        response_code = encode_server_response_code(response)
        client_socket.send(response_code)

    def encrypt_message(self, client_socket, client_public_key, payload, chunk_size=190):
        if client_public_key is None:
            client_socket.send(payload)
        else:
            chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
            encrypted_chunks = [
                base64.b64encode(client_public_key.encrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )).decode("utf-8") for chunk in chunks
            ]
            return encrypted_chunks

    def decrypt_message(self, encrypted_msg):
        data_str = encrypted_msg.decode("utf-8")
        msg_json = json.loads(data_str)
        encrypted_chunks_base64 = msg_json["chunks"]
        encrypted_chunks = [base64.b64decode(chunk) for chunk in encrypted_chunks_base64]
        decrypted_chunks = [
            self.private_key.decrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ) for chunk in encrypted_chunks
        ]
        final_message = b"".join(decrypted_chunks)

        decoded_message = final_message.decode("utf-8").strip()
        return decode_client_request(decoded_message)

    def listen(self):
        while True:
            client_socket, address = self.socket.accept()
            print("Connection from: " + str(address))
            Thread(target=self.start_server, args=(client_socket, address)).start()


if __name__ == "__main__":
    server = Server(HOST, PORT, MAX_CLIENTS)
    print("Server listening on port", PORT)
    server.listen()
