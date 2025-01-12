# server.py

import random
import socket
import string
import struct

from threading import Thread
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from protocol.protocol import *
from user import *
from db import *
from utils.security import *
from constants import *


class Server:
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
                print(COMMUNICATION_PRINT + f"Connection from {address} closed" + DEFAULT_PRINT)
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
        payload = decode_client_request(decrypt_message(self.private_key, encrypted_payload))
        if not self.db.user_exists(payload.get("phone")):
            registration_code = self.send_by_secure_channel(client_socket)
            if registration_code:
                self.db.add_pending_registration(registration_code, payload)
        else:
            self.send_response_code(client_socket, ServerResponseCodes.UserAlreadyRegistered)
            print(FAILURE_PRINT + "[FAILURE] Registerion Failed: user already registered" + DEFAULT_PRINT)
            return

    def handle_verify_request(self, client_socket):
        encrypted_payload = client_socket.recv(2048)
        decrypted_message = decode_client_request(decrypt_message(self.private_key, encrypted_payload))
        registration_code = decrypted_message["verification_code"]
        user_info = self.db.get_user_info_from_pending_list(registration_code)

        if user_info is not None:
            pending_message_socket = decrypted_message.get("pending_message_socket")
            recv_msgs_socket = decrypted_message.get("recv_messages_socket")
            public_key_str = decrypted_message.get("client_public_key")
            client_public_key = serialization.load_pem_public_key(public_key_str.encode("utf-8"))
            phone_number = user_info[registration_code]["phone"]
            name = user_info[registration_code]["name"]
            password = user_info[registration_code]["password"]

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
        user = self.db.get_user_by_socket(client_socket)

        decrypted_message = decrypt_signed_message(
            private_key=self.private_key,
            public_key=user.public_key,
            received_data=encrypted_payload
        )
        decrypted_message = decode_client_request(decrypted_message)

        # payload = decode_client_request(decrypt_signed_message(self.private_key, encrypted_payload))
        phone_number = decrypted_message.get("phone")

        pending_message_socket = decrypted_message["pending_message_socket"]
        recv_msgs_socket = decrypted_message["recv_messages_socket"]

        if self.db.user_exists(phone_number):
            user = self.db.get_user(phone_number)
            # here double user maybe delete the check
            login_code = ''.join(random.choices(string.printable, k=20))
            payload = {
                "login_code": login_code
            }
            self.send_response_code(client_socket, ServerResponseCodes.SendLoginCode)
            self.send_encrypted_message(client_socket, user.public_key, payload)
            encrypted_payload = client_socket.recv(2048)
            decrypted_message = decrypt_signed_message(
                private_key=self.private_key,
                public_key=user.public_key,
                received_data=encrypted_payload
            )
            # payload = decode_client_request(decrypt_signed_message(self.private_key, encrypted_payload))
            decrypted_message = decode_client_request(decrypted_message)

            if decrypted_message["code"] == login_code:
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
                        self.send_encrypted_message(messages_status_socket, user.public_key, payload, True)

                if user.user_read_receipt:
                    for read_receipt_from in user.user_read_receipt.keys():
                        self.send_response_code(messages_status_socket, ServerResponseCodes.ReadReceipt)
                        payload = {
                            "read_receipt_from": read_receipt_from,
                        }
                        self.send_encrypted_message(messages_status_socket, user.public_key, payload, True)
                    user.user_read_receipt = {}
                print(SUCCESS_PRINT + f"[SUCCESS] User Login Success" + DEFAULT_PRINT)
            else:
                self.send_response_code(client_socket, ServerResponseCodes.LoginFailed)
                print(FAILURE_PRINT + "[FAILURE] Login Failed: login code mismatch" + DEFAULT_PRINT)
        else:
            self.send_response_code(client_socket, ServerResponseCodes.WrongUserData)
            print(FAILURE_PRINT + "[FAILURE] Login Failed: verification code error" + DEFAULT_PRINT)

    def handle_sending_user_pkey(self, client_socket):
        encrypted_payload = client_socket.recv(2048)
        user = self.db.get_user_by_socket(client_socket)

        decrypted_message = decrypt_signed_message(
            private_key=self.private_key,
            public_key=user.public_key,
            received_data=encrypted_payload
        )
        decrypted_message = decode_client_request(decrypted_message)

        my_phone_number = decrypted_message["my_phone"]
        my_code = decrypted_message["my_code"]
        if self.db.verify_regisered_user(my_phone_number, my_code):
            send_msg_to = decrypted_message["send_msg_to"]
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
                payload = {
                    "client_public_key": req_public_key_str
                }
                self.send_response_code(client_socket, ServerResponseCodes.RegistrationSuccess)
                self.send_encrypted_message(client_socket, public_key_str, payload)
                print(SUCCESS_PRINT + "[SUCCESS] Sending user public key" + DEFAULT_PRINT)
            else:
                self.send_response_code(client_socket, ServerResponseCodes.UserNotFound)
                print(FAILURE_PRINT + "[FAILURE] Sending User Public Key Failed: user doesn't exist" + DEFAULT_PRINT)
        else:
            self.send_response_code(client_socket, ServerResponseCodes.VerificationFailed)
            print(FAILURE_PRINT + "[FAILURE] Sending User Public Key Failed: user not verified" + DEFAULT_PRINT)

    def handle_save_income_messages(self, client_socket):
        encrypted_payload = client_socket.recv(4096)

        # Decrypt the message received from the sender
        decrypted_message = decrypt_signed_message(
            private_key=self.private_key,
            public_key=self.db.get_user_by_socket(client_socket).public_key,
            received_data=encrypted_payload,
        )
        decrypted_message = decode_client_request(decrypted_message)

        # Extract the message details
        msg_to_phone = decrypted_message["message_to"]
        msg_from_phone = decrypted_message["message_from"]
        encrypted_message = decrypted_message["message"]
        signature = decrypted_message["signature"]

        # Verify the signature
        sender = self.db.get_user(msg_from_phone)
        serialized_message = json.dumps({"chunks": encrypted_message})

        if not verify_signature(sender.public_key, serialized_message, signature):
            print("[FAILURE] Invalid message signature. Discarding message.")
            self.send_response_code(client_socket, ServerResponseCodes.VerificationFailed)
            return

        # Save the encrypted message to the recipient's queue
        recipient = self.db.get_user(msg_to_phone)
        recipient.messages.setdefault(msg_from_phone, [])
        recipient.messages[msg_from_phone].append(encrypted_message)

        # Notify the recipient if they are online
        if recipient.connected:
            self.send_response_code(recipient.messages_status_socket, ServerResponseCodes.UpdatePendingMessages)
            self.send_encrypted_message(
                recipient.messages_status_socket,
                recipient.public_key,
                {"new_msg_from": msg_from_phone, "num_of_messages": 1},
                True,
            )
            self.send_response_code(client_socket, ServerResponseCodes.SendingMessageToUser)
            print("[SUCCESS] Encrypted message sent to recipient.")
        else:
            self.send_response_code(client_socket, ServerResponseCodes.UserOffline)
            print("[INFO] User is offline. Message saved for later delivery.")

    def handle_send_msg_to_user(self, client_socket, all_messages=False):
        encrypted_payload = client_socket.recv(2048)
        # verify_payload = decode_client_request(decrypt_signed_message(self.private_key, encrypted_payload))
        user = self.db.get_user_by_socket(client_socket)
        # Decrypt the message received from the client
        decrypted_message = decrypt_signed_message(
            private_key=self.private_key,
            public_key=user.public_key,
            received_data=encrypted_payload
        )
        decrypted_message = decode_client_request(decrypted_message)

        phone = decrypted_message["phone_number"]
        contact = self.db.get_user(phone)
        user_recv_msgs_socket = contact.recv_messages_socket

        if all_messages:
            while contact.messages:
                keys_to_remove = []
                for key, message_list in contact.messages.items():
                    while message_list:
                        current_message = message_list.pop(0)
                        message_payload = json.dumps({"chunks": current_message})

                        # Create signature
                        signature = create_signature(self.private_key, message_payload)
                        final_payload = json.dumps({
                            "message": message_payload,
                            "signature": signature
                        }).encode("utf-8")

                        # Send the signed message
                        length = len(final_payload)
                        length_prefix = struct.pack("!I", length)
                        user_recv_msgs_socket.sendall(length_prefix + final_payload)

                    if not message_list:
                        keys_to_remove.append(key)

                for key in keys_to_remove:
                    self.send_read_messages_update(key, phone)
                    del contact.messages[key]
                if not contact.messages:
                    print(
                        SUCCESS_PRINT + f"[SUCCESS] All pending messages for: {phone} sent successfully" + DEFAULT_PRINT)
        else:
            msg_from = decrypted_message["messages_from"]
            message_list = contact.messages[msg_from]

            while message_list:
                current_message = message_list.pop(0)
                message_payload = json.dumps({"chunks": current_message})

                # Create signature
                signature = create_signature(self.private_key, message_payload)
                final_payload = json.dumps({
                    "message": message_payload,
                    "signature": signature
                }).encode("utf-8")

                # Send the signed message
                length = len(final_payload)
                length_prefix = struct.pack("!I", length)
                user_recv_msgs_socket.sendall(length_prefix + final_payload)
                print(
                    SUCCESS_PRINT + f"[SUCCESS] Sending all messages from \"{msg_from}\" to \"{phone}\"" + DEFAULT_PRINT)

            if not message_list:
                self.send_read_messages_update(msg_from, phone)
                del contact.messages[msg_from]

    def handle_client_disconected(self, client_socket):
        encrypted_payload = client_socket.recv(2048)
        user = self.db.get_user_by_socket(client_socket)

        decrypted_message = decrypt_signed_message(
            private_key=self.private_key,
            public_key=user.public_key,
            received_data=encrypted_payload
        )
        decrypted_message = decode_client_request(decrypted_message)

        # verify_payload = decode_client_request(decrypt_signed_message(self.private_key, encrypted_payload))
        user_phone = decrypted_message["phone_number"]
        self.db.remove_user(user_phone)
        print(SUCCESS_PRINT + f"[SUCCESS] {user_phone} disconnected succesfuly" + DEFAULT_PRINT)

    def send_read_messages_update(self, user_phone, contact_phone):
        user = self.db.get_user(user_phone)
        payload = {
            "read_receipt_from": contact_phone,
        }
        payload = encode_server_response(payload)
        encrypted_msg_from_client = encrypt_message(user.public_key, payload)
        json_payload = json.dumps({"chunks": encrypted_msg_from_client}).encode("utf-8")

        # Create signature
        signature = create_signature(self.private_key, json_payload.decode("utf-8"))

        # Add signature to the payload
        final_payload = json.dumps({
            "message": json_payload.decode("utf-8"),
            "signature": signature
        }).encode("utf-8")

        # Send the payload
        length = len(final_payload)
        length_prefix = struct.pack("!I", length)

        if user.connected:
            self.send_response_code(user.messages_status_socket, ServerResponseCodes.ReadReceipt)
            user.messages_status_socket.sendall(length_prefix + final_payload)
        else:
            user.user_read_receipt.setdefault(contact_phone, [])
            user.user_read_receipt[contact_phone].append(final_payload)

    @staticmethod
    def send_response_code(client_socket, response):
        response_code = encode_server_response_code(response)
        client_socket.send(response_code)

    @staticmethod
    def send_encrypted_message(sock, public_key, payload, packed=False):
        payload = encode_server_response(payload)
        encrypted_msg = encrypt_message(public_key, payload)
        json_payload = json.dumps({"chunks": encrypted_msg})
        # Create signature
        private_key = serialization.load_pem_private_key(Server.SERVER_PRIVATE_KEY, None)

        signature = create_signature(private_key, json_payload)

        # Create final payload
        final_payload = json.dumps({
            "message": json_payload,
            "signature": signature
        }).encode("utf-8")

        # Send payload
        if packed:
            length = len(final_payload)
            length_prefix = struct.pack("!I", length)
            sock.sendall(length_prefix + final_payload)
        else:
            sock.sendall(final_payload)

    def listen(self):
        while True:
            client_socket, address = self.socket.accept()
            print("Connection from: " + str(address))
            Thread(target=self.start_server, args=(client_socket, address)).start()


if __name__ == "__main__":
    server = Server(HOST, PORT, MAX_CLIENTS)
    print("Server listening on port", PORT)
    server.listen()
