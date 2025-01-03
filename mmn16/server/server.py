# server.py
import base64
import json
import random
import socket
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
            return registration_code
        except Exception as e:
            print(f"[ERROR] Failed to send registration code: {e}")

    def start_server(self, client_socket):
        while True:
            request_code = client_socket.recv(22)
            if not request_code:
                print("client disconnected")
                break
            code = decode_client_request_code(request_code)
            match code:
                case ClientRequestCodes.RegisterRequest.value:
                    self.handle_registerion_request(client_socket)
                case ClientRequestCodes.VerifyCodeRequest.value:
                    self.handle_verify_request(client_socket)
                case ClientRequestCodes.GetUserPublicKey.value:
                    self.handle_sending_user_pkey(client_socket)
                case ClientRequestCodes.SendMsgToUser.value:
                    self.handle_send_msg_to_user(client_socket)
                case ClientRequestCodes.DisconnectRequest.value:
                    self.handle_client_disconected(client_socket)

    def handle_registerion_request(self, client_socket):
        encrypted_payload = client_socket.recv(2048)
        payload = self.decrypt_message(encrypted_payload)
        self.db.user_in_pending_list(payload.get("phone"))

        if not self.db.user_exists(payload.get("phone")):
            print("here11")
            self.send_response_code(client_socket, ServerResponseCodes.ValidUserData)

            registration_code = self.send_by_secure_channel(client_socket)
            self.db.add_pending_registration(registration_code, payload)
        else:
            print("here22")

            self.send_response_code(client_socket, ServerResponseCodes.UserAlreadyRegistered)
            return

    def handle_verify_request(self, client_socket):
        encrypted_payload = client_socket.recv(2048)
        payload = self.decrypt_message(encrypted_payload)
        registration_code = payload["verification_code"]
        user_info = self.db.get_user_info_from_pending_list(registration_code)

        if user_info is not None:
            print(f"[SUCCESS] Registration code {registration_code} verified.")
            public_key_str = payload.get("client_public_key")
            client_public_key = serialization.load_pem_public_key(public_key_str.encode("utf-8"))
            print("user_info", user_info.values())
            phone_number = user_info[registration_code]["phone"]
            name = user_info[registration_code]["name"]
            password = user_info[registration_code]["password"]
            user = User(phone_number, client_public_key, client_socket, registration_code,
                        password, name)
            self.db.add_registered_user(phone_number, user)
            self.send_response_code(client_socket, ServerResponseCodes.RegistrationSuccess)
        else:
            print(f"[ERROR] Registration code mismatch.")
            self.send_response_code(client_socket, ServerResponseCodes.RegistrationFailed)

    def handle_sending_user_pkey(self, client_socket):
        encrypted_payload = client_socket.recv(2048)
        payload = self.decrypt_message(encrypted_payload)

        my_phone_number = payload["my_phone"]
        my_code = payload["my_code"]
        if self.db.verify_regisered_user(my_phone_number, my_code):
            print("[SUCCESS] Retrieving user public keys.")
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
                print("[SUCCESS] Sending user public keys.")
            else:
                self.send_response_code(client_socket, ServerResponseCodes.UserNotFound)
        else:
            self.send_response_code(client_socket, ServerResponseCodes.VerificationFailed)

    def handle_send_msg_to_user(self, client_socket):
        encrypted_request = client_socket.recv(2048)
        verify_payload = self.decrypt_message(encrypted_request)
        send_msg_to_phone = verify_payload["message_to"]
        contact = self.db.get_user(send_msg_to_phone)
        contact_socket = contact.user_socket
        contact_public_key = contact.public_key
        payload = encode_server_response(verify_payload)
        encrypted_msg = self.encrypt_message(contact_socket, contact_public_key, payload)
        json_payload = json.dumps({"chunks": encrypted_msg})
        self.send_response_code(contact_socket, ServerResponseCodes.UserSendsMessage)
        contact_socket.sendall(json_payload.encode("utf-8"))
        self.send_response_code(client_socket, ServerResponseCodes.SendingMessageToUser)
        print("[SUCCESS] Sending message to user.")

    def handle_client_disconected(self, client_socket):
        encrypted_request = client_socket.recv(2048)
        verify_payload = self.decrypt_message(encrypted_request)
        user_phone = verify_payload["phone_number"]
        self.db.remove_user(user_phone)

    def send_response_code(self, client_socket, response):
        response_code = encode_server_response_code(response)
        # print("side: ", len(response_code))
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

            Thread(target=self.start_server, args=(client_socket,)).start()


if __name__ == "__main__":
    server = Server(HOST, PORT, MAX_CLIENTS)
    print("Server listening on port", PORT)
    server.listen()
