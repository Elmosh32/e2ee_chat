# client.py
from cryptography.hazmat.primitives import serialization, hashes
import re
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64
import json
from protocol.protocol import ServerResponseCodes, ClientRequestCodes, encode_client_request, decode_server_response, \
    encode_client_request_code, decode_server_response_code
import socket

HOST = "127.0.0.1"
PORT = 12345
# self.server_host = 'localhost'
# self.server_port = 12345

public_key_pem = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoUibKE1c+9HkG8mSdAJ8
fRBhRsQtJIGtXrSFANN/bGcaLZbQIld3XfnSuD6AfaTTQMYo7cjJz+QbTBBWud3C
xsyr2XMOD4qZ5F6LdK8ydysMPNstGukA+xep3dMUHQiEl4xb6nL/yQ/E6Y16fQ+k
xZCGHTg15CGu6zly9A2DjQLMpB3PF4UYOg3mhtQyPIxiX4XtVQpxGXbqN75+KqUP
HlE/kbkvrMjzc0rS5k1FFvoGYv8DJMXPlFUYUtQv8uS6EMV6C24rjXMJlYh/R3YZ
5s+sGzHFIi7qE/tyXrLZn8o01cGmzP1FNJfWOOKBKePD/14kLJnvOEuzpv3goPvj
EwIDAQAB
-----END PUBLIC KEY-----"""


class Client:
    def __init__(self, password, phone_number, name):
        self.name = name
        self.password = password
        self.phone_number = phone_number
        self.client_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.client_public_key = self.client_private_key.public_key()
        self.shared_key = None
        self.server_public_key = serialization.load_pem_public_key(
            public_key_pem)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((HOST, PORT))
        self.client_code = None


def register(self: "Client") -> tuple[bool, str]:
    payload = {
        "phone": self.phone_number,
        "password": self.password,
        "name": self.name
    }
    payload = encode_client_request(payload)
    encrypted_msg = encrypt_message(self.server_public_key, payload)
    json_payload = json.dumps({"chunks": encrypted_msg})
    send_request_code(self.socket, ClientRequestCodes.RegisterRequest)
    self.socket.sendall(json_payload.encode("utf-8"))
    response_code = self.socket.recv(2048).decode()
    code = decode_server_response_code(response_code)
    if code == ServerResponseCodes.SendRegistrationCode.value:
        encrypted_payload = self.socket.recv(2048).decode()
        payload = decode_server_response(encrypted_payload)
        self.client_code = payload["registration_code"]
        public_key = get_my_public_key(self)
        public_key_str = public_key.decode("utf-8")
        payload = {
            "verification_code": self.client_code,
            "client_public_key": public_key_str
        }

        payload = encode_client_request(payload)
        encrypted_chunks_base64 = encrypt_message(self.server_public_key, payload)
        json_payload = json.dumps({"chunks": encrypted_chunks_base64})
        send_request_code(self.socket, ClientRequestCodes.VerifyCodeRequest)
        self.socket.sendall(json_payload.encode("utf-8"))
        server_response_code = self.socket.recv(2048)

        if server_response_code == ServerResponseCodes.RegistrationSuccess.value:
            return True, "Registration successful"
        else:
            return False, "Registration failed"
    elif response_code == ServerResponseCodes.RegistrationFailed.value:  # RegistrationFailed
        return False, "Registration failed"
    else:
        return False, "Unexpected server response"


def send_message(self: "Client") -> tuple[bool, str]:
    phone_to_sent_msg = input("Please enter the number of the user you want to send a message to: ")
    payload = {
        "my_phone": self.phone_number,
        "my_code": self.client_code,
        "send_msg_to": phone_to_sent_msg,
    }

    payload = encode_client_request(payload)
    encrypted_msg = encrypt_message(self.server_public_key, payload)
    json_payload = json.dumps({"chunks": encrypted_msg})
    send_request_code(self.socket, ClientRequestCodes.GetUserPublicKey)
    self.socket.sendall(json_payload.encode("utf-8"))
    server_response = self.socket.recv(2048)

    if server_response == ServerResponseCodes.UserNotFound.value:
        return False, "User not found"
    else:
        encrypted_payload = self.socket.recv(2048)
        user_public_key = decrypt_message(self, encrypted_payload)
        public_key_str = user_public_key.get("client_public_key")
        client_public_key = serialization.load_pem_public_key(public_key_str.encode("utf-8"))

        message = input("Please enter the message you want to send: ")
        payload = {
            "message_from": self.phone_number,
            "message": message
        }

        payload = encode_client_request(payload)
        encrypted_msg_to_user = encrypt_message(client_public_key, payload)
        payload = {
            "message_to": phone_to_sent_msg,
            "message": encrypted_msg_to_user,
        }

        payload = encode_client_request(payload)
        encrypted_msg_to_server = encrypt_message(self.server_public_key, payload)
        json_payload = json.dumps({"chunks": encrypted_msg_to_server})
        send_request_code(self.socket, ClientRequestCodes.SendMsgToUser)
        self.socket.sendall(json_payload.encode("utf-8"))
        server_response = self.socket.recv(23).decode("utf-8")
        server_response = decode_server_response_code(server_response)

        if server_response == ServerResponseCodes.SendingMessageToUser.value:
            return True, "Message sent successfully"
        elif server_response == ServerResponseCodes.UserNotFound.value:
            return False, "User not found"
        else:
            return False, "Failed to send message"


def receive_messages(self: "Client"):
    server_response = self.socket.recv(23).decode("utf-8")
    server_response = decode_server_response_code(server_response)
    while True:
        if server_response == ServerResponseCodes.UserSendsMessage.value:
            encrypted_payload = self.socket.recv(2048)

            # Decode the payload into a JSON object
            encrypted_payload = json.loads(encrypted_payload.decode("utf-8"))
            print("decoded_payload:", encrypted_payload)

            # Extract and decrypt the chunks
            encrypted_chunks_base64 = encrypted_payload["chunks"]
            decrypted_chunks = [
                self.client_private_key.decrypt(
                    base64.b64decode(chunk),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ) for chunk in encrypted_chunks_base64
            ]

            # Combine the outer decrypted chunks into the original JSON-encoded message
            final_message = b"".join(decrypted_chunks).decode("utf-8")

            # Decode the final message into a JSON object
            final_message_json = json.loads(final_message)

            # Extract the inner encrypted message
            encrypted_message_base64 = final_message_json["payload"]["message"][0]
            encrypted_message = base64.b64decode(encrypted_message_base64)

            # Decrypt the inner message
            decrypted_message = self.client_private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            decoded_message = decrypted_message.decode("utf-8")
            data = json.loads(decoded_message)
            message_from = data["payload"]["message_from"]
            message = data["payload"]["message"]
            print(message_from, " sends you - ", message)
            return


def disconnect(self: "Client"):
    send_request_code(self.socket, ClientRequestCodes.DisconnectRequest)
    print("disconnected")


def encrypt_message(public_key, request, chunk_size=190):
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


def send_request_code(sock, request):
    request_code = encode_client_request_code(request)
    sock.send(request_code)


def get_my_public_key(self: "Client"):
    pem_encoded_public_key = self.client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_encoded_public_key


def main():
    # phone = get_user_phone()
    # password = get_user_password()
    # name = input("Enter name: ")
    # client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # client_socket.connect((HOST, PORT))

    print("Welcome to the chat.")
    phone = input("Enter phone number (10 digits): ")
    password = input(
        "Enter password (at least 8 characters, including uppercase, lowercase, number, and special character): ")
    name = input("Enter name: ")
    client = Client(
        password=password,
        phone_number=phone,
        name=name)
    print("Welcome ", name, " to the chat. Please select an action:")

    while True:
        action = input("Press 'l' to login or 'r' to register: ")
        if action == 'r':
            register(client)
            break
        elif action == 'l':
            login_user()
            break
        else:
            print("Invalid selection. Please try again.\n")

    while True:
        action = input("choose an action(s-send message, r-receive message, d-discconect from server, q-quit): ")
        if action == 's':
            status, status_str = send_message(client)
            print(status_str)
            print(status)
        elif action == 'r':
            receive_messages(client)
        elif action == 'd':
            disconnect(client)
        elif action == 'q':
            print("Goodbye!")
            client.socket.close()
            break
        else:
            print("Invalid selection. Please try again.\n")


if __name__ == "__main__":
    main()


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


def login_user():
    pass
