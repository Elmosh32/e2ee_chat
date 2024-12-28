# client.py
from cryptography.hazmat.primitives import serialization, hashes
import re
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64
import json
from protocol.protocol import ServerResponseCodes, ClientRequestCodes, encode_client_request, decode_server_response
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
    """
    Send a registration request to the server and handle the response.

    :param self:
    :return: Tuple of (success, message)
    """
    payload = {
        "phone": self.phone_number,
        "password": self.password,
        "name": self.name
    }

    request = encode_client_request(
        request_code=ClientRequestCodes.RegisterRequest,
        payload=payload
    )

    send_encrypted_request(self, request)
    response = self.socket.recv(1024).decode()
    response_code, response_payload = decode_server_response(response)
    self.client_code = response_payload["registration_code"]

    if response_code == ServerResponseCodes.SendRegistrationCode:  # SendRegistrationCode
        public_key = get_my_public_key(self)
        public_key_str = public_key.decode("utf-8")
        verify_payload = {
            "verification_code": self.client_code,
            "client_public_key": public_key_str
        }
        decoded_message = encode_client_request(
            request_code=ClientRequestCodes.VerifyCodeRequest,
            payload=verify_payload
        )
        encrypted_chunks_base64 = encrypt_long_msg(self, self.server_public_key, decoded_message)
        json_payload = json.dumps({"chunks": encrypted_chunks_base64})
        self.socket.sendall(json_payload.encode("utf-8"))

        verify_code, verify_payload = get_encrypted_response(self)
        if verify_code == ServerResponseCodes.RegistrationSuccess:
            return True, "Registration successful"
        else:
            return False, verify_payload.get("message", "Registration failed")
    elif response_code == ServerResponseCodes.RegistrationFailed:  # RegistrationFailed
        return False, response_payload.get("message", "Registration failed")
    else:
        return False, "Unexpected server response"


def send_message(self: "Client") -> tuple[bool, str]:
    phone_to_sent_msg = input("Please enter the number of the user you want to send a message to: ")
    payload = {
        "my_phone": self.phone_number,
        "my_code": self.client_code,
        "send_msg_to": phone_to_sent_msg,
    }

    send_msg_req = encode_client_request(
        request_code=ClientRequestCodes.GetUserPublicKeys,
        payload=payload
    )

    send_encrypted_request(self, send_msg_req)
    server_respnse, user_public_key = decrypt_long_msg(self)
    if server_respnse == ServerResponseCodes.UserNotFound:
        return False, "User not found"
    print("server_respnse", server_respnse)
    print("user_public_key", user_public_key)
    public_key_str = user_public_key.get("client_public_key")
    client_public_key = serialization.load_pem_public_key(public_key_str.encode("utf-8"))

    message = input("Please enter the message you want to send: ")
    payload = {
        "message_from": self.phone_number,
        "message": message
    }

    msg_to_user = encode_client_request(
        request_code=ClientRequestCodes.SendMsgToUser,
        payload=payload
    )

    encrypted_msg_to_user = encrypt_long_msg(self, client_public_key, msg_to_user)

    payload = {
        "message_to": phone_to_sent_msg,
        "message": encrypted_msg_to_user,
    }

    msg_to_server = encode_client_request(
        request_code=ClientRequestCodes.SendMsgToUser,
        payload=payload
    )

    encrypted_msg_to_server = encrypt_long_msg(self, self.server_public_key, msg_to_server)
    json_payload = json.dumps({"chunks": encrypted_msg_to_server})
    self.socket.sendall(json_payload.encode("utf-8"))
    # *** until here

    response = self.socket.recv(1024).decode()

    response_code, response_payload = decode_server_response(response)
    if response_code.value == 2200:
        return True, "Message sent successfully"
    elif response_code.value == ServerResponseCodes.UserNotFound:
        return False, "User not found"
    else:
        return False, response_payload.get("message", "Failed to send message")


def decrypt_long_msg(self) -> tuple[ClientRequestCodes, int]:
    msg = self.socket.recv(2048)
    msg_str = msg.decode("utf-8")
    msg_json = json.loads(msg_str)
    encrypted_chunks_base64 = msg_json["chunks"]
    encrypted_chunks = [base64.b64decode(chunk) for chunk in encrypted_chunks_base64]
    decrypted_chunks = []
    for encrypted_chunk in encrypted_chunks:
        decrypted_chunk = self.client_private_key.decrypt(
            encrypted_chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_chunks.append(decrypted_chunk)
    final_message = b"".join(decrypted_chunks)
    decoded_message = final_message.decode("utf-8").strip()
    return decode_server_response(decoded_message)


def send_encrypted_request(self: "Client", request):
    ciphertext = self.server_public_key.encrypt(
        request.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    self.socket.sendall(ciphertext)


def get_encrypted_response(self: "Client"):
    verify_response = self.socket.recv(1024)

    decrypted_msg = self.client_private_key.decrypt(
        verify_response,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decode_server_response(decrypted_msg.decode("utf-8"))


def get_my_public_key(self: "Client"):
    pem_encoded_public_key = self.client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_encoded_public_key


def encrypt_long_msg(self: "Client", public_key, decoded_message: str) -> list[str]:
    chunk_size = 190
    message_bytes = decoded_message.encode('utf-8')
    chunks = [message_bytes[i:i + chunk_size] for i in range(0, len(message_bytes), chunk_size)]

    encrypted_chunks = []
    for chunk in chunks:
        encrypted_chunk = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_chunks.append(encrypted_chunk)
    encrypted_chunks_base64 = [base64.b64encode(chunk).decode('utf-8') for chunk in encrypted_chunks]
    return encrypted_chunks_base64


# Example usage
def main():
    # phone = get_user_phone()
    # password = get_user_password()
    # name = input("Enter name: ")
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
    action = input("choose an action(s-send message, q-quit): ")
    if action == 's':
        status, status_str = send_message(client)
        print(status_str)
        print(status)
    elif action == 'q':
        print("Goodbye!")
        client.socket.close()


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


# def receive_messages(sock):
#     while True:
#         try:
#             message = sock.recv(1024).decode("utf-8")
#             if message:
#                 print(f"\n[SERVER] {message}")
#             else:
#                 break
#         except ConnectionResetError:
#             print("[DISCONNECTED] Server disconnected.")
#             break
#
# def main():
#     client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     client_socket.connect((HOST, PORT))
#
#     # Enter client ID
#     client_id = input("Enter your client ID: ").strip()
#     client_socket.send(client_id.encode("utf-8"))
#
#     # Start thread to listen for incoming messages
#     threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()
#
#     # Send messages to server
#     while True:
#         try:
#             message = input("Enter message (format: SEND:<ID>|<Message>): ")
#             client_socket.send(message.encode("utf-8"))
#         except KeyboardInterrupt:
#             print("\n[DISCONNECTED] Exiting...")
#             client_socket.close()
#             break


def login_user():
    pass
    # phone_number = input("Enter phone number: ")
    # password = input("Enter password: ")

    # if user_exists(phone_number, password):
    #     print("Login successful!")
    # else:
    #     print("Invalid phone number or password.")

# def register_user():
#     phone_number = get_user_phone()
#     password = get_user_password()
#     name = input("Enter name: ")
#     return phone_number, password, name
#     if user_exists(phone_number):
#         print("User already registered.")
#         return
#
#     with open("../users.txt", "a") as file:
#         file.write(f"{phone_number},{password}\n")
#     print("Registration successful!")
