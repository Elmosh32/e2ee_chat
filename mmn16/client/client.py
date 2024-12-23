# client.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import re
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from pycparser.c_ast import While
import socket
import json
from protocol import ClientRequestCodes, encode_client_request, decode_server_response
import socket
import threading

# Client configuration
HOST = "127.0.0.1"
PORT = 12345


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
        self.server_public_key = None
        self.shared_key = None


def register(self: "Client", server_host: str, server_port: int) -> tuple[bool, str]:
    """
    Send a registration request to the server and handle the response.

    :param self:
    :param server_host: Server IP address
    :param server_port: Server port number
    :return: Tuple of (success, message)
    """

    try:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((server_host, server_port))

        payload = {
            "phone": self.phone_number,
            "password": self.password,
            "name": self.name
        }

        request = encode_client_request(
            request_code=ClientRequestCodes.RegisterRequest,
            payload=payload
        )

        self.socket.send(request.encode())
        response = self.socket.recv(1024).decode()
        response_code, response_payload = decode_server_response(response)
        response_payload = response_payload["registration_code"]

        if response_code.value == 2102:  # SendRegistrationCode
            # how to send verification request with rsa 

            #
            # encrypted_verification_code = self.server_public_key.encrypt(
            #     response_payload.encode(),
            #     padding.OAEP(
            #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
            #         algorithm=hashes.SHA256(),
            #         label=None
            #     )
            # )
            # encrypted_verification_code_str = encrypted_verification_code.hex()

            # Send verification request
            pem_encoded_public_key = self.client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key_str = pem_encoded_public_key.decode("utf-8")
            verify_payload = {
                "verification_code": response_payload,
                "client_public_key": public_key_str
            }

            verify_request = encode_client_request(
                request_code=ClientRequestCodes.VerifyCodeRequest,
                payload=verify_payload
            )

            self.socket.send(verify_request.encode())

            verify_response = self.socket.recv(1024).decode()

            verify_code, verify_payload = decode_server_response(verify_response)
            if verify_code.value == 2100:  # RegistrationSuccess
                return True, "Registration successful"
            else:
                return False, verify_payload.get("message", "Registration failed")

        elif response_code.value == 2101:  # RegistrationFailed
            return False, response_payload.get("message", "Registration failed")

        else:
            return False, "Unexpected server response"

    except Exception as e:
        print("gere10")
        return False, f"Error: {str(e)}"

    finally:
        # Close the socket connection
        self.socket.close()


def send_message(self: "Client", server_host: str, server_port: int) -> tuple[bool, str]:
    phone_to_sent_msg = input("Please enter the number of the user you want to send a message to: ")
    message = input("Please enter the message you want to send: ")
    try:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((server_host, server_port))
        payload = {
            "phone": phone_to_sent_msg,
            "message": message
        }
        request = encode_client_request(
            request_code=ClientRequestCodes.SendMsgToUser,
            payload=payload
        )
        self.socket.send(request.encode())
        response = self.socket.recv(1024).decode()
        response_code, response_payload = decode_server_response(response)
        if response_code.value == 2200:
            return True, "Message sent successfully"
        else:
            return False, response_payload.get("message", "Failed to send message")
    finally:
        self.socket.close()


# Example usage
def main():
    server_host = 'localhost'  # Replace with your server's IP
    server_port = 12345  # Replace with your server's port
    phone = None
    password = None
    name = None

    while True:
        action = input("Welcome! Press 'l' to login or 'r' to register: ")
        if action == 'r':
            # phone = get_user_phone()
            # password = get_user_password()
            # name = input("Enter name: ")
            phone = input("Enter phone number (10 digits): ")
            password = input(
                "Enter password (at least 8 characters, including uppercase, lowercase, number, and special character): ")
            name = input("Enter name: ")
            client = Client(
                password=password,
                phone_number=phone,
                name=name)
            success, message = register(
                client, server_host, server_port
            )
            break
        elif action == 'l':
            login_user()
            break
        else:
            print("Invalid selection. Please try again.")

    send_message(client, server_host, server_port)


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


#
# # חיבור לשרת
# client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# client_socket.connect(('127.0.0.1', 12345))
#
# # קבלת מפתח ציבורי מהשרת
# public_key_pem = client_socket.recv(1024)
# public_key = serialization.load_pem_public_key(public_key_pem)
#
# # יצירת מפתח סימטרי
# symmetric_key = os.urandom(32)
#
# # שליחת המפתח הסימטרי המוצפן לשרת
# encrypted_key = public_key.encrypt(
#     symmetric_key,
#     padding.OAEP(
#         mgf=padding.MGF1(algorithm=hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None
#     )
# )
# client_socket.send(encrypted_key)
#
# # הצפנת הודעה
# message = "Hello, Server!"
# iv = os.urandom(16)
# cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
# encryptor = cipher.encryptor()
# ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
#
# # שליחת הודעה
# client_socket.send(iv)
# client_socket.send(ciphertext)
#
# client_socket.close()
#
