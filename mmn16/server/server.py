# server.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from db import save_pending_registration, verify_registration_code
from protocol import encode_server_response, decode_client_request, ServerResponseCodes, ClientRequestCodes

import random
import socket
import threading


# Server configuration
# HOST = "127.0.0.1"
# PORT = 12345
# MAX_CLIENTS = 10
# server_socket.bind(('0.0.0.0', 12345))

class Server:
    def __init__(self):
        self.clients = {}
        self.registration_codes_and_data = {}
        self.shared_key = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = "127.0.0.1"
        self.port = 12345
        self.max_clients = 10


def send_by_secure_channel(client_socket):
    registration_code = random.randint(100000, 999999)
    payload = {
        "registration_code": registration_code,
    }

    # Encode the request using the protocol
    response = encode_server_response(
        response_code=ServerResponseCodes.SendRegistrationCode,
        payload=payload
    )
    try:
        client_socket.send(response.encode())
        return registration_code
    except Exception as e:
        print(f"[ERROR] Failed to send registration code: {e}")


# Main server function
def start_server():
    server = Server()
    server.socket.bind((server.host, server.port))
    server.socket.listen(server.max_clients)
    print(f"[SERVER STARTED] Listening on {server.host}:{server.port}")
    while True:
        client_socket, client_address = server.socket.accept()
        client_id = client_socket.recv(1024).decode("utf-8").strip()
        verify_code, verify_payload = decode_client_request(client_id)

        if verify_code.value == 1100:
            registration_code = send_by_secure_channel(client_socket)
            server.registration_codes_and_data = {"registration_code": registration_code, "user_info": verify_payload}

        client_id = client_socket.recv(1024).decode("utf-8").strip()
        verify_code, verify_payload = decode_client_request(client_id)
        registration_code = verify_payload["verification_code"]

        if verify_code.value == 1101:
            if registration_code in server.registration_codes_and_data.values():
                print(f"[SUCCESS] Registration code {registration_code} exists in server's registration codes.")

                public_key_str = verify_payload.get("client_public_key")
                public_key = serialization.load_pem_public_key(public_key_str.encode("utf-8"))

                server.clients[server.registration_codes_and_data["user_info"]["phone"]] = {
                    "public_key": public_key,
                    "password": server.registration_codes_and_data["user_info"]["password"],
                    "name": server.registration_codes_and_data["user_info"]["name"],
                }

                response = encode_server_response(
                    response_code=ServerResponseCodes.RegistrationSuccess,
                    payload={"message": "Registration successful."}
                )
                try:
                    client_socket.send(response.encode())

                except Exception as e:
                    print(f"[ERROR] Failed to send registration success response: {e}")
            else:
                print(f"[ERROR] Registration code {registration_code} not found in server's registration codes.")

            if verify_code.value == 1105:
                pass
    # # Start a thread for sending messages from server to clients
    # threading.Thread(target=send_message_to_client, daemon=True).start()
    #
    # while True:
    #     client_socket, client_address = server_socket.accept()
    #
    #     # Ask client for ID
    #     client_socket.send("Enter your client ID: ".encode("utf-8"))
    #     client_id = client_socket.recv(1024).decode("utf-8").strip()
    #
    #     if client_id in clients:
    #         client_socket.send("Client ID already taken. Disconnecting...".encode("utf-8"))
    #         client_socket.close()
    #     else:
    #         clients[client_id] = client_socket
    #         threading.Thread(target=handle_client, args=(client_socket, client_address, client_id)).start()


if __name__ == "__main__":
    start_server()

'''
*******************************  MY END OF SERVER *********************************
'''

# Function for server to send messages to specific clients
# def send_message_to_client():
#     while True:
#         target_client_id = input("Enter the client ID to send a message: ").strip()
#         if target_client_id not in clients:
#             print(f"Client {target_client_id} not found.")
#             continue
#
#         message = input("Enter the message to send: ").strip()
#         target_socket = clients[target_client_id]
#         try:
#             target_socket.send(f"[SERVER MESSAGE]: {message}".encode("utf-8"))
#         except Exception as e:
#             print(f"Failed to send message to {target_client_id}: {e}")


# def handle_register_request(client_socket, payload):
#     """
#     Handles the initial registration request (phone, password, name).
#     """
#     phone = payload.get("phone")
#     password = payload.get("password")
#     name = payload.get("name")
#
#     # Validate data
#     if not phone or not password or not name:
#         response = encode_server_response(ServerResponseCodes.RegistrationFailed,
#                                           {"message": "Invalid registration data."})
#         client_socket.send(response.encode())
#         return
#
#     # Generate verification code
#     verification_code = str(random.randint(100000, 999999))
#
#     # Save pending registration
#     save_pending_registration(phone, password, name, verification_code)
#
#     # Send verification code to client
#     response = encode_server_response(ServerResponseCodes.SendRegistrationCode,
#                                       {"verification_code": verification_code})
#     client_socket.send(response.encode())
#
#
# def handle_verification_request(client_socket, payload):
#     """
#     Handles the verification of the temporary code sent to the client.
#     """
#     phone = payload.get("phone")
#     verification_code = payload.get("verification_code")
#
#     # Validate data
#     if not phone or not verification_code:
#         response = encode_server_response(ServerResponseCodes.RegistrationFailed,
#                                           {"message": "Invalid verification data."})
#         client_socket.send(response.encode())
#         return
#
#     # Verify the code
#     success = verify_registration_code(phone, verification_code)
#
#     if success:
#         response = encode_server_response(ServerResponseCodes.RegistrationSuccess,
#                                           {"message": "Registration completed successfully."})
#     else:
#         response = encode_server_response(ServerResponseCodes.RegistrationFailed,
#                                           {"message": "Invalid verification code."})
#
#     client_socket.send(response.encode())
#
#
# # Handle individual client connections
# def handle_client(client_socket, client_address, client_id):
#     print(f"[NEW CONNECTION] {client_id} ({client_address}) connected.")
#
#     try:
#         while True:
#             # Receive message from client
#             message = client_socket.recv(1024).decode("utf-8")
#             if not message:
#                 print(f"[DISCONNECT] {client_id} disconnected.")
#                 break
#
#             print(f"[MESSAGE FROM {client_id}] {message}")
#             if message.startswith("request_code"):
#                 payload = decode_client_request(message)
#                 handle_register_request(client_socket, payload)
#                 print("payload: ", payload)
#             else:
#                 print("error1111")
#
#             # Parse and handle message
#             if message.startswith("SEND:"):
#                 message = message[5:]  # Remove 'SEND:' from the message
#                 parts = message.split("|", 2)
#
#                 if len(parts) == 2:
#                     target_client_id, msg_content = parts[0], parts[1]
#                     if target_client_id in clients:
#                         target_socket = clients[target_client_id]
#                         try:
#                             target_socket.send(f"Message from {client_id}: {msg_content}".encode("utf-8"))
#                         except Exception as e:
#                             print(f"[ERROR] Failed to send message to {target_client_id}: {e}")
#                             client_socket.send(f"Failed to send message to {target_client_id}".encode("utf-8"))
#                     else:
#                         print("error2")
#
#                         client_socket.send(f"Client {target_client_id} not found.".encode("utf-8"))
#                 else:
#                     print("error3")
#
#                     client_socket.send("Invalid command format. Use SEND:<ID>|<Message>".encode("utf-8"))
#             else:
#                 print("error4")
#
#                 client_socket.send("Invalid command. Use SEND:<ID>|<Message>".encode("utf-8"))
#
#     except ConnectionResetError:
#         print(f"[DISCONNECT] {client_id} disconnected.")
#     finally:
#         # Remove client from the global dictionary
#         if client_id in clients:
#             del clients[client_id]
#         client_socket.close()
#         print("error45")
#
#
# # יצירת מפתחות אסימטריים
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
# )
# public_key = private_key.public_key()
#
# # שליחת המפתח הציבורי ללקוח
# server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server_socket.listen(1)
# print("Server is listening...")
#
# conn, addr = server_socket.accept()
# print(f"Connection established with {addr}")
#
# # שליחת המפתח הציבורי
# public_key_pem = public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )
# conn.send(public_key_pem)
#
# # קבלת מפתח סימטרי מוצפן
# encrypted_key = conn.recv(1024)
# symmetric_key = private_key.decrypt(
#     encrypted_key,
#     padding.OAEP(
#         mgf=padding.MGF1(algorithm=hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None
#     )
# )
# print("Symmetric key received and decrypted.")
#
# # קבלת הודעה מוצפנת
# iv = conn.recv(16)
# ciphertext = conn.recv(1024)
#
# # פענוח הודעה
# cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
# decryptor = cipher.decryptor()
# plaintext = decryptor.update(ciphertext) + decryptor.finalize()
# print("Decrypted message from client:", plaintext.decode())
#
# conn.close()
# server_socket.close()
