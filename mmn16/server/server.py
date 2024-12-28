# server.py
import base64
import json
import random
import socket
from threading import Thread

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from protocol.protocol import encode_server_response, decode_client_request, ServerResponseCodes, ClientRequestCodes


# Server configuration
# HOST = "127.0.0.1"
# PORT = 12345
# MAX_CLIENTS = 10
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
        self.clients = {}
        self.registration_codes_and_data = {}
        self.shared_key = None
        self.private_key = serialization.load_pem_private_key(Server.SERVER_PRIVATE_KEY, password=None,
                                                              backend=default_backend())
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((host, port))
        self.socket.listen(max_clients)

    def send_by_secure_channel(self, client_socket):
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

    def start_server(self, client_socket):
        while True:
            verify_code, verify_payload = self.get_client_requests(client_socket)
            if verify_code == ClientRequestCodes.RegisterRequest:
                registration_code = self.send_by_secure_channel(client_socket)
                server.registration_codes_and_data = {"registration_code": registration_code,
                                                      "user_info": verify_payload}

            verify_code, verify_payload = self.decrypt_long_msg(client_socket)
            registration_code = verify_payload["verification_code"]

            if verify_code == ClientRequestCodes.VerifyCodeRequest:  # VerifyCodeRequest
                if registration_code in server.registration_codes_and_data.values():
                    print(f"[SUCCESS] Registration code {registration_code} verified.")
                    # Store client public key
                    public_key_str = verify_payload.get("client_public_key")
                    client_public_key = serialization.load_pem_public_key(public_key_str.encode("utf-8"))
                    print("typeof client_public_key1: ", type(client_public_key))
                    print("typeof public_key_str1: ", type(public_key_str))
                    server.clients[server.registration_codes_and_data["user_info"]["phone"]] = {
                        "public_key": client_public_key,
                        "registration_code": registration_code,
                        "password": server.registration_codes_and_data["user_info"]["password"],
                        "name": server.registration_codes_and_data["user_info"]["name"],
                    }
                    self.send_response(client_socket, client_public_key, ServerResponseCodes.RegistrationSuccess,
                                       {})
                else:
                    print(f"[ERROR] Registration code mismatch.")
                    self.send_response(client_socket, None, ServerResponseCodes.RegistrationFailed,
                                       {})

            verify_code, verify_payload = self.get_client_requests(client_socket)
            if verify_code == ClientRequestCodes.GetUserPublicKeys:
                my_phone_number = verify_payload["my_phone"]
                my_code = verify_payload["my_code"]
                if my_phone_number in server.clients and my_code == server.clients[my_phone_number][
                    "registration_code"]:
                    print("[SUCCESS] Retrieving user public keys.")
                    send_msg_to = verify_payload["send_msg_to"]
                    public_key_str = server.clients[my_phone_number]["public_key"]
                    print("typeof public_key_str: ", type(public_key_str))
                    if send_msg_to in server.clients:
                        public_key = server.clients[send_msg_to]["public_key"]

                        pem_encoded_public_key = public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        req_public_key_str = pem_encoded_public_key.decode("utf-8")
                        print("typeof req_public_key_str: ", type(req_public_key_str))
                        print("typeof public_key_str: ", type(public_key_str))
                        verify_payload = {
                            "client_public_key": req_public_key_str
                        }

                        decoded_message = encode_server_response(
                            response_code=ServerResponseCodes.SendingUserPublicKey,
                            payload=verify_payload
                        )
                        encrypted_msg_from_client = self.encrypt_long_msg(client_socket, public_key_str,
                                                                          decoded_message)
                        json_payload = json.dumps({"chunks": encrypted_msg_from_client})
                        client_socket.sendall(json_payload.encode("utf-8"))
                        print("[SUCCESS] Sending user public keys.")
                    else:
                        self.send_response(client_socket, public_key_str, ServerResponseCodes.UserNotFound, {})
                else:
                    self.send_response(client_socket, None, ServerResponseCodes.VerificationFailed, {})
            verify_code, verify_payload = self.decrypt_long_msg(client_socket)
            if verify_code == ClientRequestCodes.SendMsgToUser:
                send_msg_to_phone = verify_payload["message_to"]

                print("[SUCCESS] Sending message to user.")

    def get_client_requests(self, client_socket) -> tuple[ClientRequestCodes, dict]:
        usr_msg = client_socket.recv(1024)
        decrypted_msg = self.private_key.decrypt(
            usr_msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decoded_message = decrypted_msg.decode("utf-8").strip()
        verify_code, verify_payload = decode_client_request(decoded_message)
        return verify_code, verify_payload

    def send_response(self, client_socket, client_public_key, response_code, payload):
        response = encode_server_response(
            response_code=response_code,
            payload=payload
        )
        if client_public_key is None:
            client_socket.send(response)
        else:
            encrypted_response = client_public_key.encrypt(
                response.encode("utf-8"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            client_socket.send(encrypted_response)

    def decrypt_long_msg(self, client_socket):
        msg = client_socket.recv(2048)
        msg_str = msg.decode("utf-8")
        msg_json = json.loads(msg_str)
        encrypted_chunks_base64 = msg_json["chunks"]
        encrypted_chunks = [base64.b64decode(chunk) for chunk in encrypted_chunks_base64]
        decrypted_chunks = []
        for encrypted_chunk in encrypted_chunks:
            decrypted_chunk = server.private_key.decrypt(
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
        return decode_client_request(decoded_message)

    def encrypt_long_msg(self, client_socket, public_key_str, decoded_message):
        chunk_size = 190
        message_bytes = decoded_message.encode('utf-8')
        chunks = [message_bytes[i:i + chunk_size] for i in range(0, len(message_bytes), chunk_size)]

        encrypted_chunks = []
        for chunk in chunks:
            encrypted_chunk = public_key_str.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(encrypted_chunk)
        encrypted_chunks_base64 = [base64.b64encode(chunk).decode('utf-8') for chunk in
                                   encrypted_chunks]
        return encrypted_chunks_base64

    def listen(self):
        while True:
            client_socket, address = self.socket.accept()
            print("Connection from: " + str(address))

            Thread(target=self.start_server, args=(client_socket,)).start()


if __name__ == "__main__":
    server = Server('127.0.0.1', 12345, 10)
    server.listen()

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
