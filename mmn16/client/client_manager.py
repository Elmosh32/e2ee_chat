# client.py
import errno
import struct

# from cryptography.hazmat.primitives import serialization, hashes
# import re
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# import base64
# import json
from protocol.protocol import ServerResponseCodes, ClientRequestCodes, encode_client_request, decode_server_response, \
    decode_server_response_code, SERVER_RESPONSE_SIZE
# import socket
# from chat_console import *
from threading import Thread
import time
from registered_clients import *
from datetime import datetime
from client import *

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


class ClientManager:
    def __init__(self):
        self.server_public_key = serialization.load_pem_public_key(
            public_key_pem)
        self.registered_clients = RegisteredClients()
        self.client = None
        self.print_color = Colors()

    def register(self):
        pending_messages_socket_new_address = self.client.messages_status_socket.getsockname()
        recv_messages_socket_new_address = self.client.recv_messages_socket.getsockname()

        payload = {
            "phone": self.client.phone_number,
            "password": self.client.password,
            "name": self.client.name,
            "pending_message_socket": str(pending_messages_socket_new_address),
            "recv_messages_socket": str(recv_messages_socket_new_address),
        }

        # payload = encode_client_request(payload)
        # encrypted_msg = self.client.encrypt_message(self.server_public_key, payload)
        # json_payload = json.dumps({"chunks": encrypted_msg})
        self.client.send_request_code(ClientRequestCodes.RegisterRequest)
        # self.client.socket.sendall(json_payload.encode("utf-8"))
        self.send_encrypted_message(self.client.socket, payload)

        server_response = self.get_response(self.client.socket)

        # print("code: ", code)

        if server_response == ServerResponseCodes.UserAlreadyRegistered.value:
            print_result(False, "User already exist!")
            return False
        # response_code = self.client.socket.recv(23).decode()
        # code = decode_server_response_code(response_code)
        # print("code: ", code)
        if server_response == ServerResponseCodes.SendRegistrationCode.value:
            encrypted_payload = self.client.socket.recv(2048).decode()
            payload = decode_server_response(encrypted_payload)
            self.client.client_code = payload["registration_code"]
            public_key = self.client.get_my_public_key()
            public_key_str = public_key.decode("utf-8")
            payload = {
                "verification_code": self.client.client_code,
                "client_public_key": public_key_str
            }

            payload = encode_client_request(payload)
            encrypted_chunks_base64 = self.client.encrypt_message(self.server_public_key, payload)
            json_payload = json.dumps({"chunks": encrypted_chunks_base64})
            self.client.send_request_code(ClientRequestCodes.VerifyCodeRequest)
            self.client.socket.sendall(json_payload.encode("utf-8"))

            server_response = self.get_response(self.client.socket)

            if server_response == ServerResponseCodes.RegistrationSuccess.value:
                server_pending_msgs_socket, address = self.client.messages_status_socket.accept()
                self.client.messages_status_socket = server_pending_msgs_socket
                recv_msgs_socket, address = self.client.recv_messages_socket.accept()
                self.client.recv_messages_socket = recv_msgs_socket
                self.registered_clients.add_new_client(self.client)
                print_result(True, "Registered successfully")
                return True
            else:
                print_result(True, "Registration failed")
                return False
        elif server_response == ServerResponseCodes.RegistrationFailed.value:  # RegistrationFailed
            print_result(False, "Registration failed")

            return False
        else:
            print_result(False, "Unexpected server response")

            return False

    def login_user(self):
        attempt = 0
        phone_number, password = get_login_data(attempt)
        registered_client = self.registered_clients.get_client_by_phone(phone_number)
        if registered_client:
            self.client = registered_client
        else:
            return False, "Login failed: permission denied"
        self.client.init_main_socket()
        # self.client.socket.connect((HOST, PORT))
        # if registered_clientss.check_client_data(phone_number, password):
        #     self = registered_clientss.get_client_by_phone(phone_number)
        # else:
        #     attempt = attempt + 1
        #     while attempt <= 3:
        #         phone_number, password = get_login_data(attempt)
        #         if registered_clientss.check_client_data(phone_number, password):
        #             self = registered_clientss.get_client_by_phone(phone_number)
        #             break
        #         attempt = attempt + 1
        self.client.init_listening_sockets()
        pending_messages_socket_new_address = self.client.messages_status_socket.getsockname()
        recv_messages_socket_new_address = self.client.recv_messages_socket.getsockname()

        payload = {
            "phone": phone_number,
            "password": password,
            "verification_code": registered_client.client_code,
            "pending_message_socket": str(pending_messages_socket_new_address),
            "recv_messages_socket": str(recv_messages_socket_new_address),
        }

        # payload = encode_client_request(payload)
        # encrypted_msg = self.client.encrypt_message(self.server_public_key, payload)
        # json_payload = json.dumps({"chunks": encrypted_msg})
        self.client.send_request_code(ClientRequestCodes.LoginRequest)
        # self.client.socket.sendall(json_payload.encode("utf-8"))
        self.send_encrypted_message(self.client.socket, payload)

        server_response = self.get_response(self.client.socket)

        if server_response == ServerResponseCodes.UserNotExist.value:
            return False, "User not found"
        elif server_response == ServerResponseCodes.WrongUserData.value:
            return False, "User name or/and password are incorrect"
        elif server_response == ServerResponseCodes.SendLoginCode.value:
            encrypted_payload = self.client.socket.recv(2048)
            user_public_key = self.client.decrypt_message(encrypted_payload)
            login_code = user_public_key.get("login_code")
            payload = {
                "code": login_code,
            }

            # payload = encode_client_request(payload)
            # encrypted_msg = self.client.encrypt_message(self.server_public_key, payload)
            # json_payload = json.dumps({"chunks": encrypted_msg})
            # self.client.socket.sendall(json_payload.encode("utf-8"))
            self.send_encrypted_message(self.client.socket, payload)

            server_response = self.get_response(self.client.socket)

            if server_response == ServerResponseCodes.LoginSuccess.value:
                server_pending_msgs_socket, address = self.client.messages_status_socket.accept()
                self.client.messages_status_socket = server_pending_msgs_socket
                recv_msgs_socket, address = self.client.recv_messages_socket.accept()
                self.client.recv_messages_socket = recv_msgs_socket
                return True, "Login successful"
            else:
                return False, "Login failed"
        return False, "Login failed"

    def send_message(self) -> tuple[bool, str]:
        phone_to_sent_msg = get_contact_number(self.client.phone_number)

        payload = {
            "my_phone": self.client.phone_number,
            "my_code": self.client.client_code,
            "send_msg_to": phone_to_sent_msg,
        }

        # payload = encode_client_request(payload)
        # encrypted_msg = self.client.encrypt_message(self.server_public_key, payload)
        # json_payload = json.dumps({"chunks": encrypted_msg})
        self.client.send_request_code(ClientRequestCodes.GetUserPublicKey)
        # self.client.socket.sendall(json_payload.encode("utf-8"))
        self.send_encrypted_message(self.client.socket, payload)

        server_response = self.get_response(self.client.socket)

        if server_response == ServerResponseCodes.UserNotFound.value:
            return False, "User not found"
        elif server_response == ServerResponseCodes.VerificationFailed.value:
            return False, "Verification failed"
        else:
            encrypted_payload = self.client.socket.recv(2048)
            user_public_key = self.client.decrypt_message(encrypted_payload)
            public_key_str = user_public_key.get("client_public_key")
            client_public_key = serialization.load_pem_public_key(public_key_str.encode("utf-8"))

            message = get_message_for_contact()
            payload = {
                "message_from": self.client.phone_number,
                "name": self.client.name,
                "message": message,
                "time": str(datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
            }

            payload = encode_client_request(payload)
            encrypted_msg_to_user = self.client.encrypt_message(client_public_key, payload)
            payload = {
                "message_from": self.client.phone_number,
                "message_to": phone_to_sent_msg,
                "message": encrypted_msg_to_user,
            }

            payload = encode_client_request(payload)
            encrypted_msg_to_server = self.client.encrypt_message(self.server_public_key, payload)
            json_payload = json.dumps({"chunks": encrypted_msg_to_server})
            self.client.send_request_code(ClientRequestCodes.SendMsgToUser)
            self.client.socket.sendall(json_payload.encode("utf-8"))
            server_response = self.get_response(self.client.socket)

            if server_response == ServerResponseCodes.SendingMessageToUser.value:
                return True, "Message sent successfully"
            elif server_response == ServerResponseCodes.UserOffline.value:
                return True, "Message sent to offline user"
            elif server_response == ServerResponseCodes.UserNotFound.value:
                return False, "User not found"
            elif server_response == ServerResponseCodes.VerificationFailed.value:
                return False, "Verification failed"
            else:
                return False, "Failed to send message"

    def receive_messages(self):
        if not self.client.message_buffer:
            print("No new messages at this time.")
            return

        get_messages_from = get_message_for_user()
        while True:
            if get_messages_from == 'q':
                return
            elif get_messages_from == 'a':
                break
            else:
                if get_messages_from not in self.client.message_buffer.keys():
                    get_messages_from = get_message_for_user(True)
                else:
                    break

        if get_messages_from == 'a':
            self.client.send_request_code(ClientRequestCodes.GetAllMessages)
            payload = {
                "phone_number": self.client.phone_number,
            }
        else:
            self.client.send_request_code(ClientRequestCodes.GetMessagesFromUser)
            payload = {
                "phone_number": self.client.phone_number,
                "messages_from": get_messages_from,
            }

        # payload = encode_client_request(payload)
        # encrypted_msg = self.client.encrypt_message(self.server_public_key, payload)
        # json_payload = json.dumps({"chunks": encrypted_msg})
        # self.client.socket.sendall(json_payload.encode("utf-8"))
        self.send_encrypted_message(self.client.socket, payload)
        self.print_color.get_next_color()
        messages = ""

        while self.client.message_buffer:
            length_prefix = self.client.recv_messages_socket.recv(4)
            message_length = struct.unpack("!I", length_prefix)[0]
            message_bytes = self.client.recv_messages_socket.recv(message_length)
            final_message_json = self.client.decrypt_message(message_bytes)
            encrypted_message_base64 = final_message_json["message"][0]
            decrypted_message = self.client.decrypt_inner_message(encrypted_message_base64)

            data = json.loads(decrypted_message)
            message_from = data["payload"]["message_from"]
            name = data["payload"]["name"]
            message = data["payload"]["message"]
            sending_time = data["payload"]["time"]

            messages += f"({sending_time}) {message} \n"

            self.client.message_buffer[message_from] = self.client.message_buffer.get(message_from, 0) - 1
            if self.client.message_buffer.get(message_from, 0) == 0:
                print(
                    self.print_color.get_current_color() + self.print_color.underline + self.print_color.bold + f"<{message_from}> {name}:",
                    self.print_color.end, end="\n")
                print(self.print_color.get_current_color() + self.print_color.italic +
                      messages)
                messages = ""
                self.client.message_buffer.pop(message_from)
                self.print_color.get_next_color()
                print(self.print_color.end, "", end="")
                if get_messages_from == message_from:
                    return

    def disconnect(self):
        self.client.send_request_code(ClientRequestCodes.DisconnectRequest)

        payload = {
            "phone_number": self.client.phone_number,
        }

        payload = encode_client_request(payload)
        encrypted_msg_to_server = self.client.encrypt_message(self.server_public_key, payload)
        json_payload = json.dumps({"chunks": encrypted_msg_to_server})
        self.client.socket.sendall(json_payload.encode("utf-8"))
        self.client.socket.close()
        self.client.recv_messages_socket.close()
        self.client.messages_status_socket.close()
        self.client.message_buffer = {}

        print("disconnected\n")

    def print_pending_messages(self):
        while True:
            try:
                server_response = self.get_response(self.client.messages_status_socket)
                print(server_response)
                if server_response == ServerResponseCodes.UpdatePendingMessages.value:
                    length_prefix = self.client.messages_status_socket.recv(4)
                    message_length = struct.unpack("!I", length_prefix)[0]

                    encrypted_payload = self.client.messages_status_socket.recv(message_length)
                    messages = self.client.decrypt_message(encrypted_payload)
                    msg_from_number = messages["new_msg_from"]
                    num_of_messages = messages["num_of_messages"]
                    self.client.message_buffer[msg_from_number] = self.client.message_buffer.get(msg_from_number,
                                                                                                 0) + num_of_messages
                    for msg_from, msg_counter in self.client.message_buffer.items():
                        print(self.print_color.end + "\t",
                              self.print_color.get_next_color() + self.print_color.underline + self.print_color.bold +
                              "you got {} messages from \"{}\"".format(msg_counter, msg_from))
                    print(self.print_color.end, "\n", print_chat_menu(), end="")

                elif server_response == ServerResponseCodes.ReadReceipt.value:
                    length_prefix = self.client.messages_status_socket.recv(4)
                    message_length = struct.unpack("!I", length_prefix)[0]

                    encrypted_payload = self.client.messages_status_socket.recv(message_length)
                    messages = self.client.decrypt_message(encrypted_payload)
                    receipt_from = messages["read_receipt_from"]
                    print(self.print_color.end + "\t",
                          self.print_color.get_next_color() + self.print_color.underline + self.print_color.bold +
                          "\"{}\" read all the messages that you send".format(receipt_from))
                    print(self.print_color.end, "\n", print_chat_menu(), end="")

            except Exception as e:
                err = e.args[0]
                if err == errno.EAGAIN or err == errno.EWOULDBLOCK or errno.ENOTSOCK:
                    time.sleep(1)
                    continue
                else:
                    print(f"[ERROR] Failed to get pending messages: {e}")

    def connect_to_server(self):
        user_choice = get_entry_choice()
        if user_choice == 'r':
            self.client = Client()
            self.client.create_client()
            status = self.register()

            if status:
                Thread(target=self.print_pending_messages, args=()).start()
            return status
        else:
            if not self.client:
                print("Failed! please try again later\n")
                return False, ""
            status, description = self.login_user()
            print(status)

            print(description)
            return status

    def get_response(self, sock):
        response_code = sock.recv(SERVER_RESPONSE_SIZE).decode()
        return decode_server_response_code(response_code)

    def send_encrypted_message(self, sock, payload):
        payload = encode_client_request(payload)
        encrypted_msg = self.client.encrypt_message(self.server_public_key, payload)
        json_payload = json.dumps({"chunks": encrypted_msg})
        sock.sendall(json_payload.encode("utf-8"))


def main(self):
    # phone = get_user_phone()
    # password = get_user_password()
    # name = input("Enter name: ")
    # client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # client_socket.connect((HOST, PORT))
    while True:
        status = self.connect_to_server()
        if status:
            break

    while True:
        action = get_user_chat_action()
        if action == 's':
            status, status_str = self.send_message()
            print(status_str)
            print(status)
        elif action == 'r':
            self.receive_messages()
        elif action == 'd':
            self.disconnect()
            main(self)
        else:
            self.client.socket.close()


if __name__ == "__main__":
    cm = ClientManager()
    main(cm)


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
