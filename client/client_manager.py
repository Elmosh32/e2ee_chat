# client_manager.py

import errno
import struct
from threading import Thread

import time
from datetime import datetime as dt
from datetime import timedelta as td

from client import *
from registered_clients import *
from chat_console import *
from utils.security import *
from constants import *


class ClientManager:
    def __init__(self):
        self.server_public_key = serialization.load_pem_public_key(SERVER_PUBLIC_KEY)
        self.registered_clients = RegisteredClients()
        self.client = None
        self.print_color = Colors()
        self.banned_until = None
        self.banned = None

    def register(self):
        pending_messages_socket_new_address = self.client.messages_status_socket.getsockname()
        recv_messages_socket_new_address = self.client.recv_messages_socket.getsockname()

        payload = {
            "phone": self.client.phone_number,
            "password": self.client.password,
            "name": self.client.name,
        }

        self.client.send_request_code(ClientRequestCodes.RegisterRequest)
        payload = encode_client_request(payload)
        encrypted_msg = encrypt_message(self.server_public_key, payload)
        json_payload = json.dumps({"chunks": encrypted_msg})
        self.client.socket.sendall(json_payload.encode("utf-8"))

        response_code = self.client.socket.recv(SERVER_RESPONSE_SIZE).decode()
        server_response = decode_server_response_code(response_code)
        if server_response == ServerResponseCodes.UserAlreadyRegistered.value:
            print_result(False, "User already exist!")
            return False

        if server_response == ServerResponseCodes.SendRegistrationCode.value:
            encrypted_payload = self.client.socket.recv(2048).decode()
            payload = decode_server_response(encrypted_payload)
            self.client.client_code = payload["registration_code"]
            public_key = self.client.get_public_key()
            public_key_str = public_key.decode("utf-8")
            payload = {
                "verification_code": self.client.client_code,
                "client_public_key": public_key_str,
                "pending_message_socket": str(pending_messages_socket_new_address),
                "recv_messages_socket": str(recv_messages_socket_new_address),
            }

            self.client.send_request_code(ClientRequestCodes.VerifyCodeRequest)
            payload = encode_client_request(payload)
            encrypted_msg = encrypt_message(self.server_public_key, payload)
            json_payload = json.dumps({"chunks": encrypted_msg})
            self.client.socket.sendall(json_payload.encode("utf-8"))

            response_code = self.client.socket.recv(SERVER_RESPONSE_SIZE).decode()
            server_response = decode_server_response_code(response_code)
            if server_response == ServerResponseCodes.RegistrationSuccess.value:
                server_pending_msgs_socket, address = self.client.messages_status_socket.accept()
                self.client.messages_status_socket = server_pending_msgs_socket
                recv_msgs_socket, address = self.client.recv_messages_socket.accept()
                self.client.recv_messages_socket = recv_msgs_socket
                self.registered_clients.add_new_client(self.client)
                print_result(True, "Registered successfully")
                return True
            else:
                print_result(False, "Registration failed")
                return False
        elif server_response == ServerResponseCodes.RegistrationFailed.value:  # RegistrationFailed
            print_result(False, "Registration failed")
            return False
        else:
            print_result(False, "Unexpected server response")
            return False

    def send_message(self, phone_to_sent_msg, message):
        # Request the recipient's public key from the server
        payload = {
            "my_phone": self.client.phone_number,
            "my_code": self.client.client_code,
            "send_msg_to": phone_to_sent_msg,
        }

        self.client.send_request_code(ClientRequestCodes.GetUserPublicKey)
        self.send_encrypted_message(self.client.socket, payload)

        # Receive the recipient's public key
        response_code = self.client.socket.recv(SERVER_RESPONSE_SIZE).decode()
        server_response = decode_server_response_code(response_code)

        if server_response == ServerResponseCodes.UserNotFound.value:
            print_result(False, "User not found")
            return
        elif server_response == ServerResponseCodes.VerificationFailed.value:
            print_result(False, "Verification failed")
            return

        # Decrypt the response to get the recipient's public key
        encrypted_message = self.client.socket.recv(2048)
        decrypted_message = decrypt_signed_message(
            private_key=self.client.private_key,
            public_key=self.server_public_key,
            received_data=encrypted_message,
        )
        decrypted_message = decode_server_response(decrypted_message)
        recipient_public_key_str = decrypted_message.get("client_public_key")
        recipient_public_key = serialization.load_pem_public_key(recipient_public_key_str.encode("utf-8"))

        # Prepare the message payload for the recipient
        payload = {
            "message_from": self.client.phone_number,
            "name": self.client.name,
            "message": message,
            "time": str(dt.now().strftime("%d/%m/%Y %H:%M:%S")),
        }
        serialized_payload = encode_client_request(payload)

        # Encrypt the payload with the recipient's public key
        encrypted_msg_to_user = encrypt_message(recipient_public_key, serialized_payload)
        message_payload = json.dumps({"chunks": encrypted_msg_to_user})
        signature = create_signature(self.client.private_key, message_payload)

        final_payload = {
            "message_to": phone_to_sent_msg,
            "message_from": self.client.phone_number,
            "message": encrypted_msg_to_user,
            "signature": signature,
        }

        self.client.send_request_code(ClientRequestCodes.SendMsgToUser)
        self.send_encrypted_message(self.client.socket, final_payload)
        response_code = self.client.socket.recv(SERVER_RESPONSE_SIZE).decode()
        server_response = decode_server_response_code(response_code)

        if server_response == ServerResponseCodes.SendingMessageToUser.value:
            print_result(True, "Message sent successfully")
        elif server_response == ServerResponseCodes.UserOffline.value:
            print_result(True, f"User is offline. Message saved for later delivery.")
        elif server_response == ServerResponseCodes.UserNotFound.value:
            print_result(False, "User not found")
        elif server_response == ServerResponseCodes.VerificationFailed.value:
            print_result(False, "Verification failed")
        else:
            print_result(False, "Failed to send message")

    def login_user(self):
        if self.banned:
            if self.banned_until - dt.now() <= td(days=0):
                self.banned = None
                self.banned_until = None
            else:
                minutes = (self.banned_until - dt.now()).seconds // 60
                seconds = (self.banned_until - dt.now()).seconds % 60
                print_result(False,
                             f"you are banned from the server! try again in {minutes:02d}:{seconds:02d}")
                return False

        attempt = 0
        registered_client = None
        phone_number = None
        password = None
        while attempt < 3:
            phone_number, password = get_login_data(attempt)
            registered_client = self.registered_clients.get_client(phone_number, password)
            if registered_client:
                self.client = registered_client
                break
            attempt = attempt + 1

        if attempt == 3:
            self.banned = True
            self.banned_until = dt.now() + td(minutes=5)
            print_result(False, "Login failed: permission denied - try again in 5 minutes")
            return False

        # self.client.init_main_socket()
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

        self.client.send_request_code(ClientRequestCodes.LoginRequest)
        self.send_encrypted_message(self.client.socket, payload)
        response_code = self.client.socket.recv(SERVER_RESPONSE_SIZE).decode()
        server_response = decode_server_response_code(response_code)

        if server_response == ServerResponseCodes.WrongUserData.value:
            print_result(False, "User name or/and password are incorrect")
            return False
        elif server_response == ServerResponseCodes.SendLoginCode.value:
            encrypted_message = self.client.socket.recv(2048)
            decrypted_message = decrypt_signed_message(
                private_key=self.client.private_key,
                public_key=self.server_public_key,
                received_data=encrypted_message
            )
            decrypted_message = decode_server_response(decrypted_message)

            # encrypted_payload = decode_server_response(decrypt_message(self.client.private_key, encrypted_message))
            login_code = decrypted_message.get("login_code")
            payload = {
                "code": login_code,
            }

            self.send_encrypted_message(self.client.socket, payload)
            response_code = self.client.socket.recv(SERVER_RESPONSE_SIZE).decode()
            server_response = decode_server_response_code(response_code)
            if server_response == ServerResponseCodes.LoginSuccess.value:
                server_pending_msgs_socket, address = self.client.messages_status_socket.accept()
                self.client.messages_status_socket = server_pending_msgs_socket
                recv_msgs_socket, address = self.client.recv_messages_socket.accept()
                self.client.recv_messages_socket = recv_msgs_socket
                print_result(True, "Login successful")
                return True
            else:
                print_result(False, "Login failed")
                return False
        print_result(False, "Login failed")
        return False

    def receive_messages(self, get_messages_from):
        if not self.client.message_buffer:
            print_unread_messages_status(self.client.message_buffer)
            return

        if get_messages_from != 'a':
            if get_messages_from not in self.client.message_buffer.keys():
                print_message_not_found(get_messages_from)

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

        self.send_encrypted_message(self.client.socket, payload)
        self.print_color.get_next_color()
        messages = ""

        while self.client.message_buffer:
            decrypted_message = self.decrypt_packed_message(self.client.recv_messages_socket)

            message_from = decrypted_message["message_from"]
            name = decrypted_message["name"]
            message = decrypted_message["message"]
            sending_time = decrypted_message["time"]
            messages += f"({sending_time}) {message} \n"
            self.client.message_buffer[message_from] = self.client.message_buffer.get(message_from, 0) - 1

            if self.client.message_buffer.get(message_from, 0) == 0:
                print_incoming_message(message_from, name, messages, self.print_color.get_current_color())
                messages = ""
                self.client.message_buffer.pop(message_from)
                print(self.print_color.get_next_color(), end="")

                if get_messages_from == message_from:
                    # if user want to get all the messages from specific user after
                    # he will get all the messages from this user we will return to main fumc
                    return

    def disconnect(self):
        self.client.send_request_code(ClientRequestCodes.DisconnectRequest)
        payload = {
            "phone_number": self.client.phone_number,
        }
        self.send_encrypted_message(self.client.socket, payload)
        self.client.recv_messages_socket.close()
        self.client.messages_status_socket.close()
        self.client.message_buffer = {}
        print_result(True, "Disconnected successfully")

    def print_pending_messages(self):
        while True:
            try:
                response_code = self.client.messages_status_socket.recv(SERVER_RESPONSE_SIZE).decode()
                server_response = decode_server_response_code(response_code)
                if server_response == ServerResponseCodes.UpdatePendingMessages.value:
                    messages = self.decrypt_packed_message(self.client.messages_status_socket)
                    msg_from_number = messages["new_msg_from"]
                    num_of_messages = messages["num_of_messages"]
                    self.client.message_buffer[msg_from_number] = self.client.message_buffer.get(msg_from_number,
                                                                                                 0) + num_of_messages
                    print_unread_messages_status(self.client.message_buffer, False)
                    print_user_name_and_number(self.client.phone_number, self.client.name, INPUT_COLOR)
                elif server_response == ServerResponseCodes.ReadReceipt.value:
                    decrypted_message = self.decrypt_packed_message(self.client.messages_status_socket)
                    receipt_from = decrypted_message["read_receipt_from"]
                    print_contact_read_message(self.client.phone_number, self.client.name, receipt_from,
                                               self.print_color.get_next_color())
            except Exception as e:
                err = e.args[0]
                if err == errno.EAGAIN or err == errno.EWOULDBLOCK or errno.ENOTSOCK:
                    time.sleep(1)
                    continue
                else:
                    print_result(False, f"Failed to get pending messages: {e}")

    def send_encrypted_message(self, sock, payload):
        payload = encode_client_request(payload)
        encrypted_msg = encrypt_message(self.server_public_key, payload)
        json_payload = json.dumps({"chunks": encrypted_msg})
        signature = create_signature(self.client.private_key, json_payload)
        final_payload = json.dumps({
            "message": json_payload,
            "signature": signature
        }).encode("utf-8")
        sock.sendall(final_payload)

    def decrypt_packed_message(self, sock):
        length_prefix = sock.recv(4)
        message_length = struct.unpack("!I", length_prefix)[0]
        encrypted_message = sock.recv(message_length)
        decrypted_message = decrypt_signed_message(
            private_key=self.client.private_key,
            public_key=self.server_public_key,
            received_data=encrypted_message
        )
        return decode_server_response(decrypted_message)

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
                print_result(False, "Failed! please try again later")
                return False
            status = self.login_user()
            return status


def main(self):
    while True:
        status = self.connect_to_server()
        if status:
            break

    print(chat_menu())
    while True:
        action, phone_number, message = get_user_chat_action(self.client.phone_number, self.client.name)
        if action == 's':
            self.send_message(phone_number, message)
        elif action == 'r':
            self.receive_messages(phone_number)
        elif action == 'l':
            print_unread_messages_status(self.client.message_buffer)
        elif action == 'd':
            self.disconnect()
            main(self)
        elif action == 'e':
            self.disconnect()
            print("Goodbye!")
            exit(1)


if __name__ == "__main__":
    cm = ClientManager()
    main(cm)
