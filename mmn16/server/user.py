import time


class User:
    def __init__(self, phone_number, public_key, user_socket, pending_message_socket, recv_messages_socket,
                 registration_code, password,
                 name):
        self.phone_number = phone_number
        self.public_key = public_key
        self.user_socket = user_socket
        self.messages_status_socket = pending_message_socket
        self.recv_messages_socket = recv_messages_socket
        self.registration_code = registration_code
        self.connected = True
        self.password = password
        self.name = name
        self.last_seen = time.time()
        self.messages = {}
        self.user_read_receipt = {}

    def get_user(self):
        return self

    def turn_off_connection(self):
        self.connected = False
        self.user_socket = None
        self.messages_status_socket = None
        self.recv_messages_socket = None
    # def update_pending_messages_socket(self, messages_status_socket):
    #     self.messages_status_socket = messages_status_socket
    #
    # def update_recv_messages_socket(self, recv_messages_socket):
    #     self.recv_messages_socket = recv_messages_socket
