import time


class User:
    def __init__(self, phone_number, public_key, user_socket, registration_code, password, name):
        self.phone_number = phone_number
        self.public_key = public_key
        self.user_socket = user_socket
        self.registration_code = registration_code
        self.connected = True
        self.password = password
        self.name = name
        self.last_seen = time.time()

    def get_user(self):
        return self

    def turn_off_connection(self):
        print("connected:", self.connected)
        print("user_socket:", self.user_socket)
        self.connected = False
        self.user_socket = None
