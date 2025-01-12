# db.py
from typing import Optional


class DB:
    pending_registrations = {}
    registered_users = {}

    def add_pending_registration(self, registration_code, user_info):
        self.pending_registrations[registration_code] = user_info

    def user_exists(self, phone_number):
        if phone_number in self.registered_users.keys():
            return True
        return False

    def user_in_pending_list(self, phone_number):
        if phone_number in self.pending_registrations:
            return True
        return False

    def add_registered_user(self, phone_number, user):
        self.registered_users[phone_number] = user
        self.pending_registrations.pop(user.registration_code)

    def get_user_info_from_pending_list(self, registration_code) -> Optional[dict]:
        if registration_code in self.pending_registrations.keys():
            return self.pending_registrations
        else:
            return None

    def get_public_key(self, user):
        if user in self.registered_users:
            return user.public_key

    def get_user_by_socket(self, socket):
        for key, user in self.registered_users.items():
            if user.user_socket == socket:
                return user

    def verify_regisered_user(self, phone_number, registration_code):
        if self.user_exists(phone_number):
            if registration_code == self.registered_users[phone_number].registration_code:
                return True
            else:
                return False
        else:
            return False

    def get_user(self, phone_number):
        if self.user_exists(phone_number):
            return self.registered_users[phone_number]
        return None

    def remove_user(self, phone_number):
        user = self.get_user(phone_number)
        user.turn_off_connection()

