# db.py
from typing import Optional
from user import *


# Temporary storage for pending registrations
# check if user exists
# handle disonection
# update new user
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
        print("pending registrations:", self.pending_registrations)
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
        print("here phone number", phone_number)
        user = self.get_user(phone_number)
        user.turn_off_connection()


"""
def user_exists(phone_number, password=None):
    if not os.path.exists("../users.txt"):
        return False

    with open("../users.txt", "r") as file:
        for line in file:
            stored_phone, stored_password = line.strip().split(",")
            if stored_phone == phone_number:
                if password is None or stored_password == password:
                    return True
    return False


def register_user(phone_number, password, name):
    with open("../users.txt", "a") as file:
        file.write(f"{phone_number},{password},{name}\n")
    return True


def save_pending_registration(phone, password, name, verification_code):
    pending_registrations[phone] = {
        "password": password,
        "name": name,
        "verification_code": verification_code,
        "verified": False
    }


def verify_registration_code(phone, code):
    if phone not in pending_registrations:
        return False

    registration = pending_registrations[phone]
    if registration["verification_code"] == code:
        registration["verified"] = True
        return True

    return False
"""
