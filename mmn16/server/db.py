# db.py
import os
import time
from typing import Optional

pending_registrations = {}  # Temporary storage for pending registrations

class User:
    phone_number: str
    password: str
    name: str
    public_key: Optional[bytes] = None
    last_seen: float = time.time()
    aes_key: Optional[bytes] = None

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
    """
    Saves a pending registration request.
    """
    pending_registrations[phone] = {
        "password": password,
        "name": name,
        "verification_code": verification_code,
        "verified": False
    }


def verify_registration_code(phone, code):
    """
    Verifies the registration code and marks the registration as completed.
    """
    if phone not in pending_registrations:
        return False

    registration = pending_registrations[phone]
    if registration["verification_code"] == code:
        registration["verified"] = True
        return True

    return False
