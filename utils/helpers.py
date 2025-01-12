import re


def validate_phone_number(user_phone: str, target_phone: str) -> bool:
    if target_phone == user_phone:
        print("Invalid selection, can't send a message to yourself! Please try again.")
        return False
    if not target_phone.isdigit() or len(target_phone) != 10:
        print("Invalid phone number! Must be exactly 10 digits. Please try again.")
        return False
    return True


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


def validate_message_content(message: str) -> bool:
    if not message.strip():
        print("Message cannot be empty! Please try again.")
        return False
    return True
