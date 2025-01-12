# chat_console.py

from utils.helpers import *
from constants import *


class Colors:
    def __init__(self):
        self.colors = [
            '\033[32m',  # green
            '\033[34m',  # blue
            '\033[35m',  # purple
            '\033[36m',  # cyan
            '\033[90m',  # darkgrey
            '\033[93m',  # yellow
            '\033[92m',  # lightgreen
            '\033[33m',  # orange
            '\033[94m',  # lightblue
            '\033[95m',  # pink
        ]
        self.current_index = 0

    def get_next_color(self):
        color = self.colors[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.colors)
        return color

    def get_current_color(self):
        return self.colors[self.current_index]


def get_client_data(status=None):
    if status:
        print(status, "please try again\n")
    else:
        print("Welcome to the chat.")
    phone = get_user_phone()
    password = get_user_password()
    name = input("Enter youe name: ")

    return phone, password, name


def get_login_data(attempt):
    if attempt > 0:
        print("Wrong phone number or password. {} attempts left.".format(3 - attempt))
        print("Please check your phone number and password and try again.")

    phone = input("Enter phone number (10 digits): ")
    password = input(
        "Enter password (at least 8 characters, including uppercase, lowercase, number, and special character): ")
    return phone, password


def get_entry_choice():
    while True:
        action = input("Press 'l' to login or 'r' to register: ")
        if action == 'r':
            return 'r'
        elif action == 'l':
            return 'l'
        else:
            print("Invalid selection. Please try again.\n")


def chat_menu() -> str:
    return """To send a message, type: "s - phone number - message" (e.g., s - 0542314568 - Hello)
To read messages, type: "r - phone number" or "r - a" (for all messages)
To see the list of unread messages, type: "l"
For help menu, type: h
To disconnect from the current user, type: "d"
To exit the chat, type: "e"
"""


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


def print_user_name_and_number(phone_number, name, print_color, of_other_user=False):
    if of_other_user:
        closing_char = "\n"
    else:
        closing_char = " "
    print(print_color + UNDERLINE + BOLD + f"<{phone_number}> {name}:" + RESET_STYLE, end=closing_char)
    print(ITALIC, end="")


def print_incoming_message(phone_number, name, messages, print_color):
    print_user_name_and_number(phone_number, name, print_color, True)
    print(print_color + ITALIC + messages + RESET_STYLE)


def get_user_chat_action(phone_number, name):
    while True:
        print_user_name_and_number(phone_number, name, INPUT_COLOR)
        action = input().strip().lower()
        print(RESET_STYLE, end="")

        if action.startswith("s -"):
            try:
                _, target_phone, message = map(str.strip, action.split("-", 2))
                if validate_phone_number(phone_number, target_phone) and validate_message_content(message):
                    return 's', target_phone, message
            except ValueError:
                print("Invalid format! Use: s - phone number - message")
        elif action.startswith("r -"):
            target = action.split("-")[1].strip()
            if (target.isdigit() and len(target) == 10 and target != phone_number) or (target == "a"):
                return 'r', target, None
            else:
                print("Invalid selection for reading messages! Provide a valid phone number or 'a'. Please try again.")
        elif action == 'l':
            return 'l', None, None
        elif action == 'h':
            print(chat_menu())
        elif action == 'd':
            return 'd', None, None
        elif action == 'e':
            return 'e', None, None
        else:
            print("Invalid selection. Please try again.\n")


def print_message_not_found(phone_number):
    print(RESET_STYLE + INBOX_EMPTY_COLOR + f"Cant find any message from \"{phone_number}\"")


def print_result(success, description):
    if success:
        print(SUCCESS_PRINT + f"[SUCCESS] {description}\n" + DEFAULT_PRINT)
    else:
        print(FAILURE_PRINT + f"[FAILURE] {description}\n" + DEFAULT_PRINT)


def print_unread_messages_status(message_buffer, from_main_thread=True):
    if from_main_thread:
        open_chars = "\t"
    else:
        open_chars = "\n\t"
    if message_buffer:
        for messages_from, num_of_unread_messages in message_buffer.items():
            print(RESET_STYLE + open_chars,
                  INBOX_NOT_EMPTY_COLOR + UNDERLINE + BOLD + f"you got {num_of_unread_messages} messages from \"{messages_from}\"")
    else:
        print(RESET_STYLE + open_chars,
              INBOX_EMPTY_COLOR + UNDERLINE + BOLD + "Your inbox is empty!")


def print_contact_read_message(your_phone_number, your_name, contact_phone_number, print_color):
    print(RESET_STYLE + "\n\t", print_color + UNDERLINE + BOLD + "\"{}\" read all the messages that you send".format(
        contact_phone_number) + RESET_STYLE)
    print_user_name_and_number(your_phone_number, your_name, INPUT_COLOR)
