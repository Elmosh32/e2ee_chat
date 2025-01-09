DEFAULT_PRINT = '\033[0m'
FAILURE_PRINT = '\033[31m'
SUCCESS_PRINT = '\033[32m'


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

        self.italic = '\033[3m'
        self.bold = '\033[1m'
        self.underline = '\033[4m'
        self.end = '\033[0m'

    def get_next_color(self):
        color = self.colors[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.colors)
        return color

    def get_current_color(self):
        return self.colors[self.current_index]

    # def set_to_default_color(self):
    #     return self.END


def get_client_data(status=None):
    if status:
        print(status, "please try again\n")
    else:
        print("Welcome to the chat.")
    phone = input("Enter phone number (10 digits): ")
    password = input(
        "Enter password (at least 8 characters, including uppercase, lowercase, number, and special character): ")
    name = input("Enter name: ")

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


def print_chat_menu() -> str:
    return "choose an action(s-send message, r-receive message, d-discconect from server, q-quit): "


def get_user_chat_action():
    while True:
        action = input(print_chat_menu())
        if action == 's':
            return 's'
        elif action == 'r':
            return 'r'
        elif action == 'd':
            return 'd'
        elif action == 'q':
            print("Goodbye!")
            return 'q'
        else:
            print("Invalid selection. Please try again.\n")


def get_contact_number(your_phone_number):
    while True:
        contact_phone_number = input("Enter your contact phone number: ")
        if contact_phone_number == your_phone_number:
            print("Invalid selection, cant send message to yourself! Please try again.\n")
        else:
            return contact_phone_number


def get_message_for_contact():
    msg = input("Please enter the message you want to send: ")
    return msg


def get_message_for_user(not_found=False):
    if not_found:
        read_messages_from = input(
            "No messages were found for the selected number. Please try a different number or press 'q' to quit")
    else:
        read_messages_from = input(
            "To view messages, please enter the specific phone number or type 'a' to see all your incoming messages.")
    return read_messages_from


def print_result(success, description):
    if success:
        print(SUCCESS_PRINT + f"[SUCCESS] {description}\n" + DEFAULT_PRINT)
    else:
        print(FAILURE_PRINT + f"[FAILURE] {description}\n" + DEFAULT_PRINT)
