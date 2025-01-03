def get_client_data(status: str):
    if status:
        print(status, "please try again\n")
    else:
        print("Welcome to the chat.")
    name = input("Enter name: ")
    password = input(
        "Enter password (at least 8 characters, including uppercase, lowercase, number, and special character): ")
    phone = input("Enter phone number (10 digits): ")

    print("Hello, " + name + "!")
    return phone, password, name


def how_to_connect():
    while True:
        action = input("Press 'l' to login or 'r' to register: ")
        if action == 'r':
            return 'r'
        elif action == 'l':
            return 'l'
        else:
            print("Invalid selection. Please try again.\n")


def what_to_do():
    while True:
        action = input("choose an action(s-send message, r-receive message, d-discconect from server, q-quit): ")
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
