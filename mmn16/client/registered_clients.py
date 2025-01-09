# registered_clients.py

class RegisteredClients:
    registered_clients = {}

    def add_new_client(self, client):
        # rc = RegisteredClient(client)

        self.registered_clients[client.phone_number] = client

    def get_client_by_phone(self, client_phone):
        if client_phone in self.registered_clients.keys():
            return self.registered_clients.get(client_phone)
        return None

    # def check_if_exist(self, client_phone):
    #         return True
    #     return False

    def check_client_data(self, client_phone, password):
        if client_phone in self.registered_clients.keys():
            if self.registered_clients[client_phone].password == password:
                return True
            return False
        return False

# add delete account option for client
