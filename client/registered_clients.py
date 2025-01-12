# registered_clients.py

class RegisteredClients:
    registered_clients = {}

    def add_new_client(self, client):
        self.registered_clients[client.phone_number] = client

    def get_client_by_phone(self, client_phone):
        if client_phone in self.registered_clients.keys():
            return self.registered_clients.get(client_phone)
        return None

    def get_client(self, client_phone, password):
        client = self.get_client_by_phone(client_phone)
        if client and client.password == password:
            return client
        return None

# todo: delete account func for client
