from Utils.stuff import generate_password, encrypt_message, decrypt_message


SIZE_OF_CODE = 6
SIZE_OF_PASSWORD = 10

class Client:
    id : int
    code : str
    def __init__(self, id, code):
        self.id = id
        self.code = code

    def GetCode(self) -> str:
        return self.code

class Register:
    Clients : dict
    
    def __init__(self):
        self.Clients = {}

    def GenNewClient(self):
        self.Clients[generate_password(SIZE_OF_PASSWORD)] = Client(len(self.Clients), Utils.generate_password(SIZE_OF_CODE))
    
    def GetClientCode(self, password : str):
        return self.Clients[password].GetCode()
    
    def VerifyClient(self, password : str) -> bool:
        return password in self.Clients

class Message:
    id : int
    body : str
    EncryptedContent : str
    def __init__(self, content : str) -> None:
        self.EncryptedContent = content
    


class Manager:
    def MakeNewClient():
        pass
    def GetMessage():
        pass
    def SendMessage():
        pass

def SendBySecureChannel():
    pass

def GivePassword():
    # Send code for signature
    # Send password signed and wait for approvol of message
    pass

def GetPassword():
    # Listen for password and verify it the message should be signed
    pass

def HandleClient():
    # If client is new give him a password
    GivePassword()
    # If client is old ask for password
    GetPassword()
    # Give him a list of all clients it can send to also this message is signed
    print("Sending message with all clients")
    # Listen to what client he wants to talk to check signed
    # If it's first conversation give both clients there other's 
    # public key (do the diffie-hellman protocol) 
    # the public keys will be signed each with it's own code

    pass

def main():
    # Server steps for conversation

    # Listen to new clients
    print("Listening ...")
    
    # New client
    print("Opening thread that will handle new client")
    HandleClient()
    
    print(generate_password(12))
    message = "hello"
    s, i, enc = encrypt_message(message, "lol")
    print(s.hex())
    print(i.hex())
    print(enc.hex())
    dec = decrypt_message(s, i, enc, "lol")
    print(dec)

if __name__ == "__main__":
    main()