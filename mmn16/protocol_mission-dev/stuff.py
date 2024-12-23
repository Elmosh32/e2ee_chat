import hmac
import hashlib
import secrets
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import os
import socket
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes

def generate_password(length):
    """
    Generate a random password with the given length.

    :param length: Length of the password (default is 10)
    :return: A randomly generated password (str)
    """
    # Define the characters to use in the password
    characters = string.digits
    # Generate a random password using the secrets module
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

def sign_message(message, secret_key):
    """
    Sign the message with the given secret key.
    
    :param message: The message to sign (str)
    :param secret_key: The secret key to use for signing (str)
    :return: The hexadecimal signature (str)
    """
    # Create a new HMAC object using the secret key and SHA-256 hash algorithm
    signature = hmac.new(secret_key.encode(), message.encode(), hashlib.sha256)
    # Return the hexadecimal representation of the signature
    return signature.hexdigest()

def verify_signature(message, secret_key, signature):
    """
    Verify the signature of the message with the given secret key.

    :param message: The original message (str)
    :param secret_key: The secret key used for signing (str)
    :param signature: The hexadecimal signature to verify (str)
    :return: True if the signature is valid, False otherwise
    """
    # Generate a new signature using the provided message and secret key
    expected_signature = sign_message(message, secret_key)
    # Compare the provided signature with the expected signature
    return hmac.compare_digest(expected_signature, signature)



def encrypt_message(message, password):
    # Generate a random salt
    salt = os.urandom(16)
    # Derive a key from the password
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    # Generate a random IV
    iv = os.urandom(16)
    # Pad the message to make it a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    # Encrypt the message
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    # Return the salt, IV, and ciphertext
    return salt, iv, ciphertext

def decrypt_message(salt, iv, ciphertext, password):
    # Derive the key from the password
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    # Decrypt the message
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    # Unpad the message
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()


def diffie_hellman_key_exchange():
    # Generate server's private and public key
    server_private_key = ECC.generate(curve='P-256')
    server_public_key = server_private_key.public_key().export_key(format='DER')

    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))
    server_socket.listen(1)
    print('Server: Waiting for a connection...')
    
    connection, client_address = server_socket.accept()
    try:
        print('Server: Connected to', client_address)
        
        # Send server's public key to the client
        connection.sendall(server_public_key)
        
        # Receive client's public key
        client_public_key_der = connection.recv(1024)
        client_public_key = ECC.import_key(client_public_key_der)
        
        # Compute shared secret
        shared_secret = server_private_key.pointQ * client_public_key.pointQ
        shared_key = shared_secret.x.to_bytes()
        
        print('Server: Shared key established.')
        return shared_key

    finally:
        connection.close()
