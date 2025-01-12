# security.py

import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from constants import RSA_CHUNK_SIZE


def encrypt_message(public_key, payload):
    chunks = [payload[i:i + RSA_CHUNK_SIZE] for i in range(0, len(payload), RSA_CHUNK_SIZE)]
    encrypted_chunks = [
        base64.b64encode(public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )).decode("utf-8") for chunk in chunks
    ]

    return encrypted_chunks


def decrypt_message(private_key, received_data):
    data_str = received_data.decode("utf-8")
    msg_json = json.loads(data_str)
    encrypted_chunks_base64 = msg_json["chunks"]
    encrypted_chunks = [base64.b64decode(chunk) for chunk in encrypted_chunks_base64]
    decrypted_chunks = [
        private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ) for chunk in encrypted_chunks
    ]
    return b"".join(decrypted_chunks).decode("utf-8").strip()


def decrypt_signed_message(private_key, public_key, received_data):
    try:
        # Decode the incoming data
        data_str = received_data.decode("utf-8")
        msg_json = json.loads(data_str)

        # Separate the "message" and "signature"
        encrypted_message = msg_json["message"]
        signature = msg_json["signature"]

        # Verify the signature
        if not verify_signature(public_key, encrypted_message, signature):
            raise ValueError("Signature verification failed!")

        # Extract the chunks from the "message"
        encrypted_message_json = json.loads(encrypted_message)
        encrypted_chunks_base64 = encrypted_message_json["chunks"]
        # Decrypt each chunk
        encrypted_chunks = [base64.b64decode(chunk) for chunk in encrypted_chunks_base64]
        decrypted_chunks = [
            private_key.decrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ) for chunk in encrypted_chunks
        ]
        return b"".join(decrypted_chunks).decode("utf-8").strip()
    except KeyError as e:
        print(f"Decryption failed due to missing field: {e}")
        raise
    except json.JSONDecodeError as e:
        print(f"Invalid JSON format in received data: {e}")
        raise
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}")
        raise


def create_signature(private_key, message):
    message_bytes = None
    if type(message) == str:
        message_bytes = message.encode("utf-8")
    elif type(message) == bytes:
        message_bytes = message

    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_key, message, signature):
    # print(
    #     f"in verify_signature:\npublic_key {public_key}\n message {message}\n signature {signature}\n\n")
    message_bytes = message.encode("utf-8")
    signature_bytes = base64.b64decode(signature)
    try:
        public_key.verify(
            signature_bytes,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
