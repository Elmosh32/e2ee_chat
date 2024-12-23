from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import math

# Generate two pairs of keys
key1_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
key1_public = key1_private.public_key()

key2_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
key2_public = key2_private.public_key()

# Message to be signed and encrypted
message = b"Hello World!"

# Sign the message with private key1
signature = key1_private.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Combine message and signature
combined_data = message + b"||" + signature

# RSA Encryption chunk size (key size - padding overhead)
key_size = 2048 // 8
max_chunk_size = key_size - 2 * hashes.SHA256().digest_size - 2

# Split combined_data into chunks
chunks = [
    combined_data[i:i + max_chunk_size]
    for i in range(0, len(combined_data), max_chunk_size)
]

# Encrypt each chunk with public key2
encrypted_chunks = [
    key2_public.encrypt(
        chunk,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    for chunk in chunks
]

# Decrypt each chunk with private key2
decrypted_chunks = [
    key2_private.decrypt(
        encrypted_chunk,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    for encrypted_chunk in encrypted_chunks
]

# Reconstruct the original combined data
decrypted_combined_data = b"".join(decrypted_chunks)

# Separate the message from the signature
decrypted_message, decrypted_signature = decrypted_combined_data.split(b"||")

# Verify the signature using public key1
try:
    key1_public.verify(
        decrypted_signature,
        decrypted_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature is valid!")
except Exception as e:
    print("Signature verification failed:", e)

# Print the results
print("Original Message:", message.decode())
print("Decrypted Message:", decrypted_message.decode())
