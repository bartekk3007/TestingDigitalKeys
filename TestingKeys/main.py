import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import base64
from bitarray import bitarray

def encrypt_with_public_key(public_key, key):
    """Szyfrowanie klucza AES przy użyciu klucza publicznego RSA."""
    return public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def public_key_to_pem(public_k):
    pem = public_k.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')  # Konwersja do tekstu

def convert_key(base64keyEncypted, privateK):
    byteKey = base64.b64decode(base64keyEncypted)
    decryptedSessionKey = privateK.decrypt(
        byteKey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
    return decryptedSessionKey

test_key = os.urandom(32)
file_path = 'sessionKey.txt'
with open(file_path, 'rb') as file:
    read_key = file.read()
random_key = b'&\xd8nI4t6|\xea\x1f\xda\x7fF\xad\xff\xc0\xc0s\x04\xb5s\xe8\x00\x99\x03G\x89\xac\xd8\xb6\x95\xd7'

file_path = 'privateKey.txt'
with open(file_path, 'rb') as file:
    file_content = file.read()
utf_8_private_key = file_content

private_key = serialization.load_pem_private_key(
    utf_8_private_key,
    password=None,  # Jeśli klucz jest zabezpieczony hasłem, podaj je tutaj
    backend=default_backend()
)
public_key = private_key.public_key()
pem_public_key = public_key_to_pem(public_key)

EncryptedKBytes = encrypt_with_public_key(public_key, random_key)
EncryptedKString = base64.b64encode(EncryptedKBytes).decode('utf-8')

newKey = convert_key(EncryptedKString, private_key)

print(random_key)
print(newKey)