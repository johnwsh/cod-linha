import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



def encryptMessage(message: bytes, password: bytes): 
    salt = b'\x87z\xe4\xa93{\t\x8f#xF,yy\xc2\x05'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))

    f = Fernet(key)

    token = f.encrypt(message)
    return token

def decryptMessage(token: bytes, password: bytes):
    salt = b'\x87z\xe4\xa93{\t\x8f#xF,yy\xc2\x05'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))

    f = Fernet(key)

    message = f.decrypt(token)
    return message

def binarize(data: bytes):
    return ''.join(format(byte, '08b') for byte in data)

def debinarize(data: str):
    bytes_list = [data[i:i + 8] for i in range(0, len(data), 8)]
    return bytes(int(byte, 2) for byte in bytes_list)

def encryptMessageFromStr(message: str, password: str):
    return encryptMessage(message.encode('utf-8'), password.encode('utf-8'))

def decryptMessageToStr(token: bytes, password: str):
    decrypted = decryptMessage(token, password.encode('utf-8'))
    return decrypted.decode('utf-8')

