from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import socket


HOST = '192.168.2.1'
PORT = 65432

with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as socketA:
    socketA.connect((HOST,PORT))
    public_key_bytes = socketA.recv(4196)
    print('public key PEM: ',public_key_bytes)
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
    print('public key: ',public_key)
    msg= input('Message to encrypt: ')
    encryptedMsg = public_key.encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    socketA.send(encryptedMsg)
