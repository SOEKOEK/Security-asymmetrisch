from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import socket

HOST = '192.168.2.1'
PORT = 65432

print('Server Started, awaiting connection')

while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socketA:
        socketA.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        socketA.bind((HOST,PORT))
        socketA.listen()
        conn,addr = socketA.accept()
        with conn:
            print('Connected with: ',addr)

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            print(public_key)

            pem=public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=(serialization.PublicFormat.SubjectPublicKeyInfo)
            )
            conn.send(pem)
            encryptedMsg = conn.recv(4096)