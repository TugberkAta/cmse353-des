import socket
from des_algorithm import encrypt  # Assuming the DES algorithm code is saved in des_algorithm.py

KEY = "746f6d616e646a"
host = '172.20.10.4'  # Replace SERVER_IP with the actual IP address of the server
port = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen(1)

print(f"Server listening on {host}:{port}")

while True:
    client_socket, addr = server_socket.accept()
    print(f"Connection from {addr}")

    message = "This is a secret message from the server!"
    encrypted_message = encrypt(message, KEY)
    
    print(f"Original message: {message}")
    print(f"Encrypted message: {encrypted_message}")

    client_socket.send(encrypted_message.encode())
    client_socket.close()
