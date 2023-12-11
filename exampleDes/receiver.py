import socket
from des_algorithm import decrypt  # Assuming the DES algorithm code is saved in des_algorithm.py

KEY = "746f6d616e646a"
host = '172.20.10.4'  # Replace SERVER_IP with the actual IP address of the server
port = 8080

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, port))

encrypted_message = client_socket.recv(1024).decode()
print(f"Received encrypted message: {encrypted_message}")

decrypted_message = decrypt(encrypted_message, KEY)
print(f"Decrypted message: {decrypted_message}")

client_socket.close()
