import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

HOST = "0.0.0.0"
PORT = 9899

sock.bind((HOST, PORT))
print(f"TCP server started on: {HOST}:{PORT}")
sock.listen()

try:
    while True:
        client_sock, client_address = sock.accept()
        print(f"Connected by: {client_address}")

        with open("files/file1.bin", "rb") as file:
            while chunk := file.read(65536):
                client_sock.send(chunk)

        client_sock.close()
finally:
    sock.close()
