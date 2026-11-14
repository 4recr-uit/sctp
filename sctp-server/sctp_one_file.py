import socket
import sctp

HOST = "0.0.0.0"
PORT = 9899

server = sctp.sctpsocket_tcp(socket.AF_INET)

BUF_SIZE = 4 * 1024 * 1024  # 4 MB

server.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUF_SIZE)
server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUF_SIZE)

server.bind((HOST, PORT))
server.listen()

print(f"SCTP server listening on {HOST}:{PORT}")

try:
    while True:
        conn, addr = server.accept()
        print("Client connected:", addr)

        with open("files/file1.bin", "rb") as file:
            while chunk := file.read(65536):
                conn.sctp_send(chunk)
        
        conn.close()
finally:
    server.close()
