import socket
import sctp
import threading
import time

HOST = "0.0.0.0"
PORT = 9899

server = sctp.sctpsocket_tcp(socket.AF_INET)

BUF_SIZE = 4 * 1024 * 1024  # 4 MB

server.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUF_SIZE)
server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUF_SIZE)

server.bind((HOST, PORT))
server.listen()

print(f"SCTP server listening on {HOST}:{PORT}")

lock = threading.Lock()
def send_file(name, sctp_socket, stream_id):
    with open(name, "rb") as file:
        while chunk := file.read(65536):
            with lock:
                sctp_socket.sctp_send(chunk, stream=stream_id)

filenames = ["files/file1.bin", "files/file2.bin", "files/file3.bin", "files/file4.bin", "files/file5.bin"]

try:
    while True:
        conn, addr = server.accept()
        print("Client connected:", addr)

        threads = []

        for index, name in enumerate(filenames):
            thread = threading.Thread(target=send_file, args=(name, conn, index))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        conn.close()
finally:
    server.close()
