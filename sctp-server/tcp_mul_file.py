import socket
import threading

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

HOST = "0.0.0.0"
PORT = 9899

server.bind((HOST, PORT))
server.listen()

lock = threading.Lock()
filenames = ["files/file1.bin", "files/file2.bin", "files/file3.bin", "files/file4.bin", "files/file5.bin"]

def send_file(filename, sock, stream_id):
    with open(filename, "rb") as file:
        while chunk := file.read(65535):
            with lock:
                sock.send(bytes([stream_id]) + len(chunk).to_bytes(4, "big") + chunk)

try:
    print(f"TCP server listen on: {HOST}:{PORT}")
    while True:
        conn, addr = server.accept()
        print(f"Client connected: {addr}")

        threads = []

        for index, filename in enumerate(filenames):
            thread = threading.Thread(target=send_file, args=(filename, conn, index))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        conn.close()
finally:
    server.close()
