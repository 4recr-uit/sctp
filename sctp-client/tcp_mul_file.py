import socket
import time

HOST = "172.31.11.110"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

filenames = ["files/file1.bin", "files/file2.bin", "files/file3.bin", "files/file4.bin", "files/file5.bin"]
file_fd = []

time_end: list[float | None] = [ 0 for i in range(len(filenames)) ]

def recv_exact(sock, size):
    data = bytearray()

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            if not data:
                return None
            return None

        data.extend(chunk)

    return bytes(data)

try:
    for name in filenames:
        file_fd.append(open(name, "wb"))

    client.connect((HOST, 9899))

    start_time = time.perf_counter()

    while True:
        header = recv_exact(client, 5)
        if not header:
            break

        stream_id = header[0]
        length = int.from_bytes(header[1:5], "big")

        chunk = recv_exact(client, length)

        if not chunk:
            break

        file_fd[stream_id].write(chunk)
        time_end[stream_id] = time.perf_counter() - start_time

finally:
    for fd in file_fd:
        fd.close()

    client.close()

for index, filename in enumerate(filenames):
    print(f"File: {filename.split('/')[1]}, finished: {time_end[index]} s")
