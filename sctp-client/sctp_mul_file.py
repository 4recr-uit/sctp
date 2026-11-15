import socket
import sctp
import time

from sctp_connection import connect_client

HOST = "172.31.11.110"
# Set both local IPv4 addresses to enable multihoming.
ETHERNET_IP = ""
WIFI_IP = ""

client = sctp.sctpsocket_tcp(socket.AF_INET)

BUF_SIZE = 4 * 1024 * 1024  # 4 MB

# Set buffers BEFORE bind
client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUF_SIZE)
client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUF_SIZE)

client.events.clear()
client.events.data_io = 1

# Verify it worked
print(f"SNDBUF: {client.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)} bytes")
print(f"RCVBUF: {client.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)} bytes")

filenames = ["files/file1.bin", "files/file2.bin", "files/file3.bin", "files/file4.bin", "files/file5.bin"]
file_fd = []

time_end : list[float | None] = [ None for i in range(len(filenames))]

try:
    for name in filenames:
        file_fd.append(open(name, "wb"))

    connect_client(client, HOST, ETHERNET_IP, WIFI_IP)

    time_start = time.perf_counter()

    fromaddr, flags, msg, notif = client.sctp_recv(65536)
    while msg:
        stream_id = getattr(notif, "stream")

        file_fd[stream_id].write(msg)
        time_end[stream_id] = time.perf_counter() - time_start
        fromaddr, _, msg, notif = client.sctp_recv(65536)
        
finally:
    for fd in file_fd:
        fd.close()

    client.close()

for index, filename in enumerate(filenames):
    print(f"File: {filename.split('/')[1]}, finished: {time_end[index]} s")
