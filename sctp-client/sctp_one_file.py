import socket
import sctp
import time

from sctp_connection import connect_client

HOST = "172.197.216.155"
# Set both local IPv4 addresses to enable multihoming.
ETHERNET_IP = ""
WIFI_IP = ""

client = sctp.sctpsocket_tcp(socket.AF_INET)

BUF_SIZE = 4 * 1024 * 1024

client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUF_SIZE)
client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUF_SIZE)

print(f"SNDBUF: {client.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)} bytes")
print(f"RCVBUF: {client.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)} bytes")

try:
    connect_client(client, HOST, ETHERNET_IP, WIFI_IP)

    while msg := client.recv(65536):
        with open("/dev/null", "wb") as file:
            file.write(msg)
finally:
    client.close()
