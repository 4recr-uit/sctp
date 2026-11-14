import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    sock.connect(("172.197.216.155", 9899))

    while msg := sock.recv(65536):
        with open("/dev/null", "wb") as null_file:
            null_file.write(msg)
finally:
    sock.close()
