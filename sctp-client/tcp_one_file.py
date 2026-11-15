import socket

HOST = "172.197.216.155"
PORT = 9899
CONNECT_TIMEOUT = 10  # seconds
RECEIVE_TIMEOUT = 10  # seconds without receiving data

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect((HOST, PORT))
    except socket.timeout:
        print(
            f"Connection timed out after {CONNECT_TIMEOUT} seconds: {HOST}:{PORT}",
            flush=True,
        )
        raise SystemExit(1) from None

    sock.settimeout(RECEIVE_TIMEOUT)

    try:
        while msg := sock.recv(65536):
            with open("/dev/null", "wb") as null_file:
                null_file.write(msg)
    except socket.timeout:
        print(
            f"Receive timed out: no data received for {RECEIVE_TIMEOUT} seconds "
            f"from {HOST}:{PORT}",
            flush=True,
        )
        raise SystemExit(1) from None
    except OSError as exc:
        print(f"Receive failed: {exc}", flush=True)
        raise SystemExit(1) from None
finally:
    sock.close()
