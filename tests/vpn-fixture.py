import socket
import threading
import time


def tcp():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 5201))
    server.listen()
    while True:
        connection, _ = server.accept()
        with connection:
            connection.sendall(b"echo:" + connection.recv(4096))


def udp():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("0.0.0.0", 5201))
    while True:
        data, address = server.recvfrom(4096)
        server.sendto(b"echo:" + data, address)


for handler in (tcp, udp):
    threading.Thread(target=handler, daemon=True).start()
while True:
    time.sleep(60)
