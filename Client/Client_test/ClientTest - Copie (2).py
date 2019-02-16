import socket

HOST = '127.0.0.1'
PORT = 6802

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
print(sock.getpeername())

msgrecv = b""

while msgrecv != b"fin":

    msgrecv = sock.recv(1024)
    print(msgrecv.decode())

print("Closing..")
sock.close()
