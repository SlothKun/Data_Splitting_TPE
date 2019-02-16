import socket
import rstr
import struct
import hashlib

HOST = '127.0.0.1'
PORT = 80
sock = ""


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
print(sock.getpeername())
print(type(sock))

msgrecv = b""


def send_msg(sock, msg):
    # Prefix each message with a 4-byte length (network byte order)
    sock.sendall(struct.pack('>I', hashlib.sha512(len(msg)).hexdigest()))
    sock.sendall(msg)

#def create_check_sum(file):
 #   return file

big_nonce_original = rstr.rstr('azertyuiopmlkjhgfdsqwxcvbnAZERTYUIOPMLKJHGFDSQWXCVBN0123456789', 1000000)
print(big_nonce_original)

while msgrecv != b"fin":
    sock.sendall(big_nonce_original.encode())
    msgrecv = sock.recv(16777216)
print("Closing..")
sock.close()
