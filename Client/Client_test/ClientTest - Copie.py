import socket
import pyDH

HOST = '127.0.0.1'
PORT = 80

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
print(sock.getpeername())

msgrecv = b""
d1 = pyDH.DiffieHellman()
d1_pubkey = d1.gen_public_key()
d1_pubkey = str(d1_pubkey)


while msgrecv != b"fin":
    if msgrecv == b"":
        sock.send(d1_pubkey.encode())
        msgrecv = sock.recv(2048)
        print(type(msgrecv.decode()))
        d1_sharedkey = d1.gen_shared_key(int(msgrecv))
        print(d1_sharedkey)




print("Closing..")
sock.close()
