import socket
import select
import struct
import pyDH
import fcntl, os
import errno
from time import sleep
import sys


HOST = '127.0.0.1'  # address of server
PORT = 80  # port to use
ClientsConnected = []  # list that'll contain connected client
ClientRead = []  # list that'll contain client who wait us to be read
fcntl.fcntl(s, fcntl.F_SETFL, os.O_NONBLOCK)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen(5)  # wait for connexion



def recv_msg(sock):
    # Read message length and unpack it into an integer
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Read the message data
    print(msglen)
    return recvall(sock, msglen)

def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        print(len(packet))
        print("------")
        if not packet:
            return None
        data += packet
    print(len(data))
    return data


while True:
    ConnexionAsk, wlist, xlist = select.select([sock], [], [], 0.05)  # keep eye on new connexion if there's

    for connexion in ConnexionAsk:  # if there's client, then accept the connexion and add him to ClientConnected
        ClientConnect, ClientInfo = sock.accept()
        ClientsConnected.append(ClientConnect)
        print(ClientInfo, " is connected")

    try:
        ClientRead, wlist, xlist  = select.select(ClientsConnected, [], [], 0.05)  # if there's a client who wait to being read, read him
    except select.error:
        pass
    else:
        for client in ClientRead:
            try:
                msg = s.recv(4096)
            except e:
                err = e.args[0]
                if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                    sleep(1)
                    print('No data available')
                    continue
                else:
                    # a "real" error occurred
                    print(e)
                    sys.exit(1)
                    recv = "b"
                    bigmessage = ""
                    while recv != "":
                        recv = ""
                        recv = client.recv(2048)

                        bigmessage += recv.decode()
                        print(recv)
                        print(len(recv))
                        print("----")
                    print(bigmessage)
                    print(len(bigmessage))
















'''

            msgrecv = client.recv(65536)

            if msgrecv == b"fin":  # if the client send "fin" close the server
                print(msgrecv.decode())
                client.send(b"fin")
                break
            else:
                print(msgrecv)
                 # print out the message and confirm the reception to the client




for client in ClientConnected:
    print("Closing " + client)
    client.close()
sock.close()
'''